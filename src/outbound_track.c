/*    Copyright (C) 2022  Robert Caamano   */
 /*
  *   This program splices tcp and udp flows via ebpf tc that match openzit service destination prefixes & dst ports
  *   to either openziti edge-router tproxy port or to a locally hosted openziti service socket
  *   completely replacing iptables rules.  It works with a modified openziti edge module that calls the binaries
  *   in this repo.   
  *
  *   This program is free software: you can redistribute it and/or modify
  *   it under the terms of the GNU General Public License as published by
  *   the Free Software Foundation, either version 3 of the License, or
  *   (at your option) any later version.

  *   This program is distributed in the hope that it will be useful,
  *   but WITHOUT ANY WARRANTY; without even the implied warranty of
  *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  *   GNU General Public License for more details.
  *   see <https://www.gnu.org/licenses/>.
*/

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bcc/bcc_common.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <iproute2/bpf_elf.h>
#include <stdbool.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if.h>
#include <stdio.h>

#define BPF_MAP_ID_DIAG_MAP 5
#define BPF_MAP_ID_TCP_MAP 7
#define BPF_MAP_ID_UDP_MAP 8
#define MAX_INDEX_ENTRIES  100 //MAX port ranges per prefix need to match in user space apps 

/*Key to tcp_map and udp_map*/
struct tuple_key {
    __u32 daddr;
    __u32 saddr;
    __u16 sport;
    __u16 dport;
};

/*Value to tcp_map*/
struct tcp_state {
    unsigned long long tstamp;
    int syn;
    int fin;
    int ack;
    int rst;
    int est;
    int pad;
};

/*Value to udp_map*/
struct udp_state {
    unsigned long long tstamp;
};

/*value to diag_map*/
struct diag_ip4 {
    bool echo;
    bool verbose;
    bool per_interface;
    bool ssh_disable;
    bool tc_ingress;
    bool tc_egress;
};

//map to keep status of diagnostic rules
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(id, BPF_MAP_ID_DIAG_MAP);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct diag_ip4));
    __uint(max_entries, 28);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} diag_map SEC(".maps");

/*Hashmap to track outbound passthrough TCP connections*/
struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(id, BPF_MAP_ID_TCP_MAP);
     __uint(key_size, sizeof(struct tuple_key));
     __uint(value_size,sizeof(struct tcp_state));
     __uint(max_entries, 200);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_map SEC(".maps");

/*Hashmap to track outbound passthrough UDP connections*/
struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(id, BPF_MAP_ID_UDP_MAP);
     __uint(key_size, sizeof(struct tuple_key));
     __uint(value_size,sizeof(struct udp_state));
     __uint(max_entries, 200);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_map SEC(".maps");

/*Insert entry into tcp state table*/
static inline void insert_tcp(struct tcp_state tstate, struct tuple_key key){
     bpf_map_update_elem(&tcp_map, &key, &tstate,0);
}

/*Remove entry into tcp state table*/
static inline void del_tcp(struct tuple_key key){
     bpf_map_delete_elem(&tcp_map, &key);
}

/*get entry from tcp state table*/
static inline struct tcp_state *get_tcp(struct tuple_key key){
    struct tcp_state *ts;
    ts = bpf_map_lookup_elem(&tcp_map, &key);
	return ts;
}

/*Insert entry into udp state table*/
static inline void insert_udp(struct udp_state ustate, struct tuple_key key){
     bpf_map_update_elem(&udp_map, &key, &ustate,0);
}

/*get entry from udp state table*/
static inline struct udp_state *get_udp(struct tuple_key key){
    struct udp_state *us;
    us = bpf_map_lookup_elem(&udp_map, &key);
	return us;
}

static inline struct diag_ip4 *get_diag_ip4(__u32 key){
    struct diag_ip4 *if_diag;
    if_diag = bpf_map_lookup_elem(&diag_map, &key);

	return if_diag;
}


/* function to determine if an incomming packet is a udp/tcp IP tuple
* or not.  If not returns NULL.  If true returns a struct bpf_sock_tuple
* from the combined IP SA|DA and the TCP/UDP SP|DP. 
*/
static struct bpf_sock_tuple *get_tuple(struct __sk_buff *skb, __u64 nh_off,
    __u16 eth_proto, bool *ipv4, bool *ipv6, bool *udp, bool *tcp, bool *arp, bool *icmp, struct diag_ip4 *local_diag){
    struct bpf_sock_tuple *result;
    __u8 proto = 0;
    
    /* check if ARP */
    if (eth_proto == bpf_htons(ETH_P_ARP)) {
        *arp = true;
        return NULL;
    }
    
    /* check if IPv6 */
    if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        *ipv6 = true;
        return NULL;
    }
    
    /* check IPv4 */
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        *ipv4 = true;

        /* find ip hdr */
        struct iphdr *iph = (struct iphdr *)(skb->data + nh_off);
        
        /* ensure ip header is in packet bounds */
        if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
            if(local_diag->verbose){
                bpf_printk("header too big");
            }
            return NULL;
		}
        /* ip options not allowed */
        if (iph->ihl != 5){
		    //bpf_printk("no options allowed");
            return NULL;
        }
        /* get ip protocol type */
        proto = iph->protocol;
        /* check if ip protocol is UDP */
        if (proto == IPPROTO_UDP) {
            *udp = true;
        }
        /* check if ip protocol is TCP */
        if (proto == IPPROTO_TCP) {
            *tcp = true;
        }
        if(proto == IPPROTO_ICMP){
            *icmp = true;
            return NULL;
        }
        /* check if ip protocol is not UDP or TCP. Return NULL if true */
        if ((proto != IPPROTO_UDP) && (proto != IPPROTO_TCP)) {
            return NULL;
        }
        /*return bpf_sock_tuple*/
        result = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    } else {
        return NULL;
    }
    return result;
}

//ebpf tc code entry program
SEC("action")
int bpf_sk_splice(struct __sk_buff *skb){
    struct bpf_sock *sk;
    struct bpf_sock_tuple *tuple, reverse_tuple = {0};
    int tuple_len;
    bool ipv4 = false;
    bool ipv6 = false;
    bool udp=false;
    bool tcp=false;
    bool arp=false;
    bool icmp=false;
    struct tuple_key tcp_state_key;
    struct tuple_key udp_state_key;

    /*look up attached interface inbound diag status*/
    struct diag_ip4 *local_diag = get_diag_ip4(skb->ifindex);
    if(!local_diag){
        if(skb->ingress_ifindex == 1){
            return TC_ACT_OK;
        }else{
            return TC_ACT_SHOT;
        }
    }

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    /* verify its a valid eth header within the packet bounds */
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
	}

    /* check if incomming packet is a UDP or TCP tuple */
    tuple = get_tuple(skb, sizeof(*eth), eth->h_proto, &ipv4,&ipv6, &udp, &tcp, &arp, &icmp, local_diag);

    /* if not tuple forward */
    if (!tuple){
        return TC_ACT_OK;
    }

    /* determine length of tupple */
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       return TC_ACT_SHOT;
    }

    /* if tcp based tuple implement statefull inspection to see if they were
     * initiated by the local OS if not then its passthrough traffic and so wee need to
     * setup our own state to track the outbound pass through connections in via shared hashmap
    * with with ingress tc program*/
    if(tcp){
        struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
        if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        struct tcphdr *tcph = (struct tcphdr *)((unsigned long)iph + sizeof(*iph));
        if ((unsigned long)(tcph + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        reverse_tuple.ipv4.daddr = tuple->ipv4.saddr;
        reverse_tuple.ipv4.dport = tuple->ipv4.sport;
        reverse_tuple.ipv4.saddr = tuple->ipv4.daddr;
        reverse_tuple.ipv4.sport = tuple->ipv4.dport;
        sk = bpf_skc_lookup_tcp(skb, &reverse_tuple, sizeof(reverse_tuple.ipv4),BPF_F_CURRENT_NETNS, 0);
        if(sk){
            if (sk->state != BPF_TCP_LISTEN){
                bpf_sk_release(sk);
                return TC_ACT_OK;
            }
            bpf_sk_release(sk);
            return TC_ACT_OK;
        }
        tcp_state_key.daddr = tuple->ipv4.daddr;
        tcp_state_key.saddr = tuple->ipv4.saddr;
        tcp_state_key.sport = tuple->ipv4.sport;
        tcp_state_key.dport = tuple->ipv4.dport;
        unsigned long long tstamp = bpf_ktime_get_ns();
        struct tcp_state *tstate;
        if(tcph->syn && !tcph->ack){
            struct tcp_state ts = {
            tstamp,
            1,
            0,
            0,
            0,
            0,
            0
        };
            insert_tcp(ts, tcp_state_key);
            if(local_diag->verbose){
                bpf_printk("sent syn to 0x%X : %d\n" ,bpf_ntohl(tuple->ipv4.daddr), bpf_ntohs  (tuple->ipv4.dport));
            }
        }
        else if(tcph->fin){
            tstate = get_tcp(tcp_state_key);
            if(tstate){
                tstate->tstamp = tstamp;
                tstate->fin = 1;
                if(local_diag->verbose){
                    bpf_printk("sent fin to 0x%X : %d\n" ,bpf_ntohl(tuple->ipv4.daddr), bpf_ntohs(tuple->ipv4.dport));
                }
            }
        }
        else if(tcph->rst){
            tstate = get_tcp(tcp_state_key);
            if(tstate){
                del_tcp(tcp_state_key);
                if(local_diag->verbose){
                    bpf_printk("Received rst from client 0x%X:%d\n", bpf_ntohl(tuple->ipv4.daddr), bpf_ntohs(tuple->ipv4.dport));
                }
                tstate = get_tcp(tcp_state_key);
                if(!tstate){
                    if(local_diag->verbose){
                        bpf_printk("removed tcp state %X:%d\n", bpf_ntohl(tuple->ipv4.daddr), bpf_ntohs(tuple->ipv4.dport));
                    }
                }
            }
        }
        else if(tcph->ack){
            tstate = get_tcp(tcp_state_key);
            if(tstate){
                if(tstate->ack && tstate->syn){
                    if(local_diag->verbose){
                        bpf_printk("Established tcp connection to : 0x%X:%d\n", bpf_ntohl(tuple->ipv4.daddr), bpf_ntohs(tuple->ipv4.dport));
                    }
                    tstate->tstamp = tstamp;
                    tstate->syn = 0;
                    tstate->est = 1;
                }
                if(tstate->fin == 1){
                    del_tcp(tcp_state_key);
                    if(local_diag->verbose){
                        bpf_printk("sent final ack to 0x%X : %d\n" ,bpf_ntohl(tuple->ipv4.daddr), bpf_ntohs(tuple->ipv4.dport));
                    }
                    tstate = get_tcp(tcp_state_key);
                    if(!tstate){
                        if(local_diag->verbose){
                            bpf_printk("removed tcp state: 0x%X:%d\n", bpf_ntohl(tuple->ipv4.daddr), bpf_ntohs(tuple->ipv4.dport ));
                        }
                    }
                }
                else{
                    tstate->tstamp = tstamp;
                    //bpf_printk("sent ack to 0x%X : %lld\n" ,bpf_ntohl(tuple->ipv4.daddr), tstamp);
                }
            }
        }
    }else{
    /* if udp based tuple implement statefull inspection to see if they were
     * initiated by the local OS if not then its passthrough traffic and so wee need to
     * setup our own state to track the outbound pass through connections in via shared hashmap
    * with with ingress tc program */
        struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
        if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        struct udphdr *udph = (struct udphdr *)((unsigned long)iph + sizeof(*iph));
        if ((unsigned long)(udph + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
           return TC_ACT_SHOT;
        }
        reverse_tuple.ipv4.daddr = tuple->ipv4.saddr;
        reverse_tuple.ipv4.dport = tuple->ipv4.sport;
        reverse_tuple.ipv4.saddr = tuple->ipv4.daddr;
        reverse_tuple.ipv4.sport = tuple->ipv4.dport;
	    unsigned long long tstamp = bpf_ktime_get_ns();
        sk = bpf_sk_lookup_udp(skb, &reverse_tuple, sizeof(reverse_tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
        if(sk){
           bpf_sk_release(sk);
        }else{
            udp_state_key.daddr = tuple->ipv4.daddr;
            udp_state_key.saddr = tuple->ipv4.saddr;
            udp_state_key.sport = tuple->ipv4.sport;
            udp_state_key.dport = tuple->ipv4.dport;
            struct udp_state *ustate = get_udp(udp_state_key);
            if((!ustate) || (ustate->tstamp > (tstamp + 30000000000))){
                struct udp_state us = {
                    tstamp
                };
                insert_udp(us, udp_state_key);
                if(local_diag->verbose){
                    bpf_printk("udp conv initiated to 0x%X: %d\n" ,bpf_ntohl(tuple->ipv4.daddr), bpf_ntohs(tuple->ipv4.dport));
                }
            }
            else if(ustate){
                ustate->tstamp = tstamp;
            }
        }
    }
    return TC_ACT_OK;
}
SEC("license") const char __license[] = "Dual BSD/GPL";
