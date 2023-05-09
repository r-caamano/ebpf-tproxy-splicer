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
#include <linux/icmp.h>
#include <linux/if.h>
#include <stdio.h>

#define BPF_MAP_ID_TPROXY           1
#define BPF_MAP_ID_IFINDEX_IP       2
#define BPF_MAP_ID_PROG_MAP         3
#define BPF_MAP_ID_MATCHED_KEY      4
#define BPF_MAP_ID_DIAG_MAP         5

#define BPF_MAP_ID_TUPLE_COUNT_MAP  6
#define BPF_MAP_ID_TCP_MAP          7
#define BPF_MAP_ID_UDP_MAP          8
#ifndef BPF_MAX_ENTRIES
#define BPF_MAX_ENTRIES   100 //MAX # PREFIXES
#endif
#define MAX_INDEX_ENTRIES           100 //MAX port ranges per prefix need to match in user space apps 
#define MAX_TABLE_SIZE              65536 //needs to match in userspace
#define GENEVE_UDP_PORT             6081
#define GENEVE_VER                  0
#define AWS_GNV_HDR_OPT_LEN         32 // Bytes
#define AWS_GNV_HDR_LEN             40 // Bytes
#define MATCHED_KEY_DEPTH           3
#define MATCHED_INT_DEPTH           50
#define MAX_IF_LIST_ENTRIES         3


struct tproxy_port_mapping {
    __u16 low_port;
    __u16 high_port;
    __u16 tproxy_port;
    __u8 if_list[MAX_IF_LIST_ENTRIES];
};

struct tproxy_tuple {
    __u16 index_len; /*tracks the number of entries in the index_table*/
    __u16 index_table[MAX_INDEX_ENTRIES];/*Array used as index table which point to struct 
                                             *tproxy_port_mapping in the port_maping array
                                             * with each poulated index represening a udp or tcp tproxy 
                                             * mapping in the port_mapping array
                                             */
    struct tproxy_port_mapping port_mapping[MAX_TABLE_SIZE];/*Array to store unique tproxy mappings
                                                               *  with each index matches the low_port of
                                                               * struct tproxy_port_mapping {
                                                               *  __u16 low_port;
                                                               *  __u16 high_port;
                                                               * __u16 tproxy_port;
                                                               * __u32 tproxy_ip;
                                                               * }
                                                               */
};

/*key to zt_tproxy_map*/
struct tproxy_key {
    __u32 dst_ip;
    __u32 src_ip;
    __u16 dprefix_len;
    __u16 sprefix_len;
    __u16 protocol;
    __u16 pad;
};
/*Key to tcp_map*/
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

/*Value to matched_map*/
struct match_tracker {
    __u16 count;
    struct tproxy_key matched_keys[MATCHED_KEY_DEPTH];
};



/*value to ifindex_ip_map*/
struct ifindex_ip4 {
    __u32 ipaddr;
    char ifname[IFNAMSIZ];
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

/*bpf program map*/
struct bpf_elf_map SEC("maps") prog_map = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= 3,
	.size_key	= sizeof(uint32_t),
	.size_value	= sizeof(uint32_t),
	.pinning	= PIN_GLOBAL_NS,
	.max_elem	= 10,
};

/*map to track up to 3 key matches per incomming packet search.  Map is 
then used to search for port mappings.  This was required when source filtering was 
added to accommodate the additional intructions per ebpf program.  The search now spans
5 ebpf programs  */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(id, BPF_MAP_ID_MATCHED_KEY);
    __uint(key_size, sizeof(unsigned int));
    __uint(value_size, sizeof(struct match_tracker));
    __uint(max_entries, MATCHED_INT_DEPTH);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} matched_map SEC(".maps");

/* File system pinned Array Map key mapping to ifindex with used to allow 
 * ebpf program to learn the ip address
 * of the interface it is attched to by reading the mapping
 * provided by user space it can use skb->ingre __uint(key_size, sizeof(uint32_t));ss_ifindex
 * to find its cooresponding ip address. Currently used to limit
 * ssh to only the attached interface ip 
*/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(id, BPF_MAP_ID_IFINDEX_IP);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct ifindex_ip4));
    __uint(max_entries, 28);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifindex_ip_map SEC(".maps");

//map to keep status of diagnostic rules
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(id, BPF_MAP_ID_DIAG_MAP);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct diag_ip4));
    __uint(max_entries, 28);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} diag_map SEC(".maps");

//map to keep track of total entries in zt_tproxy_map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(id, BPF_MAP_ID_TUPLE_COUNT_MAP);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tuple_count_map SEC(".maps");

/* File system pinned Hashmap to store the socket mapping with look up key with the 
* following struct format. 
*
* struct tproxy_key {
*    __u32 dst_ip;
*    __u16 dprefix_len;
*    __u16 pad;
*
*    which is a combination of ip prefix and cidr mask length.
*
*    The value is has the format of the following struct
*
*    struct tproxy_tuple {
*    __u32 dst_ip; future use
*	 __u32 src_ip; 
*    __u16 index_len; //tracks the number of entries in the index_table
*    __u16 index_table[MAX_INDEX_ENTRIES];
*    struct tproxy_port_mapping port_mapping[MAX_TABLE_SIZE];
*    }
*/
struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(id, BPF_MAP_ID_TPROXY);
     __uint(key_size, sizeof(struct tproxy_key));
     __uint(value_size,sizeof(struct tproxy_tuple));
     __uint(max_entries, BPF_MAX_ENTRIES);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} zt_tproxy_map SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(id, BPF_MAP_ID_TCP_MAP);
     __uint(key_size, sizeof(struct tuple_key));
     __uint(value_size,sizeof(struct tcp_state));
     __uint(max_entries, 200);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_map SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(id, BPF_MAP_ID_UDP_MAP);
     __uint(key_size, sizeof(struct tuple_key));
     __uint(value_size,sizeof(struct udp_state));
     __uint(max_entries, 200);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_map SEC(".maps");

/* function for ebpf program to access zt_tproxy_map entries
 * based on {prefix,mask,protocol} i.e. {192.168.1.0,24,IPPROTO_TCP}
 */
static inline struct tproxy_tuple *get_tproxy(struct tproxy_key key){
    struct tproxy_tuple *tu;
    tu = bpf_map_lookup_elem(&zt_tproxy_map, &key);
	return tu;
}

static inline void del_tcp(struct tuple_key key){
     bpf_map_delete_elem(&tcp_map, &key);
}

static inline struct tcp_state *get_tcp(struct tuple_key key){
    struct tcp_state *ts;
    ts = bpf_map_lookup_elem(&tcp_map, &key);
	return ts;
}

static inline void del_udp(struct tuple_key key){
     bpf_map_delete_elem(&udp_map, &key);
}

static inline struct udp_state *get_udp(struct tuple_key key){
    struct udp_state *us;
    us = bpf_map_lookup_elem(&udp_map, &key);
	return us;
}

/* Function used by ebpf program to access ifindex_ip_map
 * inroder to lookup the ip associed with its attached interface
 * This allows distiguishing between socket to the local system i.e. ssh
 *  vs socket that need to be forwarded to the tproxy splicing function
 * 
 */
static inline struct ifindex_ip4 *get_local_ip4(__u32 key){
    struct ifindex_ip4 *ifip4;
    ifip4 = bpf_map_lookup_elem(&ifindex_ip_map, &key);

	return ifip4;
}

static inline struct diag_ip4 *get_diag_ip4(__u32 key){
    struct diag_ip4 *if_diag;
    if_diag = bpf_map_lookup_elem(&diag_map, &key);

	return if_diag;
}

/*function to update the ifindex_ip_map locally from ebpf possible
future use*/
/*static inline void update_local_ip4(__u32 ifindex,__u32 key){
    struct ifindex_ip4 *ifip4;
    ifip4 = bpf_map_lookup_elem(&ifindex_ip_map, &key);
    if(ifip4){
        __sync_fetch_and_add(&ifip4->ifindex, ifindex);
    }
}*/

/*function to update the matched_map locally from ebpf*/
static inline void insert_matched_key(struct match_tracker matched_keys, unsigned int key){
     bpf_map_update_elem(&matched_map, &key, &matched_keys,0);
}

/*Function to get stored matched tracker*/
static inline struct match_tracker *get_matched_keys(unsigned int key){
    struct match_tracker *mt;
    mt = bpf_map_lookup_elem(&matched_map, &key);
	return mt;
}

/*Function to get stored matched key count*/
static inline __u16 get_matched_count(unsigned key){
    struct match_tracker *mt;
    __u16 mc = 0;
    mt = bpf_map_lookup_elem(&matched_map,&key);
    if(mt){
        mc = mt->count;
    }
    return mc;
}

/*Function to clear matched tracker*/
static inline void clear_match_tracker(__u32 key){
    struct match_tracker mt = {0};
    bpf_map_update_elem(&matched_map, &key, &mt,0);
}

/* function to determine if an incomming packet is a udp/tcp IP tuple
* or not.  If not returns NULL.  If true returns a struct bpf_sock_tuple
* from the combined IP SA|DA and the TCP/UDP SP|DP. 
*/
static struct bpf_sock_tuple *get_tuple(struct __sk_buff *skb, __u64 nh_off,
    __u16 eth_proto, bool *ipv4, bool *ipv6, bool *udp, bool *tcp, bool *arp, bool *icmp, struct diag_ip4 *local_diag){
    struct bpf_sock_tuple *result;
    __u8 proto = 0;
    int ret;
    
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
            /* check outter ip header */
            struct udphdr *udph = (struct udphdr *)(skb->data + nh_off + sizeof(struct iphdr));
            if ((unsigned long)(udph + 1) > (unsigned long)skb->data_end){
                if(local_diag->verbose){
                    bpf_printk("udp header is too big");
                }
                return NULL;
            }

            /* If geneve port 6081, then do geneve header verification */
            if (bpf_ntohs(udph->dest) == GENEVE_UDP_PORT){
                if(local_diag->verbose){
                    bpf_printk("GENEVE MATCH FOUND ON DPORT = %d", bpf_ntohs(udph->dest));
                    bpf_printk("UDP PAYLOAD LENGTH = %d", bpf_ntohs(udph->len));
                }
                /* read receive geneve version and header length */
                __u8 *genhdr = (void *)(unsigned long)(skb->data + nh_off + sizeof(struct iphdr) + sizeof(struct udphdr));
                if ((unsigned long)(genhdr + 1) > (unsigned long)skb->data_end){
                    if(local_diag->verbose){
                        bpf_printk("geneve header is too big");
                    }
                    return NULL;
                }
                int gen_ver  = genhdr[0] & 0xC0 >> 6;
                int gen_hdr_len = genhdr[0] & 0x3F;
                if(local_diag->verbose){
                    bpf_printk("Received Geneve version is %d", gen_ver);
                    bpf_printk("Received Geneve header length is %d bytes", gen_hdr_len * 4);
                }
                /* if the length is not equal to 32 bytes and version 0 */
                if ((gen_hdr_len != AWS_GNV_HDR_OPT_LEN / 4) || (gen_ver != GENEVE_VER)){
                    if(local_diag->verbose){
                        bpf_printk("Geneve header length:version error %d:%d", gen_hdr_len * 4, gen_ver);
                    }
                    return NULL;
                }

                /* Updating the skb to pop geneve header */
                //bpf_printk("SKB DATA LENGTH =%d", skb->len);
                ret = bpf_skb_adjust_room(skb, -68, BPF_ADJ_ROOM_MAC, 0);
                if (ret) {
                    if(local_diag->verbose){
                        bpf_printk("error calling skb adjust room.");
                    }
                    return NULL;
                }
                if(local_diag->verbose){
                    bpf_printk("SKB DATA LENGTH AFTER=%d", skb->len);
                }
                /* Initialize iph for after popping outer */
                iph = (struct iphdr *)(skb->data + nh_off);
                if((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                    if(local_diag->verbose){
                        bpf_printk("IP header too big");
                    }
                    return NULL;
                }
                proto = iph->protocol;
                if(local_diag->verbose){
                    bpf_printk("INNER Protocol = %d", proto);
                }
            }
            /* set udp to true if inner is udp, and let all other inner protos to the next check point */
            if (proto == IPPROTO_UDP) {
                *udp = true;
            }
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

static inline void iterate_masks(__u32 *mask, __u32 *exponent){
    if(*mask == 0x00ffffff){
        *exponent=16;
    }
    if(*mask == 0x0000ffff){
        *exponent=8;
    }
    if(*mask == 0x000000ff){
        *exponent=0;
    }
    if((*mask >= 0x80ffffff) && (*exponent >= 24)){
        *mask = *mask - (1 << *exponent);
    }else if((*mask >= 0x0080ffff) && (*exponent >= 16)){
        *mask = *mask - (1 << *exponent);
    }else if((*mask >= 0x000080ff) && (*exponent >= 8)){
        *mask = *mask - (1 << *exponent);
    }else if((*mask >= 0x00000080) && (*exponent >= 0)){
        *mask = *mask - (1 << *exponent);
    }
}

//ebpf tc code entry program
SEC("action")
int bpf_sk_splice(struct __sk_buff *skb){
    struct bpf_sock *sk; 
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    bool ipv4 = false;
    bool ipv6 = false;
    bool udp=false;
    bool tcp=false;
    bool arp=false;
    bool icmp=false;
    int ret;
    
    /*look up attached interface inbound diag status*/
    struct diag_ip4 *local_diag = get_diag_ip4(skb->ingress_ifindex);
    if(!local_diag){
        if(skb->ingress_ifindex == 1){
            return TC_ACT_OK;
        }else{
            return TC_ACT_SHOT;
        }
    }

    struct tuple_key tcp_state_key;
    struct tuple_key udp_state_key;

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    /* verify its a valid eth header within the packet bounds */
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
	}

    /* check if incomming packet is a UDP or TCP tuple */
    tuple = get_tuple(skb, sizeof(*eth), eth->h_proto, &ipv4,&ipv6, &udp, &tcp, &arp, &icmp, local_diag);

    /*look up attached interface IP address*/
    struct ifindex_ip4 *local_ip4 = get_local_ip4(skb->ingress_ifindex);

    /* if not tuple forward ARP and drop all other traffic */
    if (!tuple){
        if(skb->ingress_ifindex == 1){
            return TC_ACT_OK;
        }
        else if(arp){
            return TC_ACT_OK;
	    }
        else if(icmp){
            struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
            if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            struct icmphdr *icmph = (struct icmphdr *)((unsigned long)iph + sizeof(*iph));
            if ((unsigned long)(icmph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            else if((icmph->type == 8) && (icmph->code == 0)){
                if(local_diag && local_diag->echo){
                    return TC_ACT_OK;
                }
                else{
                    return TC_ACT_SHOT;
                }
            }
            else if((icmph->type == 0) && (icmph->code == 0)){
                return TC_ACT_OK;
            }
            else{
                return TC_ACT_SHOT;
            }
        }else{
            return TC_ACT_SHOT;
        }
    }

    /* determine length of tupple */
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       return TC_ACT_SHOT;
    }

    if((skb->ingress_ifindex == 1) && udp && (bpf_ntohs(tuple->ipv4.dport) == 53)){
       return TC_ACT_OK;
    }

    /*if(bpf_ntohs(tuple->ipv4.sport) == 53){
       return TC_ACT_OK;
    }*/


    /* allow ssh to local system */
    if(((!local_ip4) || (!local_ip4->ipaddr)) || ((tuple->ipv4.daddr == local_ip4->ipaddr) && !local_diag->ssh_disable)){
       if(tcp && (bpf_ntohs(tuple->ipv4.dport) == 22)){
            return TC_ACT_OK;
       }
    }

    /* forward DHCP messages to local system */
    if(udp && (bpf_ntohs(tuple->ipv4.sport) == 67) && (bpf_ntohs(tuple->ipv4.dport) == 68)){
       return TC_ACT_OK;
    }
     /* if tcp based tuple implement statefull inspection to see if they were
     * initiated by the local OS if not pass on to tproxy logic to determin if the
     * openziti router has tproxy intercepts defined for the flow
     */
    if(tcp){
    /*if tcp based tuple implement statefull inspection to see if they were
     * initiated by the local OS and If yes jump to assign. Then check if tuple is a reply to 
      outbound initated from through the router interface. if not pass on to tproxy logic
      to determine if the openziti router has tproxy intercepts defined for the flow*/
       sk = bpf_skc_lookup_tcp(skb, tuple, tuple_len,BPF_F_CURRENT_NETNS, 0);
       if(sk){
            if (sk->state != BPF_TCP_LISTEN){
                goto assign;
            }
            bpf_sk_release(sk);
        /*reply to outbound passthrough check*/
       }else{
            struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
            if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            struct tcphdr *tcph = (struct tcphdr *)((unsigned long)iph + sizeof(*iph));
            if ((unsigned long)(tcph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            tcp_state_key.daddr = tuple->ipv4.saddr;
            tcp_state_key.saddr = tuple->ipv4.daddr;
            tcp_state_key.sport = tuple->ipv4.dport;
            tcp_state_key.dport = tuple->ipv4.sport;
	        unsigned long long tstamp = bpf_ktime_get_ns();
            struct tcp_state *tstate = get_tcp(tcp_state_key);
            /*check tcp state and timeout if greater than 60 minutes without traffic*/
            if(tstate && (tstamp < (tstate->tstamp + 3600000000000))){    
                if(tcph->syn  && tcph->ack){
                    tstate->ack =1;
                    tstate->tstamp = tstamp;
                    if(local_diag->verbose){
                        bpf_printk("got syn-ack from 0x%X :%d\n" ,bpf_ntohl(tuple->ipv4.saddr), bpf_ntohs(tuple->ipv4.sport));
                    }
                    return TC_ACT_OK;
                }
                else if(tcph->fin){
                    if(tstate->est){
                        tstate->tstamp = tstamp;
                        tstate->fin = 1;
                        if(local_diag->verbose){
                            bpf_printk("Received fin from Server 0x%X:%d\n", bpf_ntohl(tuple->ipv4.saddr), bpf_ntohs(tuple->ipv4.sport));
                        }
                        return TC_ACT_OK;
                    }
                }
                else if(tcph->rst){
                    if(tstate->est){
                        del_tcp(tcp_state_key);
                        if(local_diag->verbose){
                            bpf_printk("Received rst from Server 0x%X :%d\n", bpf_ntohl(tuple->ipv4.saddr), bpf_ntohs(tuple->ipv4.sport));
                        }
                        tstate = get_tcp(tcp_state_key);
                        if(!tstate){
                            if(local_diag->verbose){
                                bpf_printk("removed tcp state: 0x%X:%d\n", bpf_ntohl(tuple->ipv4.saddr), bpf_ntohs(tuple->ipv4.sport));
                            }
                        }
                        return TC_ACT_OK;
                    }
                }
                else if(tcph->ack){
                    if(tstate->est){
                        tstate->tstamp = tstamp;
                        return TC_ACT_OK;
                    }
                }
            }
            else if(tstate){
                del_tcp(tcp_state_key);
            }
       }
    }else{
       /* if udp based tuple implement statefull inspection to 
        * implement statefull inspection to see if they were initiated by the local OS and If yes jump
        * to assign label. Then check if tuple is a reply to outbound initated from through the router interface. 
        * if not pass on to tproxy logic to determine if the openziti router has tproxy intercepts
        * defined for the flow*/
        sk = bpf_sk_lookup_udp(skb, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0);
        if(sk){
           /*
            * check if there is a dest ip associated with the local socket. if yes jump to assign if not
            * disregard and release the sk and continue on to check for tproxy mapping.
            */
           if(sk->dst_ip4){
                goto assign;
           }
           bpf_sk_release(sk);
        /*reply to outbound passthrough check*/
        }else{
            udp_state_key.daddr = tuple->ipv4.saddr;
            udp_state_key.saddr = tuple->ipv4.daddr;
            udp_state_key.sport = tuple->ipv4.dport;
            udp_state_key.dport = tuple->ipv4.sport;
            unsigned long long tstamp = bpf_ktime_get_ns();
            struct udp_state *ustate = get_udp(udp_state_key);
            if(ustate){
                /*if udp outbound state has been up for 30 seconds without traffic remove it from hashmap*/
                if(tstamp > (ustate->tstamp + 30000000000)){
                    if(local_diag->verbose){
                        bpf_printk("udp inbound matched expired state from 0x%X:%d\n", bpf_ntohl(tuple->ipv4.saddr), bpf_ntohs(tuple->ipv4.sport));
                    }
                    del_udp(udp_state_key);
                    ustate = get_udp(udp_state_key);
                    if(!ustate){
                        if(local_diag->verbose){
                            bpf_printk("expired udp state removed from 0x%X:%d\n", bpf_ntohl(tuple->ipv4.saddr), bpf_ntohs(tuple->ipv4.sport));
                        }
                    }
                }
                else{
                    ustate->tstamp = tstamp;
                    return TC_ACT_OK;
                }
            }
        }
    }
    //init the match_count_map
    clear_match_tracker(skb->ifindex);
    bpf_tail_call(skb, &prog_map, 1);
    if(skb->ingress_ifindex == 1){
        return TC_ACT_OK;
    }else{
        return TC_ACT_SHOT;
    }
    assign:
    /*attempt to splice the skb to the tproxy or local socket*/
    ret = bpf_sk_assign(skb, sk, 0);
    /*release sk*/
    bpf_sk_release(sk);
    if(ret == 0){
        //if succedded forward to the stack
        return TC_ACT_OK;
    }
    /*else drop packet if not running on loopback*/
    if(skb->ingress_ifindex == 1){
        return TC_ACT_OK;
    }else{
        return TC_ACT_SHOT;
    }
}

/*Search for keys with Dest mask lengths from /32 down to /25
* and Source masks /32 down to /0 */
SEC("3/1")
int bpf_sk_splice1(struct __sk_buff *skb){
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    int protocol;

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    

    /* check if incomming packet is a UDP or TCP tuple */
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
    protocol = iph->protocol;
    tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       return TC_ACT_SHOT;
    }
	struct tproxy_tuple *tproxy;
    __u32 dexponent=24;  /* unsigned integer used to calulate prefix matches */
    __u32 dmask = 0xffffffff;  /* starting mask value used in prfix match calculation */
    __u32 sexponent=24;  /* unsigned integer used to calulate prefix matches */
    __u32 smask = 0xffffffff;  /* starting mask value used in prfix match calculation */
    __u16 maxlen = 8; /* max number ip ipv4 prefixes */
    __u16 smaxlen = 32; /* max number ip ipv4 prefixes */
    /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
    struct match_tracker key_tracker = {0,{}};
    insert_matched_key(key_tracker, skb->ifindex);
    struct match_tracker *tracked_key_data = get_matched_keys(skb->ifindex);
     if(!tracked_key_data){
       return TC_ACT_SHOT;
    }
    for (__u16 dcount = 0;dcount <= maxlen; dcount++){
            
            /*
             * lookup based on tuple-ipv4.daddr logically ANDed with
             * cidr mask starting with /32 and working down to /1 if no match packet is discarded
             */
            for (__u16 scount = 0; scount <= smaxlen; scount++){
                
                struct tproxy_key key = {(tuple->ipv4.daddr & dmask),(tuple->ipv4.saddr & smask), 32-dcount, smaxlen-scount, protocol, 0};
                if ((tproxy = get_tproxy(key))){
                    if(tracked_key_data->count < MATCHED_KEY_DEPTH){
                        tracked_key_data->matched_keys[tracked_key_data->count] = key;
                        tracked_key_data->count++;
                    }
                    if(tracked_key_data->count == MATCHED_KEY_DEPTH){
                            bpf_tail_call(skb, &prog_map, 5);
                    }
                }              
                if(smask == 0x00000000){
                    break;
                }
                iterate_masks(&smask, &sexponent);
                sexponent++;
            }
            /*algorithm used to calculate mask while traversing
            each octet.
            */
            if(dmask == 0x80ffffff){
                bpf_tail_call(skb, &prog_map, 2);
                break;
            }
            iterate_masks(&dmask, &dexponent);
            smask = 0xffffffff;
            sexponent = 24;
            dexponent++;
    }
    return TC_ACT_SHOT;
}

/*Search for keys with Dest mask lengths from /24 down to /17
* and Source masks /32 down to /0 */
SEC("3/2")
int bpf_sk_splice2(struct __sk_buff *skb){
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    int protocol;

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    

    /* check if incomming packet is a UDP or TCP tuple */
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
    protocol = iph->protocol;
    tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       return TC_ACT_SHOT;
    }
	struct tproxy_tuple *tproxy;
    __u32 dexponent=16;  /* unsigned integer used to calulate prefix matches */
    __u32 dmask = 0xffffff;  /* starting mask value used in prfix match calculation */
    __u32 sexponent=24;  /* unsigned integer used to calulate prefix matches */
    __u32 smask = 0xffffffff;  /* starting mask value used in prfix match calculation */
    __u16 maxlen = 8; /* max number ip ipv4 prefixes */
    __u16 smaxlen = 32; /* max number ip ipv4 prefixes */
    /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
    struct match_tracker *tracked_key_data = get_matched_keys(skb->ifindex);
    if(!tracked_key_data){
       return TC_ACT_SHOT;
    }
    for (__u16 dcount = 0;dcount <= maxlen; dcount++){
            
            /*
             * lookup based on tuple-ipv4.daddr logically ANDed with
             * cidr mask starting with /32 and working down to /1 if no match packet is discarded
             */
            for (__u16 scount = 0; scount <= smaxlen; scount++){
                
                struct tproxy_key key = {(tuple->ipv4.daddr & dmask),(tuple->ipv4.saddr & smask), 24-dcount, smaxlen-scount, protocol, 0};
               
                if ((tproxy = get_tproxy(key))){
                    if(tracked_key_data->count < MATCHED_KEY_DEPTH){
                        tracked_key_data->matched_keys[tracked_key_data->count] = key;
                        tracked_key_data->count++;
                    }
                    if(tracked_key_data->count == MATCHED_KEY_DEPTH){
                            bpf_tail_call(skb, &prog_map, 5);
                    }
                }              
                if(smask == 0x00000000){
                    break;
                }
                iterate_masks(&smask, &sexponent);
                sexponent++;
            }
            /*algorithm used to calculate mask while traversing
            each octet.
            */
            if(dmask == 0x80ffff){
                bpf_tail_call(skb, &prog_map, 3);
                break;
            }
            iterate_masks(&dmask, &dexponent);
            smask = 0xffffffff;
            sexponent = 24;
            dexponent++;
    }
    return TC_ACT_SHOT;
}

/*Search for keys with Dest mask lengths from /16 down to /9
* and Source masks /32 down to /0 */
SEC("3/3")
int bpf_sk_splice3(struct __sk_buff *skb){
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    int protocol;

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    

    /* check if incomming packet is a UDP or TCP tuple */
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
    protocol = iph->protocol;
    tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       return TC_ACT_SHOT;
    }
	struct tproxy_tuple *tproxy;
    __u32 dexponent=8;  /* unsigned integer used to calulate prefix matches */
    __u32 dmask = 0xffff;  /* starting mask value used in prfix match calculation */
    __u32 sexponent=24;  /* unsigned integer used to calulate prefix matches */
    __u32 smask = 0xffffffff;  /* starting mask value used in prfix match calculation */
    __u16 maxlen = 8; /* max number ip ipv4 prefixes */
    __u16 smaxlen = 32; /* max number ip ipv4 prefixes */
    /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
    struct match_tracker *tracked_key_data = get_matched_keys(skb->ifindex);
    if(!tracked_key_data){
       return TC_ACT_SHOT;
    }
    for (__u16 dcount = 0;dcount <= maxlen; dcount++){
            
            /*
             * lookup based on tuple-ipv4.daddr logically ANDed with
             * cidr mask starting with /32 and working down to /1 if no match packet is discarded
             */
            for (__u16 scount = 0; scount <= smaxlen; scount++){
                
                struct tproxy_key key = {(tuple->ipv4.daddr & dmask),(tuple->ipv4.saddr & smask), 16-dcount, smaxlen-scount, protocol, 0};
                if ((tproxy = get_tproxy(key))){
                    if(tracked_key_data->count < MATCHED_KEY_DEPTH){
                        tracked_key_data->matched_keys[tracked_key_data->count] = key;
                        tracked_key_data->count++;
                    }
                    if(tracked_key_data->count == MATCHED_KEY_DEPTH){
                            bpf_tail_call(skb, &prog_map, 5);
                    }
                }               
                if(smask == 0x00000000){
                    break;
                }
                iterate_masks(&smask, &sexponent);
                sexponent++;
            }
            /*algorithm used to calculate mask while traversing
            each octet.
            */
            if(dmask == 0x80ff){
                bpf_tail_call(skb, &prog_map, 4);
                break;
            }
            iterate_masks(&dmask, &dexponent);
            smask = 0xffffffff;
            sexponent = 24;
            dexponent++;
    }
    return TC_ACT_SHOT;
}

/*Search for keys with Dest mask lengths from /8 down to /0
* and Source masks /32 down to /0 */
SEC("3/4")
int bpf_sk_splice4(struct __sk_buff *skb){
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    int protocol;

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    

    /* check if incomming packet is a UDP or TCP tuple */
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
    protocol = iph->protocol;
    tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       return TC_ACT_SHOT;
    }
	struct tproxy_tuple *tproxy;
    __u32 dexponent=0;  /* unsigned integer used to calulate prefix matches */
    __u32 dmask = 0xff;  /* starting mask value used in prfix match calculation */
    __u32 sexponent=24;  /* unsigned integer used to calulate prefix matches */
    __u32 smask = 0xffffffff;  /* starting mask value used in prfix match calculation */
    __u16 maxlen = 8; /* max number ip ipv4 prefixes */
    __u16 smaxlen = 32; /* max number ip ipv4 prefixes */
    /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
    struct match_tracker *tracked_key_data = get_matched_keys(skb->ifindex);
    if(!tracked_key_data){
       return TC_ACT_SHOT;
    }
    for (__u16 dcount = 0;dcount <= maxlen; dcount++){
            
            /*
             * lookup based on tuple-ipv4.daddr logically ANDed with
             * cidr mask starting with /32 and working down to /1 if no match packet is discarded
             */
            for (__u16 scount = 0; scount <= smaxlen; scount++){
                
                struct tproxy_key key = {(tuple->ipv4.daddr & dmask),(tuple->ipv4.saddr & smask), 8-dcount, smaxlen-scount, protocol, 0};
                if ((tproxy = get_tproxy(key))){
                    if(tracked_key_data->count < MATCHED_KEY_DEPTH){
                        tracked_key_data->matched_keys[tracked_key_data->count] = key;
                        tracked_key_data->count++;
                    }
                    if(tracked_key_data->count == MATCHED_KEY_DEPTH){
                            bpf_tail_call(skb, &prog_map, 5);
                    }
                }              
                if(smask == 0x00000000){
                    break;
                }
                iterate_masks(&smask, &sexponent);
                sexponent++;
            }
            /*algorithm used to calculate mask while traversing
            each octet.
            */
            if(dmask == 0x00000000){
                if((tracked_key_data->count > 0)){
                    bpf_tail_call(skb, &prog_map, 5);
                    break;
                }
            }
            iterate_masks(&dmask, &dexponent);
            smask = 0xffffffff;
            sexponent = 24;
            dexponent++;
    }
    return TC_ACT_SHOT;
}

SEC("3/5")
int bpf_sk_splice5(struct __sk_buff *skb){
    struct bpf_sock *sk;
    int ret; 
    struct bpf_sock_tuple *tuple,sockcheck = {0};
    int tuple_len;

    /*look up attached interface inbound diag status*/
    struct diag_ip4 *local_diag = get_diag_ip4(skb->ingress_ifindex);
    if(!local_diag){
        if(skb->ingress_ifindex == 1){
            return TC_ACT_OK;
        }else{
            return TC_ACT_SHOT;
        }
    }

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
    tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    //tuple = get_tuple(skb, sizeof(*eth), eth->h_proto, &ipv4,&ipv6, &udp, &tcp, &arp);
    if(!tuple){
       return TC_ACT_SHOT;
    }

    /* determine length of tupple */
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       return TC_ACT_SHOT;
    }
    struct tproxy_key key;
     /*look up attached interface IP address*/
    struct ifindex_ip4 *local_ip4 = get_local_ip4(skb->ingress_ifindex);
    if(!local_ip4){
       return TC_ACT_SHOT;
    }   
    struct tproxy_tuple *tproxy;
    struct match_tracker *key_tracker;
    __u16 match_count = get_matched_count(skb->ifindex);
    if (match_count > MATCHED_KEY_DEPTH){
       match_count = MATCHED_KEY_DEPTH;
    }
    for(__u16 count =0; count < match_count; count++){
        key_tracker = get_matched_keys(skb->ifindex);
        if(key_tracker){
           key = key_tracker->matched_keys[count];
        }else{
            break;
        }
        if((tproxy = get_tproxy(key)) && tuple){
            __u16 max_entries = tproxy->index_len;
            if (max_entries > MAX_INDEX_ENTRIES) {
                max_entries = MAX_INDEX_ENTRIES;
            }

            for (int index = 0; index < max_entries; index++) {
                int port_key = tproxy->index_table[index];
                //check if there is a udp or tcp destination port match
                if ((bpf_ntohs(tuple->ipv4.dport) >= bpf_ntohs(tproxy->port_mapping[port_key].low_port))
                && (bpf_ntohs(tuple->ipv4.dport) <= bpf_ntohs(tproxy->port_mapping[port_key].high_port))) {
                     if(local_diag->verbose){
                        bpf_printk("%s",local_ip4->ifname);
                        bpf_printk("source_ip = 0x%X",bpf_ntohl(tuple->ipv4.saddr));
                        bpf_printk("dest_ip = 0x%X",bpf_ntohl(tuple->ipv4.daddr));
                        bpf_printk("protocol_id = %d",key.protocol);
                        bpf_printk("tproxy_mapping->%d to %d\n",bpf_ntohs(tuple->ipv4.dport),
                        bpf_ntohs(tproxy->port_mapping[port_key].tproxy_port));
                    }
                    /*check if interface is set for per interface rule awarness and if yes check if it is in the rules interface list.  If not in
                    the interface list drop it on all interfaces accept loopback.  If its not aware then forward based on mapping*/
                    sockcheck.ipv4.daddr = 0x0100007f;
                    sockcheck.ipv4.dport = tproxy->port_mapping[port_key].tproxy_port;
                    if(!local_diag->per_interface){
                        if(tproxy->port_mapping[port_key].tproxy_port == 0){
                            return TC_ACT_OK;
                        }
                        if(key.protocol == IPPROTO_TCP){
                            sk = bpf_skc_lookup_tcp(skb, &sockcheck, sizeof(sockcheck.ipv4),BPF_F_CURRENT_NETNS, 0);
                        }else{
                            sk = bpf_sk_lookup_udp(skb, &sockcheck, sizeof(sockcheck.ipv4),BPF_F_CURRENT_NETNS, 0);
                        }
                        if(!sk){
                            return TC_ACT_SHOT;
                        }
                        if((key.protocol == IPPROTO_TCP) && (sk->state != BPF_TCP_LISTEN)){
                            bpf_sk_release(sk);
                            return TC_ACT_SHOT;    
                        }
                        goto assign;
                    }
                    
                    for(int x = 0; x < MAX_IF_LIST_ENTRIES; x++){
                        if(tproxy->port_mapping[port_key].if_list[x] == skb->ifindex){
                            if(tproxy->port_mapping[port_key].tproxy_port == 0){
                                return TC_ACT_OK;
                            }
                            if(key.protocol == IPPROTO_TCP){
                                sk = bpf_skc_lookup_tcp(skb, &sockcheck, sizeof(sockcheck.ipv4),BPF_F_CURRENT_NETNS, 0);
                            }else{
                                sk = bpf_sk_lookup_udp(skb, &sockcheck, sizeof(sockcheck.ipv4),BPF_F_CURRENT_NETNS, 0);
                            }
                            if(!sk){
                                return TC_ACT_SHOT;
                            }
                            if((key.protocol == IPPROTO_TCP) && (sk->state != BPF_TCP_LISTEN)){
                                bpf_sk_release(sk);
                                return TC_ACT_SHOT;    
                            }
                            goto assign;
                        }
                    }

                    if(skb->ifindex == 1){
                        if(local_diag->verbose){
                            bpf_printk("%s failed to match rule: Reason interface list", local_ip4->ifname);
                        }
                        return TC_ACT_OK;
                    }
                    else{
                        if(local_diag->verbose){
                            bpf_printk("%s failed to match rule: Reason interface list", local_ip4->ifname);
                        }
                        return TC_ACT_SHOT;
                    }
                }
            }
        }
    }
    if(skb->ingress_ifindex == 1){
        return TC_ACT_OK;
    }else{
        return TC_ACT_SHOT;
    }
    assign:
    /*attempt to splice the skb to the tproxy or local socket*/
    ret = bpf_sk_assign(skb, sk, 0);
    /*release sk*/
    bpf_sk_release(sk);
    if(ret == 0){
        //if succedded forward to the stack
        return TC_ACT_OK;
    }
    /*else drop packet if not running on loopback*/
    if(skb->ingress_ifindex == 1){
        return TC_ACT_OK;
    }else{
        return TC_ACT_SHOT;
    }

}

SEC("license") const char __license[] = "Dual BSD/GPL";
