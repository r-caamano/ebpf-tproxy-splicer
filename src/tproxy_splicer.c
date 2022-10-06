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
#include <linux/pkt_cls.h>
#include <bcc/bcc_common.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <iproute2/bpf_elf.h>
#include <stdbool.h>
#include <linux/tcp.h>\

#define BPF_MAP_ID_TPROXY  1
#define BPF_MAP_ID_IFINDEX_IP  2
#define BPF_MAX_ENTRIES    100 //MAX # PREFIXES
#define MAX_INDEX_ENTRIES  25 //MAX port ranges per prefix need to match in User space apps 
#define MAX_TABLE_SIZE  65536

struct tproxy_tcp_port_mapping {
    __u16 low_port;
    __u16 high_port;
    __u16 tproxy_port;
    __u32 tproxy_ip;
};

struct tproxy_udp_port_mapping {
    __u16 low_port;
    __u16 high_port;
    __u16 tproxy_port;
    __u32 tproxy_ip;
};

struct tproxy_tuple {
    __u32 dst_ip;
	__u32 src_ip;
    __u16 udp_index_len;
    __u16 tcp_index_len;
    __u16 udp_index_table[MAX_INDEX_ENTRIES];
    __u16 tcp_index_table[MAX_INDEX_ENTRIES];
    struct tproxy_udp_port_mapping udp_mapping[MAX_TABLE_SIZE];
    struct tproxy_tcp_port_mapping tcp_mapping[MAX_TABLE_SIZE];
};

struct tproxy_key {
    __u32 dst_ip;
    __u16 prefix_len;
    __u16 pad;
};

struct ifindex_ip4 {
    __u32 ipaddr;
    __u32 ifindex;
};



struct bpf_elf_map SEC("maps") ifindex_ip_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .id   = BPF_MAP_ID_IFINDEX_IP,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(struct ifindex_ip4),
    .max_elem = 50,
    .pinning  = PIN_GLOBAL_NS,
}; 


struct bpf_elf_map SEC("maps") zt_tproxy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .id   = BPF_MAP_ID_TPROXY,
    .size_key = sizeof(struct tproxy_key),
    .size_value = sizeof(struct tproxy_tuple),
    .max_elem = BPF_MAX_ENTRIES,
    .pinning  = PIN_GLOBAL_NS,
};

static inline struct tproxy_tuple *get_tproxy(struct tproxy_key key){
    struct tproxy_tuple *tu;
    tu = bpf_map_lookup_elem(&zt_tproxy_map, &key);
	return tu;
}

static inline struct ifindex_ip4 *get_local_ip4(__u32 key){
    struct ifindex_ip4 *ifip4;
    ifip4 = bpf_map_lookup_elem(&ifindex_ip_map, &key);

	return ifip4;
}

/*static inline void update_local_ip4(__u32 ifindex,__u32 key){
    struct ifindex_ip4 *ifip4;
    ifip4 = bpf_map_lookup_elem(&ifindex_ip_map, &key);
    if(ifip4){
        __sync_fetch_and_add(&ifip4->ifindex, ifindex);
    }
}*/

static struct bpf_sock_tuple *get_tuple(void *data, __u64 nh_off,
                                        void *data_end, __u16 eth_proto,
                                        bool *ipv4, bool *ipv6, bool *udp, bool *tcp, bool *arp){
    struct bpf_sock_tuple *result;
    __u8 proto = 0;
    
    if (eth_proto == bpf_htons(ETH_P_ARP)) {
        *arp = true;
        return NULL;
    }

    if (eth_proto == bpf_htons((ETH_P_IPV6)) {
        *ipv6 = true;
        return NULL;
    }

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(data + nh_off);

        if ((unsigned long)(iph + 1) > (unsigned long)data_end){
            bpf_printk("header too big");
            return NULL;
		}
        if (iph->ihl != 5){
		    bpf_printk("no options allowed");
            return NULL;
		}
        proto = iph->protocol;
        if(proto == IPPROTO_UDP){
            *udp = true;    
        }else if(proto == IPPROTO_TCP){
            *tcp = true;
	    }else{
             return NULL;
        }
        *ipv4 = true;
        result = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    } else {
        return NULL;
    }
    return result;
}

//ebpf tc code
SEC("sk_tproxy_splice")
int bpf_sk_splice(struct __sk_buff *skb){
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = (struct ethhdr *)(data);
    struct bpf_sock_tuple *tuple, sockcheck1 = {0}, sockcheck2 = {0};
    struct bpf_sock *sk; 
    int tuple_len;
    bool ipv4 = false;
    bool ipv6 = false;
    bool udp=false;
    bool tcp=false;
    bool arp=false;
    int ret;
    if ((unsigned long)(eth + 1) > (unsigned long)data_end){
            return TC_ACT_SHOT;
	}
    tuple = get_tuple(data, sizeof(*eth), data_end, eth->h_proto, &ipv4,&ipv6, &udp, &tcp, &arp);
    if (!tuple){
        if(arp){
           return TC_ACT_OK;
        }else{
           return TC_ACT_SHOT;
        }
	}
    tuple_len = sizeof(tuple->ipv4);
	if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
	    return TC_ACT_SHOT;
	}
	struct tproxy_tuple *tproxy;
	__u32 exponent=24;
	__u32 mask = 0xffffffff;
	__u16 maxlen = 32;
    struct ifindex_ip4 *local_ip4 = get_local_ip4(skb->ingress_ifindex);
    if((local_ip4) && (local_ip4->ipaddr)){
       if((tuple->ipv4.daddr == local_ip4->ipaddr) && (bpf_ntohs(tuple->ipv4.dport) == 22)){
            return TC_ACT_OK;
       }
    }else{
        if(tcp && (bpf_ntohs(tuple->ipv4.dport) == 22)){
            return TC_ACT_OK;
        }
    }
    if(udp && (bpf_ntohs(tuple->ipv4.sport) == 67)){
       return TC_ACT_OK;
    }
    if(tcp){
       sk = bpf_skc_lookup_tcp(skb, tuple, tuple_len,BPF_F_CURRENT_NETNS, 0);
       if(sk){
            if (sk->state != BPF_TCP_LISTEN){
                goto assign;
            }
            bpf_sk_release(sk);
        }
    }
    if(udp){
        sockcheck1.ipv4.daddr = tuple->ipv4.daddr;
        sockcheck1.ipv4.saddr = tuple->ipv4.saddr;
        sockcheck1.ipv4.dport = tuple->ipv4.dport;
        sockcheck1.ipv4.sport = tuple->ipv4.sport;
        sk = bpf_sk_lookup_udp(skb, &sockcheck1, sizeof(sockcheck1.ipv4), BPF_F_CURRENT_NETNS, 0);
        if(sk){
           if(sk->dst_ip4){
                goto assign;
           }
           bpf_sk_release(sk);
        }
    }
    for (__u16 count = 0;count <= maxlen; count++){
            struct tproxy_key key = {(tuple->ipv4.daddr & mask), maxlen-count,0};
            if ((tproxy = get_tproxy(key))){
                if(udp) {
                    __u16 udp_max_entries = tproxy->udp_index_len;
                    if (udp_max_entries > MAX_INDEX_ENTRIES) {
                        udp_max_entries = MAX_INDEX_ENTRIES;
                    }
                    for (int index = 0; index < udp_max_entries; index++) {
                        int port_key = tproxy->udp_index_table[index];
                        if ((bpf_ntohs(tuple->ipv4.dport) >= bpf_ntohs(tproxy->udp_mapping[port_key].low_port)) && (bpf_ntohs(tuple->ipv4.dport) <= bpf_ntohs(tproxy->udp_mapping[port_key].high_port))) {
                            bpf_printk("udp_tproxy_mapping->%d to %d", bpf_ntohs(tuple->ipv4.dport), bpf_ntohs(tproxy->udp_mapping[port_key].tproxy_port));
                            sockcheck2.ipv4.daddr = tproxy->udp_mapping[port_key].tproxy_ip;
                            sockcheck2.ipv4.dport = tproxy->udp_mapping[port_key].tproxy_port;
                            sk = bpf_sk_lookup_udp(skb, &sockcheck2, sizeof(sockcheck2.ipv4),BPF_F_CURRENT_NETNS, 0);
				            if(!sk){
                                return TC_ACT_SHOT;
                            }
                            goto assign;
                        }
                    }
                }else{
                    __u16 tcp_max_entries = tproxy->tcp_index_len;
                    if (tcp_max_entries > MAX_INDEX_ENTRIES) {
                        tcp_max_entries = MAX_INDEX_ENTRIES;
                    }
                    for (int index = 0; index < tcp_max_entries; index++) {
                        int port_key = tproxy->tcp_index_table[index];
                        if (tproxy->tcp_mapping[port_key].low_port) {
                            if ((bpf_ntohs(tuple->ipv4.dport) >= bpf_ntohs(tproxy->tcp_mapping[port_key].low_port)) && (bpf_ntohs(tuple->ipv4.dport) <= bpf_ntohs(tproxy->tcp_mapping[port_key].high_port))) {
                                bpf_printk("tcp_tproxy_mapping->%d to %d", bpf_ntohs(tuple->ipv4.dport), bpf_ntohs(tproxy->tcp_mapping[port_key].tproxy_port));
                				sockcheck2.ipv4.daddr = tproxy->tcp_mapping[port_key].tproxy_ip;
                                sockcheck2.ipv4.dport = tproxy->tcp_mapping[port_key].tproxy_port;
                                sk = bpf_skc_lookup_tcp(skb, &sockcheck2, sizeof(sockcheck2.ipv4),BPF_F_CURRENT_NETNS, 0);
                                if(!sk){
                                    return TC_ACT_SHOT;
                                }
                                if (sk->state != BPF_TCP_LISTEN){
                                    bpf_sk_release(sk);
                                    return TC_ACT_SHOT;
                                }
                                goto assign;
                            }
                        }
                    }
                }
            }
            if(mask == 0x00ffffff){
                exponent=16;
            }
            if(mask == 0x0000ffff){
                exponent=8;
            }
            if(mask == 0x000000ff){
                exponent=0;
            }
            if(mask == 0x00000080){
                return TC_ACT_SHOT;
            }
            if((mask >= 0x80ffffff) && (exponent >= 24)){
                mask = mask - (1 << exponent);
            }else if((mask >= 0x0080ffff) && (exponent >= 16)){
                mask = mask - (1 << exponent);
            }else if((mask >= 0x000080ff) && (exponent >= 8)){
                    mask = mask - (1 << exponent);
            }else if((mask >= 0x00000080) && (exponent >= 0)){
                mask = mask - (1 << exponent);
            }
            exponent++;
    } 
    return TC_ACT_SHOT;
    assign:
    ret = bpf_sk_assign(skb, sk, 0);
    bpf_sk_release(sk);
    if(ret == 0){
        return TC_ACT_OK;
    }
    return TC_ACT_SHOT;
}
SEC("license") const char __license[] = "Dual BSD/GPL";
