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
#include <net/if.h>

#define BPF_MAP_ID_TPROXY  1
#define BPF_MAP_ID_IFINDEX_IP  2
#define BPF_MAP_ID_PROG_MAP 3
#define BPF_MAP_ID_MATCHED_KEY 4
#define BPF_MAP_ID_MATCHED_COUNT 5
#define BPF_MAX_ENTRIES    100 //MAX # PREFIXES
#define MAX_INDEX_ENTRIES  100 //MAX port ranges per prefix need to match in user space apps 
#define MAX_TABLE_SIZE  65536 //needs to match in userspace
#define GENEVE_UDP_PORT         6081
#define GENEVE_VER              0
#define AWS_GNV_HDR_OPT_LEN     32 // Bytes
#define AWS_GNV_HDR_LEN         40 // Bytes
#define MATCHED_KEY_DEPTH       3
#define MATCHED_INT_DEPTH       50



struct tproxy_port_mapping {
    __u16 low_port;
    __u16 high_port;
    __u16 tproxy_port;
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

/*Value to matched_map*/
struct match_tracker {
    __u16 count;
    struct tproxy_key matched_keys[MATCHED_KEY_DEPTH];
};



/*value to ifindex_ip_map*/
struct ifindex_ip4 {
    __u32 ipaddr;
    char ifname[IF_NAMESIZE];
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

/*matched map*/
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
    __uint(max_entries, 50);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifindex_ip_map SEC(".maps");

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

/* function for ebpf program to access zt_tproxy_map entries
 * based on {prefix,mask,protocol} i.e. {192.168.1.0,24,IPPROTO_TCP}
 */
static inline struct tproxy_tuple *get_tproxy(struct tproxy_key key){
    struct tproxy_tuple *tu;
    tu = bpf_map_lookup_elem(&zt_tproxy_map, &key);
	return tu;
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

/*function to update the ifindex_ip_map locally from ebpf possible
future use*/
/*static inline void update_local_ip4(__u32 ifindex,__u32 key){
    struct ifindex_ip4 *ifip4;
    ifip4 = bpf_map_lookup_elem(&ifindex_ip_map, &key);
    if(ifip4){
        __sync_fetch_and_add(&ifip4->ifindex, ifindex);
    }
}*/

/*function to update the matched_key_map locally from ebpf*/
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
    __u16 eth_proto, bool *ipv4, bool *ipv6, bool *udp, bool *tcp, bool *arp){
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
            bpf_printk("header too big");
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
            *udp = true;
        }
        /* check if ip protocol is TCP */
        if (proto == IPPROTO_TCP) {
            *tcp = true;
        }/* check if ip protocol is not UDP and not TCP to return NULL */
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



//ebpf tc code
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
    int ret;

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    /* verify its a valid eth header within the packet bounds */
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
	}

    /* check if incomming packet is a UDP or TCP tuple */
    tuple = get_tuple(skb, sizeof(*eth), eth->h_proto, &ipv4,&ipv6, &udp, &tcp, &arp);

    /*look up attached interface IP address*/
    struct ifindex_ip4 *local_ip4 = get_local_ip4(skb->ingress_ifindex);

    /* if not tuple forward ARP and drop all other traffic */
    if (!tuple){
        if(skb->ingress_ifindex == 1){
        return TC_ACT_OK;
        }
        else if(arp){
            return TC_ACT_OK;
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



    /* allow ssh to local system */
    if(((!local_ip4) || (!local_ip4->ipaddr)) || (tuple->ipv4.daddr == local_ip4->ipaddr)){
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
       sk = bpf_skc_lookup_tcp(skb, tuple, tuple_len,BPF_F_CURRENT_NETNS, 0);
       if(sk){
            if (sk->state != BPF_TCP_LISTEN){
                goto assign;
            }
            bpf_sk_release(sk);
        }
    }else{
    /* if udp based tuple implement statefull inspection to see if they were
     * initiated by the local OS If yes jump to assign.if not pass on to tproxy logic to determin if the
     * openziti router has tproxy intercepts defined for the flow
     */ 
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
    __u32 dexponent=24;  /* unsugend integer used to calulate prefix matches */
    __u32 dmask = 0xffffffff;  /* starting mask value used in prfix match calculation */
    __u32 sexponent=24;  /* unsugend integer used to calulate prefix matches */
    __u32 smask = 0xffffffff;  /* starting mask value used in prfix match calculation */
    __u16 maxlen = 8; /* max number ip ipv4 prefixes */
    __u16 smaxlen = 32; /* max number ip ipv4 prefixes */
    /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
    struct match_tracker key_tracker = {0,{}};
    insert_matched_key(key_tracker, skb->ifindex);
    struct match_tracker *tracked_key_data = get_matched_keys(skb->ifindex);
     if(!tracked_key_data){
       bpf_printk("dropping1\n");
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
    __u32 dexponent=16;  /* unsugend integer used to calulate prefix matches */
    __u32 dmask = 0xffffff;  /* starting mask value used in prfix match calculation */
    __u32 sexponent=24;  /* unsugend integer used to calulate prefix matches */
    __u32 smask = 0xffffffff;  /* starting mask value used in prfix match calculation */
    __u16 maxlen = 8; /* max number ip ipv4 prefixes */
    __u16 smaxlen = 32; /* max number ip ipv4 prefixes */
    /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
    struct match_tracker *tracked_key_data = get_matched_keys(skb->ifindex);
    if(!(tuple->ipv4.daddr == 0x010110ac)){
        return TC_ACT_SHOT;
    }
    if(!tracked_key_data){
       bpf_printk("dropping2\n");
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
    __u32 dexponent=8;  /* unsugend integer used to calulate prefix matches */
    __u32 dmask = 0xffff;  /* starting mask value used in prfix match calculation */
    __u32 sexponent=24;  /* unsugend integer used to calulate prefix matches */
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
    __u32 dexponent=0;  /* unsugend integer used to calulate prefix matches */
    __u32 dmask = 0xff;  /* starting mask value used in prfix match calculation */
    __u32 sexponent=24;  /* unsugend integer used to calulate prefix matches */
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
    bpf_printk("ip =%x\n",tuple->ipv4.daddr );
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
                
                if ((bpf_ntohs(tuple->ipv4.dport) >= bpf_ntohs(tproxy->port_mapping[port_key].low_port))
                && (bpf_ntohs(tuple->ipv4.dport) <= bpf_ntohs(tproxy->port_mapping[port_key].high_port))) {
                    bpf_printk("%s",local_ip4->ifname);
                    bpf_printk("protocol_id=%d",key.protocol);
                    bpf_printk("tproxy_mapping->%d to %d",bpf_ntohs(tuple->ipv4.dport),
                    bpf_ntohs(tproxy->port_mapping[port_key].tproxy_port));
                    if(tproxy->port_mapping[port_key].tproxy_port == 0){
                        return TC_ACT_OK;
                    }
                    sockcheck.ipv4.daddr = 0x0100007f;
                    sockcheck.ipv4.dport = tproxy->port_mapping[port_key].tproxy_port;
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
