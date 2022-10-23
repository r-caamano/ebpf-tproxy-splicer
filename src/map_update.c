/*    Copyright (C) 2022  Robert Caamano   */
 /*
  *
  *   This program inserts a rule into an existing pinned 
  *   zt_tproxy_map hash table created by the tproxy_splicer
  *   program when attatched to an interface via tc
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <string.h>
#include <errno.h>



#define MAX_INDEX_ENTRIES  50 //MAX port ranges per prefix 
#define MAX_TABLE_SIZE  65536 //PORT MApping table size



struct ifindex_ip4 {
    __u32 ipaddr;
    __u32 ifindex;
};

struct tproxy_port_mapping {
    __u16 low_port;
    __u16 high_port;
    __u16 tproxy_port;
    __u32 tproxy_ip;
};

struct tproxy_tuple {
    __u32 dst_ip;
    __u32 src_ip;
    __u16 index_len;
    __u16 index_table[MAX_INDEX_ENTRIES];
    struct tproxy_port_mapping port_mapping[MAX_TABLE_SIZE];
};

struct tproxy_key {
           __u32  dst_ip;
	   __u16  prefix_len;
           __u16  protocol;
};

/* function to get ifindex by interface name */
int get_index(char *name, int *idx)
{
    int             fd, result;
    struct ifreq    irequest;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd == -1)
        return errno;

    strncpy(irequest.ifr_name, name, IF_NAMESIZE);
    if (ioctl(fd, SIOCGIFINDEX, &irequest) == -1) {
        do {
            result = close(fd);
        } while (result == -1 && errno == EINTR);
        return errno = ENOENT;
    }

    *idx = irequest.ifr_ifindex;

    return 0;
}

/* convert dotted decimal ip string to int 32 */
int32_t ip2l(char *ip){
    char *endPtr;
    int32_t byte1 = strtol(ip,&endPtr,10);
    if((byte1 <= 0) || (byte1 > 223) || (!isdigit(*(endPtr + 1)))){
        printf("Invalid IP Address: %s\n",ip);
        exit(1);	
    }
    int32_t byte2 = strtol(endPtr + 1,&endPtr,10);
    if((byte2 < 0) || (byte2 > 255) || (!isdigit(*(endPtr + 1)))){
       printf("Invalid IP Address: %s\n",ip);
       exit(1);
    }
    int32_t byte3 = strtol(endPtr + 1,&endPtr,10);
    if((byte3 < 0) || (byte3 > 255) || (!isdigit(*(endPtr + 1)))){
       printf("Invalid IP Address: %s\n",ip);
       exit(1);
    }
    int32_t byte4 = strtol(endPtr + 1,&endPtr,10);
    if((byte4 < 0) || (byte4 > 255) || (!(*(endPtr) == '\0'))){
       printf("Invalid IP Address: %s\n",ip);
       exit(1);
    }
    return (byte1 << 24) + (byte2 << 16) + (byte3 << 8) + byte4;
}

/* convert string port to unsigned short int */
unsigned short port2s(char *port){
    char *endPtr;
    int32_t tmpint = strtol(port,&endPtr,10);
    if((tmpint <=0) || (tmpint > 65535) || (!(*(endPtr) == '\0'))){
       printf("Invalid Port: %s\n", port);
       exit(1);
    }
    unsigned short usint = (unsigned short)tmpint;
    return usint;
}

/* convert string protocol number to __u8 */
__u8 proto2u8(char *protocol){
    char *endPtr;
    int32_t tmpint = strtol(protocol,&endPtr,10);
    if((tmpint <=0) || (tmpint > 255) || (!(*(endPtr) == '\0'))){
       printf("Invalid Protocol: %s\n", protocol);
       exit(1);
    }
    __u8 usint = (__u8)tmpint;
    return usint;
}

/* convert prefix string to __u16 */
__u16 len2u16(char *len){
    char *endPtr;
    int32_t tmpint = strtol(len,&endPtr,10);
    if((tmpint <= 0) || (tmpint > 32) || (!(*(endPtr) == '\0'))){
       printf("Invalid Prefix Length: %s\n", len);
       exit(1);
    }
    __u16 u16int = (__u16)tmpint;
    return u16int;
}

/* function to add a UDP port range to a tproxy mapping */
void add_index(__u16 index, struct tproxy_port_mapping *mapping, struct tproxy_tuple *tuple){
    bool is_new = true;
    for (int x = 0; x < tuple->index_len ; x++){
        if(tuple->index_table[x] == index){
            is_new = false;
        }
    }
    if(is_new){
        tuple->index_table[tuple->index_len] = index;
        tuple->index_len +=1;
    }
    memcpy((void *)&tuple->port_mapping[index],(void *)mapping,sizeof(struct tproxy_port_mapping));
}

int main(int argc, char **argv){
    /* Make sure user enters correct number of agrguments */
    if (argc < 7) {
        fprintf(stderr, "Usage: %s <ip dest address or prefix> <prefix length> <low_port> <high_port> <tproxy_port> <protocol id>\n", argv[0]);
        exit(0);
    }
    /* create bpf_attr to store ifindex_ip_map */
    union bpf_attr if_map;
    /*path to pinned ifindex_ip_map*/
    const char *if_map_path = "/sys/fs/bpf/tc/globals/ifindex_ip_map";

    __u8 protocol = proto2u8(argv[6]);
    struct ifaddrs *addrs;

    /* call function to get a linked list of interface structs from system */
    if(getifaddrs(&addrs)==-1){
        printf("can't get addrs");
        return -1;
    }
    struct ifaddrs *address = addrs;
    /* open BPF ifindex_ip_map */
    memset(&if_map, 0, sizeof(if_map));
    /* set path name with location of map in filesystem */
    if_map.pathname = (uint64_t) if_map_path;
    if_map.bpf_fd = 0;
    if_map.file_flags = 0;
    /* make system call to get fd for map */
    int if_fd = syscall(__NR_bpf, BPF_OBJ_GET, &if_map, sizeof(if_map));
    if (if_fd == -1){
	    printf("BPF_OBJ_GET: %s \n", strerror(errno));
        exit(1);
    }
    if_map.map_fd = if_fd;
    int idx=0;
    /*
     * travers linked list of interfaces and for each non-loopback interface 
    *  populate the index into the map with ifindex as the key and ip address
    *  as the value
    */
    while(address){
        int family = address->ifa_addr->sa_family;
        if(family == AF_INET){
            if(strncmp(address->ifa_name,"lo",2)){
                get_index(address->ifa_name,&idx);	
                char ap[100];
                const int family_size = sizeof(struct sockaddr_in);
                getnameinfo(address->ifa_addr,family_size,ap,sizeof(ap),0,0,1);
                struct ifindex_ip4 ifip4 = {
                    htonl(ip2l(ap)),
                    idx,
                };          
                if_map.key = (uint64_t)&idx;
                if_map.flags = BPF_ANY;
                if_map.value = (uint64_t)&ifip4;
                int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &if_map, sizeof(if_map));
                if (ret){
	                printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
                    exit(1);
                }
            }
        }
        address = address->ifa_next;
    }
    close(if_fd);
    freeifaddrs(addrs);
    
    union bpf_attr map;
    const char *path = "/sys/fs/bpf/tc/globals/zt_tproxy_map";
    struct tproxy_key key = {htonl(ip2l(argv[1])), len2u16(argv[2]),protocol};
    struct tproxy_tuple orule; /* struct to hold an existing entry if it exists */
    /* open BPF zt_tproxy_map map */
    memset(&map, 0, sizeof(map));
    /* set path name with location of map in filesystem */
    map.pathname = (uint64_t) path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    /* make system call to get fd for map */
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1){
	    printf("BPF_OBJ_GET: %s \n", strerror(errno));
        exit(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&orule;
    /* make system call to lookup prefix/mask in map */
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    unsigned short index = htons(port2s(argv[3]));
    /* pupulate a struct for a port mapping */
    struct tproxy_port_mapping port_mapping = {
        htons(port2s(argv[3])),
        htons(port2s(argv[4])),
        htons(port2s(argv[5])),
        0x0100007f
    };
    /* 
     * Check result of lookup if not 0 then create a new entery
     * else edit an existing entry
     */
    if(protocol == IPPROTO_UDP){
        printf("Adding UDP mapping\n");
    }else if(protocol == IPPROTO_TCP){
        printf("Adding TCP mapping\n");
    }else{
        printf("Unsupported Protocol\n");
        exit(1);
    }
    if(lookup){
        /* create a new tproxy prefix entry and add port range to it */
        struct tproxy_tuple rule = {
                htonl(ip2l(argv[1])),
                0x0, /* zero source address future use */
                1,
                {index},
                {}
        };
        memcpy((void *)&rule.port_mapping[index],(void *)&port_mapping,sizeof(struct tproxy_port_mapping));
        map.value = (uint64_t)&rule;
        if(!rule.port_mapping[index].low_port){
            printf("memcpy failed");
            exit(1);
        }
    }else{
        /* modify existing prefix entry and add or modify existing port mapping entry  */
        printf("lookup success\n");
        add_index(index, &port_mapping, &orule);
        if(!(orule.port_mapping[index].low_port == index)){
            printf("memcpy failed");
            exit(1);
        }
    }
    map.flags = BPF_ANY;
    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
    if (result){
	printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
        exit(1);
    }
    close(fd);
}
