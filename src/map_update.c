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
#include <arpa/inet.h>
#include <argp.h>
#include <linux/socket.h>

#define MAX_INDEX_ENTRIES 120 // MAX port ranges per prefix
#define MAX_TABLE_SIZE 65536 // PORT MApping table size

static bool add = false;
static bool delete = false;
static bool list = false;
static bool flush = false;
static bool lpt = false;
static bool hpt = false;
static bool tpt = false;
static bool pl = false;
static bool cd = false;
static bool prot = false;
static bool route = false;
static struct in_addr cidr;
static unsigned short plen;
static unsigned short low_port;
static unsigned short high_port;
static unsigned short tproxy_port;
static char *program_name;
static char *protocol_name;
static __u8 protocol;
static const char *path = "/sys/fs/bpf/tc/globals/zt_tproxy_map";
static char doc[] = "map_update -- ebpf mapping tool";
const char *argp_program_version = "0.1.0";

struct ifindex_ip4
{
    __u32 ipaddr;
    char ifname[IF_NAMESIZE];
};

struct tproxy_port_mapping
{
    __u16 low_port;
    __u16 high_port;
    __u16 tproxy_port;
};

struct tproxy_tuple
{
    __u16 index_len;
    __u16 index_table[MAX_INDEX_ENTRIES];
    struct tproxy_port_mapping port_mapping[MAX_TABLE_SIZE];
};

struct tproxy_key
{
    __u32 dst_ip;
    __u16 prefix_len;
    __u16 protocol;
};

/*function to add loopback binding for intercept IP prefixes that do not
 * currentlt exist as a subset of an external interface
 * */
void bind_prefix(struct in_addr *address, unsigned short mask){
    char *prefix = inet_ntoa(*address);
    char *cidr_block = malloc(19);
    sprintf(cidr_block, "%s/%u", prefix, mask);
    printf("binding intercept %s to loopback\n",cidr_block);
    pid_t pid;
    char *const parmList[] = {"/usr/bin/ip", "addr", "add", cidr_block, "dev", "lo", "scope", "host", NULL};
    if ((pid = fork()) == -1){
        perror("fork error: can't spawn bind");
    }else if (pid == 0) {
       execv("/usr/sbin/ip", parmList);
       printf("execv error: unknown error binding");
    }
    free(cidr_block);	
}

void unbind_prefix(struct in_addr *address, unsigned short mask){
    char *prefix = inet_ntoa(*address);
    char *cidr_block = malloc(19);
    sprintf(cidr_block, "%s/%u", prefix, mask);
    printf("unbinding intercept %s from loopback\n",cidr_block);
    pid_t pid;
    char *const parmList[] = {"/usr/sbin/ip", "addr", "delete", cidr_block, "dev", "lo", "scope", "host", NULL};
    if ((pid = fork()) == -1){
        perror("fork error: can't spawn unbind");
    }else if (pid == 0) {
       execv("/usr/sbin/ip", parmList);
       printf("execv error: unknown error unbinding");
    }
    free(cidr_block);
}

/*function to check if prefix is subset of interface subnet*/
int is_subset(__u32 network, __u32 netmask,__u32 prefix){
    if ((network & netmask) == (prefix & netmask)){
        return 0;
    }else{
        return -1;
    }   
}

/* function to get ifindex by interface name */
int get_index(char *name, int *idx)
{
    int fd, result;
    struct ifreq irequest;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd == -1)
        return errno;

    strncpy(irequest.ifr_name, name, IF_NAMESIZE);
    if (ioctl(fd, SIOCGIFINDEX, &irequest) == -1)
    {
        do
        {
            result = close(fd);
        } while (result == -1 && errno == EINTR);
        return errno = ENOENT;
    }

    *idx = irequest.ifr_ifindex;

    return 0;
}

/* convert string port to unsigned short int */
unsigned short port2s(char *port)
{
    char *endPtr;
    int32_t tmpint = strtol(port, &endPtr, 10);
    if ((tmpint < 0) || (tmpint > 65535) || (!(*(endPtr) == '\0')))
    {
        printf("Invalid Port: %s\n", port);
        exit(1);
    }
    unsigned short usint = (unsigned short)tmpint;
    return usint;
}

/* convert string protocol to __u8 */
__u8 proto2u8(char *protocol)
{
    char *endPtr;
    int32_t tmpint = strtol(protocol, &endPtr, 10);
    if ((tmpint <= 0) || (tmpint > 255) || (!(*(endPtr) == '\0')))
    {
        printf("Invalid Protocol: %s\n", protocol);
        exit(1);
    }
    __u8 usint = (__u8)tmpint;
    return usint;
}

/*convert integer ip to dotted decimal string*/
char *nitoa(uint32_t address)
{
    char *ipaddr = malloc(16);
    int b0 = (address & 0xff000000) >> 24;
    int b1 = (address & 0xff0000) >> 16;
    int b2 = (address & 0xff00) >> 8;
    int b3 = address & 0xff;
    sprintf(ipaddr, "%d.%d.%d.%d", b0, b1, b2, b3);
    return ipaddr;
}

/* convert prefix string to __u16 */
__u16 len2u16(char *len)
{
    char *endPtr;
    int32_t tmpint = strtol(len, &endPtr, 10);
    if ((tmpint <= 0) || (tmpint > 32) || (!(*(endPtr) == '\0')))
    {
        printf("Invalid Prefix Length: %s\n", len);
        exit(1);
    }
    __u16 u16int = (__u16)tmpint;
    return u16int;
}

/* function to add a UDP or TCP port range to a tproxy mapping */
void add_index(__u16 index, struct tproxy_port_mapping *mapping, struct tproxy_tuple *tuple)
{
    bool is_new = true;
    for (int x = 0; x < tuple->index_len; x++)
    {
        if (tuple->index_table[x] == index)
        {
            is_new = false;
        }
    }
    if (is_new)
    {
        tuple->index_table[tuple->index_len] = index;
        tuple->index_len += 1;
    }
    memcpy((void *)&tuple->port_mapping[index], (void *)mapping, sizeof(struct tproxy_port_mapping));
}

void remove_index(__u16 index, struct tproxy_tuple *tuple)
{
    bool found = false;
    int x = 0;
    for (; x < tuple->index_len; x++)
    {
        if (tuple->index_table[x] == index)
        {
            found = true;
            break;
        }
    }
    if (found)
    {
        for (; x < tuple->index_len - 1; x++)
        {
            tuple->index_table[x] = tuple->index_table[x + 1];
        }
        tuple->index_len -= 1;
        memset((void *)&tuple->port_mapping[index], 0, sizeof(struct tproxy_port_mapping));
        if (tuple->port_mapping[index].low_port == index)
        {
            printf("mapping[%d].low_port = %d\n", index, ntohs(tuple->port_mapping[index].low_port));
        }
        else
        {
            printf("mapping[%d] removed\n", ntohs(index));
        }
    }
    else
    {
        printf("mapping[%d] does not exist\n", ntohs(index));
    }
}

void print_rule(struct tproxy_key *key, struct tproxy_tuple *tuple, int *rule_count)
{
    char *proto;
    if (key->protocol == IPPROTO_UDP)
    {
        proto = "udp";
    }
    else if (key->protocol == IPPROTO_TCP)
    {
        proto = "tcp";
    }
    else
    {
        proto = "unknown";
    }
    char *prefix = nitoa(ntohl(key->dst_ip));
    char *cidr_block = malloc(19);
    sprintf(cidr_block, "%s/%d", prefix, key->prefix_len);
    char *dpts = malloc(17);

    int x = 0;
    for (; x < tuple->index_len; x++)
    {
        sprintf(dpts, "dpts=%d:%d", ntohs(tuple->port_mapping[tuple->index_table[x]].low_port),
            ntohs(tuple->port_mapping[tuple->index_table[x]].high_port));
        if(ntohs(tuple->port_mapping[tuple->index_table[x]].tproxy_port) > 0){
            printf("%-11s\t%-3s\tanywhere\t%-32s%-17s\tTPROXY redirect 127.0.0.1:%d\n", "TPROXY", proto, cidr_block,
               dpts, ntohs(tuple->port_mapping[tuple->index_table[x]].tproxy_port));
        }else{
            printf("%-11s\t%-3s\tanywhere\t%-32s%-17s\t%s to %s\n","PASSTHRU", proto, cidr_block,
               dpts, "PASSTHRU",cidr_block);
        }
	*rule_count += 1;
    }
    free(dpts);
    free(cidr_block);
    free(prefix);
}

void usage(char *message)
{
    fprintf(stderr, "%s : %s\n", program_name, message);
    fprintf(stderr, "Usage: map_update -I -c <ip dest address or prefix> -m <prefix length> -l <low_port> -h <high_port> -t <tproxy_port> -p <protocol id>\n");
    fprintf(stderr, "       map_update -D -c <ip dest address or prefix> -m <prefix length> -l <low_port> -p <protocol id>\n");
    fprintf(stderr, "       map_update -L -c <ip dest address or prefix> -m <prefix length> -p <protocol id>\n");
    fprintf(stderr, "       map_update -L -c <ip dest address or prefix> -m <prefix length>\n");
    fprintf(stderr, "       map_update -F\n");
    fprintf(stderr, "       map_update -L\n");
    fprintf(stderr, "       map_update -V\n");
    fprintf(stderr, "       map_update --help\n");
    exit(1);
}

bool interface_map(){
    /* create bpf_attr to store ifindex_ip_map */
    union bpf_attr if_map;
    /*path to pinned ifindex_ip_map*/
    const char *if_map_path = "/sys/fs/bpf/tc/globals/ifindex_ip_map";
    struct ifaddrs *addrs;

    /* call function to get a linked list of interface structs from system */
    if (getifaddrs(&addrs) == -1)
    {
        printf("can't get addrs");
        exit(1);
    }
    struct ifaddrs *address = addrs;
    /* open BPF ifindex_ip_map */
    memset(&if_map, 0, sizeof(if_map));
    /* set path name with location of map in filesystem */
    if_map.pathname = (uint64_t)if_map_path;
    if_map.bpf_fd = 0;
    if_map.file_flags = 0;
    /* make system call to get fd for map */
    int if_fd = syscall(__NR_bpf, BPF_OBJ_GET, &if_map, sizeof(if_map));
    if (if_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        exit(1);
    }
    if_map.map_fd = if_fd;
    int idx = 0;
    /*
     * traverse linked list of interfaces and for each non-loopback interface
     *  populate the index into the map with ifindex as the key and ip address
     *  as the value
     */
    int net_count = 0;
    struct sockaddr_in *ipaddr;
    in_addr_t ifip;
    int ipcheck = 0;
    bool create_route = true;
    while (address)
    {
        int family = address->ifa_addr->sa_family;
        if (family == AF_INET)
        {
            get_index(address->ifa_name, &idx);
            if (strncmp(address->ifa_name, "lo", 2))
            {
                ipaddr = (struct sockaddr_in *)address->ifa_addr;
                ifip = ipaddr->sin_addr.s_addr;
                struct sockaddr_in *network_mask = (struct sockaddr_in *)address->ifa_netmask;
                __u32 netmask = ntohl(network_mask->sin_addr.s_addr);
                ipcheck = is_subset(ntohl(ifip) ,netmask,ntohl(cidr.s_addr));
                if(!ipcheck){
                    create_route = false;
                }
            }else{
               ifip = 0x0100007f;
            }
            struct ifindex_ip4 ifip4 = {
                ifip,
                {0}};
            sprintf(ifip4.ifname, "%s", address->ifa_name);
            if_map.key = (uint64_t)&idx;
            if_map.flags = BPF_ANY;
            if_map.value = (uint64_t)&ifip4;
            int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &if_map, sizeof(if_map));
            if (ret){
                printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
                close(if_fd);
                exit(1);
            }
        }
        net_count++;
        address = address->ifa_next;
    }
    close(if_fd);
    freeifaddrs(addrs);
    return create_route;
}

void map_insert()
{
    bool route_insert = interface_map();
    union bpf_attr map;
    struct tproxy_key key = {cidr.s_addr, plen, protocol};
    struct tproxy_tuple orule; /* struct to hold an existing entry if it exists */
    /* open BPF zt_tproxy_map map */
    memset(&map, 0, sizeof(map));
    /* set path name with location of map in filesystem */
    map.pathname = (uint64_t)path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    /* make system call to get fd for map */
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        exit(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&orule;
    /* make system call to lookup prefix/mask in map */
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    unsigned short index = htons(low_port);
    /* pupulate a struct for a port mapping */
    struct tproxy_port_mapping port_mapping = {
        htons(low_port),
        htons(high_port),
        htons(tproxy_port)
        };
    /*
     * Check result of lookup if not 0 then create a new entery
     * else edit an existing entry
     */
    if (protocol == IPPROTO_UDP)
    {
        printf("Adding UDP mapping\n");
    }
    else if (protocol == IPPROTO_TCP)
    {
        printf("Adding TCP mapping\n");
    }
    else
    {
        printf("Unsupported Protocol\n");
        close(fd);
        exit(1);
    }
    if (lookup)
    {
        /* create a new tproxy prefix entry and add port range to it */
        struct tproxy_tuple rule = {
            1,
            {index},
            {}};
        memcpy((void *)&rule.port_mapping[index], (void *)&port_mapping, sizeof(struct tproxy_port_mapping));
        map.value = (uint64_t)&rule;
        if (!rule.port_mapping[index].low_port)
        {
            printf("memcpy failed");
            close(fd);
            exit(1);
        }
	    if(route && route_insert){
           bind_prefix(&cidr, plen);
        }
    }
    else
    {
        /* modify existing prefix entry and add or modify existing port mapping entry  */
        printf("lookup success\n");
        add_index(index, &port_mapping, &orule);
        if (!(orule.port_mapping[index].low_port == index))
        {
            printf("memcpy failed");
            close(fd);
            exit(1);
        }
    }
    map.flags = BPF_ANY;
    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
        exit(1);
    }
    close(fd);
}

void map_delete_key(struct tproxy_key key)
{
    char *prefix = nitoa(ntohl(key.dst_ip));
    inet_aton(prefix, &cidr);
    plen = key.prefix_len;
    free(prefix);
    bool route_delete = interface_map();
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        exit(1);
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
    }
    else
    {
        if(route && route_delete){
            unbind_prefix(&cidr,plen);
        }
    }
    close(fd);
}

void map_delete()
{
    bool route_delete = interface_map();
    union bpf_attr map;
    struct tproxy_key key = {cidr.s_addr, plen, protocol};
    struct tproxy_tuple orule;
    // Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        exit(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&orule;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    unsigned short index = htons(low_port);
    if (lookup)
    {
        printf("MAP_DELETE_ELEM: %s\n", strerror(errno));

        exit(1);
    }
    else
    {
        printf("lookup success\n");
        if (protocol == IPPROTO_UDP)
        {
            printf("Attempting to remove UDP mapping\n");
        }
        else if (protocol == IPPROTO_TCP)
        {
            printf("Attempting to remove TCP mapping\n");
        }
        else
        {
            printf("Unsupported Protocol\n");
            exit(1);
        }
        remove_index(index, &orule);
        if (orule.index_len == 0)
        {
            memset(&map, 0, sizeof(map));
            map.pathname = (uint64_t)path;
            map.bpf_fd = 0;
            int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
            if (fd == -1)
            {
                printf("BPF_OBJ_GET: %s\n", strerror(errno));
                exit(1);
            }
            // delete element with specified key
            map.map_fd = fd;
            map.key = (uint64_t)&key;
            int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
            if (result)
            {
                printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
                close(fd);
                exit(1);
            }
            else
            {
                printf("Last Element: Hash Entry Deleted\n");
                if(route && route_delete){
		            unbind_prefix(&cidr,plen);
                }
                exit(0);
            }
        }
        map.value = (uint64_t)&orule;
        map.flags = BPF_ANY;
        /*Flush Map changes to system -- Needed when removing an entry that is not the last range associated
         *with a prefix/protocol pair*/
        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
        if (result)
        {
            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
            close(fd);
            exit(1);
        }
    }
    close(fd);
}

void map_flush()
{
    union bpf_attr map;
    struct tproxy_key *key = NULL;
    struct tproxy_key current_key;
    struct tproxy_tuple orule;
    // Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        exit(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&orule;
    int ret = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1)
        {
            break;
        }
        map.key = map.next_key;
        current_key = *(struct tproxy_key *)map.key;
        map_delete_key(current_key);
    }
    close(fd);
}

void map_list()
{
    union bpf_attr map;
    struct tproxy_key key = {cidr.s_addr, plen, protocol};
    struct tproxy_tuple orule;
    // Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        exit(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&orule;
    int lookup = 0;
    printf("%-8s\t%-3s\t%-8s\t%-32s%-17s\t\t\t\n","target","proto","source","destination","mapping:");
    printf("--------\t-----\t--------\t------------------\t\t-------------------------------------------------------\n");
    int rule_count = 0;
    if (prot)
    {
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
        if (!lookup)
        {
            print_rule((struct tproxy_key *)map.key, &orule, &rule_count);
            printf("Rule Count: %d\n", rule_count);
        }
    }
    else
    {
        int vprot[] = {IPPROTO_UDP, IPPROTO_TCP};
        int x = 0;
        for (; x < 2; x++)
        {
            rule_count = 0;
            struct tproxy_key vkey = {cidr.s_addr, plen, vprot[x]};
            map.key = (uint64_t)&vkey;
            lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
            if (!lookup)
            {
                print_rule((struct tproxy_key *)map.key, &orule, &rule_count);
                printf("Rule Count: %d\n", rule_count);
            }
        }
    }

    close(fd);
}

void map_list_all()
{
    union bpf_attr map;
    struct tproxy_key *key = NULL;
    struct tproxy_key current_key;
    struct tproxy_tuple orule;
    // Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        exit(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&orule;
    int lookup = 0;
    int ret = 0;
    printf("%-8s\t%-3s\t%-8s\t%-32s%-17s\t\t\t\n","target","proto","source","destination","mapping:");
    printf("--------\t-----\t--------\t------------------\t\t-------------------------------------------------------\n");
    int rule_count=0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        // printf("ret=%d\n",ret);
        if (ret == -1)
        {
            printf("Rule Count: %d\n",rule_count);
            break;
        }
        map.key = map.next_key;
        current_key = *(struct tproxy_key *)map.key;
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
        if (!lookup)
        {
            print_rule(&current_key, &orule, &rule_count);
        }
        else
        {
            printf("Not Found\n");
        }
        map.key = (uint64_t)&current_key;
    }
    close(fd);
}

// commandline parser options
static struct argp_option options[] = {
    {"insert", 'I', NULL, 0, "Insert map rule", 0},
    {"delete", 'D', NULL, 0, "Delete map rule", 0},
    {"list", 'L', NULL, 0, "List map rules", 0},
    {"flush", 'F', NULL, 0, "Flush all map rules", 0},
    {"cidr-block", 'c', "", 0, "Set ip prefix i.e. 192.168.1.0 <mandatory for insert/delete/list>", 0},
    {"prefix-len", 'm', "", 0, "Set prefix length (1-32) <mandatory for insert/delete/list >", 0},
    {"low-port", 'l', "", 0, "Set low-port value (1-65535)> <mandatory insert/delete>", 0},
    {"high-port", 'h', "", 0, "Set high-port value (1-65535)> <mandatory for insert>", 0},
    {"tproxy-port", 't', "", 0, "Set high-port value (0-65535)> <mandatory for insert>", 0},
    {"protocol", 'p', "", 0, "Set protocol (tcp or udp) <mandatory insert/delete>", 0},
    {"route", 'r', NULL, 0, "Add or Delete static ip/prefix for intercept dest to lo interface <optional insert/delete>", 0},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    program_name = state->name;
    switch (key)
    {
    case 'I':
        add = true;
        break;
    case 'D':
        delete = true;
        break;
    case 'L':
        list = true;
        break;
    case 'F':
        flush = true;
        break;
    case 'c':
        if (!inet_aton(arg, &cidr))
        {
            fprintf(stderr, "Invalid IP Address for arg -p, --protocol: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        cd = true;
        break;
    case 'm':
        plen = len2u16(arg);
        pl = true;
        break;
    case 'l':
        low_port = port2s(arg);
        lpt = true;
        break;
    case 'h':
        high_port = port2s(arg);
        hpt = true;
        break;
    case 't':
        tproxy_port = port2s(arg);
        tpt = true;
        break;
    case 'p':
        if ((strcmp("tcp", arg) == 0) || (strcmp("TCP", arg) == 0))
        {
            protocol = IPPROTO_TCP;
        }
        else if ((strcmp("udp", arg) == 0) || (strcmp("UDP", arg) == 0))
        {
            protocol = IPPROTO_UDP;
        }
        else
        {
            fprintf(stderr, "Invalid protocol for arg -p,--protocol <tcp|udp>\n");
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        protocol_name = arg;
        prot = true;
        break;
    case 'r':
        route = true;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

struct argp argp = {options, parse_opt, 0, doc, 0, 0, 0};

int main(int argc, char **argv)
{
    argp_parse(&argp, argc, argv, 0, 0, 0);

    if (add)
    {
        if (!cd)
        {
            usage("Missing argument -c, --cider-block");
        }
        else if (!pl)
        {
            usage("Missing argument -m, --prefix-len");
        }
        else if (!lpt)
        {
            usage("Missing argument -l, --low-port");
        }
        else if (!hpt)
        {
            usage("Missing argument -h, --high-port");
        }
        else if (!tpt)
        {
            usage("Missing argument -t, --tproxy-port");
        }
        else if (!prot)
        {
            usage("Missing argument -p, --protocol");
        }
        else
        {
            map_insert();
        }
    }
    else if (delete)
    {
        if (!cd)
        {
            usage("Missing argument -c, --cider-block");
        }
        else if (!pl)
        {
            usage("Missing argument -m, --prefix-len");
        }
        else if (!lpt)
        {
            usage("Missing argument -l, --low-port");
        }
        else if (!prot)
        {
            usage("Missing argument -p, --protocol");
        }
        else
        {
            map_delete();
        }
    }
    else if(flush)
    {
        map_flush();
    }
    else if (list)
    {
        if (!cd && !pl)
        {
            map_list_all();
        }
        else if (!cd)
        {
            usage("Missing argument -c, --cider-block");
        }
        else if (!pl)
        {
            usage("Missing argument -m, --prefix-len");
        }
        else
        {
            map_list();
        }
    }
    else
    {
        usage("No arguments specified");
    }
}
