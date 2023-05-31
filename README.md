# ARCHIVED
  ## Project moved to https://github.com/r-caamano/zfw

                                   

## Introduction
--- 
**Notice: This repo has been hard forked into https://github.com/netfoundry/ebpf-tproxy-splicer for inclusion in 
CloudZiti edge-router builds as an optional interception mode. This repo will continue to be maintained for R&D.**
This is a project to develop an eBPF program that utilizes tc-bpf to act as a statefull ingress FW and to redirect 
ingress ipv4 udp/tcp flows toward dynamically created sockets that correspond to zero trust based services on OpenZiti
edge-routers. Those interested on how to setup an openziti development environment should visit 
https://github.com/openziti/ziti. 
Also note this is eBPF tc based so interception only occurs for traffic ingressing on the interface that the eBPF program
is attached to. To intercept packets generated locally by the router itself the eBPF program would need to be attached to
the loopback interface. The eBPF program also provides stateful inbound firewalling and only allows ssh, dhcp and arp
bypass by default. Initially the program will allow ssh to any address inbound however after the first tproxy mapping is
inserted by the map_update tool it will only allow ssh addressed to the IP address of the interface that tc has loaded the
eBPF program.  All other traffic must be configured as a service in an OpenZiti Controller which then informs the edge-router
which traffic flows to accept. The open ziti edge-router then uses the map_update user space app to insert rules to
allow traffic in on the interface tc is running on. For those interested in additional background on the project please visit: 
https://openziti.io/using-ebpf-tc-to-securely-mangle-packets-in-the-kernel-and-pass-them-to-my-secure-networking-application.  


## Build
---
[To build from source. Click here!](./BUILD.md)

## Management After Deployment
---

### Attaching to interface

```bash   
sudo map_update --set-tc-filter <interface name> --object-file=tproxy_splicer.o --direction=ingress
sudo map_update --set-tc-filter <interface name>--object-file=outbound_track.o --direction=egress //optional only if firewalling subtending devices see below
sudo ufw allow in on <interface name> to any
```

ebpf will now take over firewalling this interface and only allow ssh, dhcp and arp till ziti
services are provisioned as inbound intercepts via the map_udate app. Router will statefully allow responses to router
initiated sockets as well. tc commands above do not survive reboot so would need to be added to startup service / script.

A new addtion is firewall support for subtending devices for two interface scenarios i.e.
external and trusted.

    external inet <----> (ens33)[ebpf-router](ens37) <----> trusted clients

    with tproxy-splicer.o applied ingress on ens33 and oubound_track.o applied egress on ens33 the router will
    statefully track outbound udp and tcp connections on ens33 and allow the associated inbound traffic.  While
    running in this mode it does not make sense to add ziti tproxy rules and is meant for running as a traditional fw.
    As be for you can also create passthrough FW rules (set -t --tproxy-port to 0) which would also make sense in the mode for
    specific internet initiated traffic you might want to allow in.

    TCP:
        If the tcp connections close gracefully then the entries will remove upon connection closure. 
        if not then there is a 60 minute timeout that will remove the in active state if no traffic seen
        in either direction.

    UDP:
        State will remain active as long as packets tuples matching SRCIP/SPORT/DSTIP/DPORT are seen in
        either direction within 30 seconds.  If no packets seen in either dorection the state will expire.
        If an external packet enters the interface after expire the entry will be deleted.  if an egress
        packet fined a matching expired state it will return the state to active.

    In order to support this per interface rule awareness was added which allows each port range within a prefix
    to match a list of connected interfaces.  On a per interface basis you can decide to honor that list or not via
    a per-prefix-rules setting in the following manner via the map_update utility
    
    singly:
    ```
    sudo map_update -P <ifname>
    ```
    or 

    all interfaces:
    ```
    sudo map_update -P all
    ```

    In order to assign 1 to 3 interfaces to a rule you would use the new -N option in combination with the -I i.e.
    to associate the rule to end37 and lo:

    ```
    sudo map_update -I -c 172.16.31.0 -m 24 -l 443 -h 443 -t 44000 -p tcp -N ens37 -N lo
    ```

### Openziti Ingress

Testing with ziti-router after attaching. Build a ziti network first and create services as explained at [Host It Anywhere](https://docs.openziti.io/docs/learn/quickstarts/network/hosted/)

Grab the edge router binary `(>= v0.27.3)` at [open ziti](https://github.com/openziti/ziti/releases).

```bash
# Copy the user space map program to folder in $PATH i.e
sudo cp map_update /usr/bin

# In the router config.yml set tunnel mode to ebpf i.e.   
- binding: tunnel
  options:
    mode: tproxy:/path/to/map_update

# Run edge router command 
# Note: assumption - ziti-router and config.yml in PATH
sudo ziti-router run config.yml
```

### Detaching from interface:

```bash
sudo map_update --set-tc-filter <interface name>  --direction <ingress | egress> --disable
```

## Ebpf Map User Space Management
---
Example: Insert map entry to direct SIP traffic destined for 172.16.240.0/24

```bash
Usage: ./map_update -I <ip dest address or prefix> -m <prefix length> -l <low_port> -h <high_port> -t <tproxy_port> -p <protocol>

sudo ./map_update -I -c 172.16.240.0 -m 24 -l 5060 -h 5060 -t 58997 -p udp
```

As mentioned earlier if you add -r, --route as argument the program will add 172.16.240.0/24 to the "lo" interface if it
does not overlap with an external LAN interface subnet.

Example: Disable ssh from interface.

This will disable default ssh action to pass to ip of local interface and then fall through to rule check instead where a more specific rule could
be applied.  This is a per interface setting and can be set for all interfaces except loopback.

```bash
Usage: ./map_update -x <interface-name> | all

sudo sudo ./map_update -x ens33
```


Example: Insert map entry to with source filteing to only allow rule for ip source 10.1.1.1/32.

```bash
Usage: ./map_update -I -c <ip dest address or prefix> -m <dest prefix len> -o <origin address or prefix> -n <origin prefix len> -l <low_port> -h <high_port> -t <tproxy_port> -p <protocol>

sudo sudo ./map_update -I -c 172.16.240.0 -m 24 -o 10.1.1.1 -n 32  -p tcp -l 22 -h 22 -t 0
```

Example: Insert FW rule for local router tcp listen port 443 where local router's tc interface ip address is 10.1.1.1
with tproxy_port set to 0 signifying local connect rule

```bash
sudo ./map_update -I -c 10.1.1.1 -m 32 -l 443 -h 443 -t 0 -p tcp  
```

Example: Monitor ebpf trace messages

```
sudo map_update -v all
sudo cat /sys/kernel/debug/tracing/trace_pipe
  
<idle>-0       [007] dNs.. 167940.070727: bpf_trace_printk: ens33
<idle>-0       [007] dNs.. 167940.070728: bpf_trace_printk: source_ip = 0xA010101
<idle>-0       [007] dNs.. 167940.070728: bpf_trace_printk: dest_ip = 0xAC10F001
<idle>-0       [007] dNs.. 167940.070729: bpf_trace_printk: protocol_id = 17
<idle>-0       [007] dNs.. 167940.070729: bpf_trace_printk: tproxy_mapping->5060 to 59423

<idle>-0       [007] dNs.. 167954.255414: bpf_trace_printk: ens33
<idle>-0       [007] dNs.. 167954.255414: bpf_trace_printk: source_ip = 0xA010101
<idle>-0       [007] dNs.. 167954.255415: bpf_trace_printk: dest_ip = 0xAC10F001
<idle>-0       [007] dNs.. 167954.255415: bpf_trace_printk: protocol_id = 6
<idle>-0       [007] dNs.. 167954.255416: bpf_trace_printk: tproxy_mapping->22 to 39839

```
Example: Remove previous entry from map
```bash
Usage: ./map_update -D -c <ip dest address or prefix> -m <prefix len> -l <low_port> -p <protocol>

sudo ./map_update -D -c 172.16.240.0 -m 24 -l 5060 -p udp
```

Example: Remove all entries from map
```
Usage: ./map_update -F

sudo ./map_update -F
```

Example: List all rules in map
```
Usage: ./map_update -L

sudo ./map_update -L

target     proto    origin              destination               mapping:                                                   interface list
------     -----    ---------------     ------------------        --------------------------------------------------------- ----------------
TPROXY     tcp      0.0.0.0/0           10.0.0.16/28              dpts=22:22                TPROXY redirect 127.0.0.1:33381  [ens33,lo]
TPROXY     tcp      0.0.0.0/0           10.0.0.16/28              dpts=30000:40000          TPROXY redirect 127.0.0.1:33381  []
TPROXY     udp      0.0.0.0/0           172.20.1.0/24             dpts=5000:10000           TPROXY redirect 127.0.0.1:59394  []
TPROXY     tcp      0.0.0.0/0           172.16.1.0/24             dpts=22:22                TPROXY redirect 127.0.0.1:33381  []
TPROXY     tcp      0.0.0.0/0           172.16.1.0/24             dpts=30000:40000          TPROXY redirect 127.0.0.1:33381  []
PASSTHRU   udp      0.0.0.0/0           192.168.3.0/24            dpts=5:7                  PASSTHRU to 192.168.3.0/24       []
PASSTHRU   udp      10.1.1.1/32         192.168.100.100/32        dpts=50000:60000          PASSTHRU to 192.168.100.100/32   []
PASSTHRU   tcp      10.230.40.1/32      192.168.100.100/32        dpts=60000:65535          PASSTHRU to 192.168.100.100/32   []
TPROXY     udp      0.0.0.0/0           192.168.0.3/32            dpts=5000:10000           TPROXY redirect 127.0.0.1:59394  []
PASSTHRU   tcp      0.0.0.0/0           192.168.100.100/32        dpts=60000:65535          PASSTHRU to 192.168.100.100/32   []
```
Example: List rules in map for a given prefix and protocol
```bash
# Usage: ./map_update -L -c <ip dest address or prefix> -m <prefix len> -p <protocol>
  
sudo map_update -L -c 192.168.100.100 -m 32 -p udp
  
target     proto    origin           destination              mapping:                                                  interface list
------     -----    --------         ------------------       --------------------------------------------------------- ------------------    
PASSTHRU   udp      0.0.0.0/0        192.168.100.100/32       dpts=50000:60000 	      PASSTHRU to 192.168.100.100/32     []
``` 

Example: List rules in map for a given prefix
```bash
# Usage: ./map_update -L -c <ip dest address or prefix> -m <prefix len> -p <protocol>

sudo map_update -L -c 192.168.100.100 -m 32

target     proto    origin           destination              mapping:                                                  interface list
------     -----    --------         ------------------       --------------------------------------------------------- -------------------
PASSTHRU   udp      0.0.0.0/0        192.168.100.100/32       dpts=50000:60000 	      PASSTHRU to 192.168.100.100/32     []
PASSTHRU   tcp      0.0.0.0/0        192.168.100.100/32       dpts=60000:65535	      PASSTHRU to 192.168.100.100/32     []
```
Example: List all interface setting
```bash
Usage: ./map_update -L -E

sudo ./map_update -E

lo:
--------------------------
icmp echo               :1
verbose                 :0
ssh disable             :0
per interface           :0
tc ingress filter       :1
tc egress filter        :0
--------------------------

ens33:
--------------------------
icmp echo               :0
verbose                 :1
ssh disable             :1
per interface           :1
tc ingress filter       :1
tc egress filter        :1
--------------------------

ens37:
--------------------------
icmp echo               :0
verbose                 :0
ssh disable             :0
per interface           :0
tc ingress filter       :1
tc egress filter        :0
--------------------------
```

Example: Remove all tc-ebpf on router
```bash
Usage: ./map_update -Q,--disable-ebpf

sudo map_update --disable-ebpf
tc parent del : lo
tc parent del : ens33
tc parent del : ens37
removing /sys/fs/bpf/tc/globals/zt_tproxy_map
removing /sys/fs/bpf/tc/globals/diag_map
removing /sys/fs/bpf/tc/globals/ifindex_ip_map
removing /sys/fs/bpf/tc/globals/tuple_count_map
removing /sys/fs/bpf/tc/globals/prog_map
removing /sys/fs/bpf/tc/globals/udp_map
removing /sys/fs/bpf/tc//globals/matched_map
removing /sys/fs/bpf/tc/globals/tcp_map
```


## Additional Distro testing
---

Fedora 36 kernel 6.0.5-200

On fedora I found that NetworkManager interferes with eBPF socket redirection and can
be unpredictable so belowis what I changed to get it working consistently. Other less
intrusive methods not requiring removal of NM might also be possible.

```bash
sudo yum install network-scripts
sudo systemctl enable network
sudo yum remove NetworkManager

sudo vi /etc/sysconfig/network-scripts/ifcfg-eth0

# if eth0 will be dhcp then something like:
BOOTPROTO=dhcp
DEVICE=eth0
ONBOOT=yes

# or if static
BOOTPROTO=static
IPADDR=192.168.61.70
NETMASK=255.255.255.0
DEVICE=eth1
ONBOOT=yes
```

The following grub change is only necessary on systems that do not use ethX naming by
default like vmware. this changes fedora back to using ethX for interface naming network-scripts looks for this nomenclature and will fail DHCP otherwise

```bash 
sudo vi /etc/default/grub

# change:
GRUB_CMDLINE_LINUX="rd.lvm.lv=fedora_fedora/root rhgb quiet"

# to:
GRUB_CMDLINE_LINUX="rd.lvm.lv=fedora_fedora/root rhgb quiet net.ifnames=0 biosdevname=0"

# then:
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```
This updates dhcp script to dynamically update systemd-resolved on per interface resolver

```bash
sudo vi /usr/sbin/dhclient-script

# change:
if [ -n "${new_domain_name_servers}" ]; then
    for nameserver in ${new_domain_name_servers} ; do
        echo "nameserver ${nameserver}" >> "${rscf}"
    done

# to:   
if [ -n "${new_domain_name_servers}" ]; then
    for nameserver in ${new_domain_name_servers} ; do
        echo "nameserver ${nameserver}" >> "${rscf}"
        systemd-resolve --interface "${interface}" --set-dns "${nameserver}"
    done
````

## Analisys
---

                                                        DIAGRAMS

![Diagram](packet-flow.drawio.png) 



