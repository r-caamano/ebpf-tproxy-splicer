# Intro:

This is a project to develop an eBPF program that utilizes tc-bpf to act as a statefull ingress FW and to redirect 
ingress ipv4 udp/tcp flows toward dynamically created sockets that correspond to zero trust based services on OpenZiti
edge-routers. Note: For this to work the ziti-router code had to be modified to not insert ip tables tproxy rules for
the services defined and to instead call map_update for tproxy redirection. example edge code at 
https://github.com/r-caamano/edge/tree/v0.26.11 assumes map_update binary is in the ziti-router's search path and the
eBPF program is loaded via linux tc command per instructions below. Those interested on how to setup an openziti
development environment should visit https://github.com/openziti/ziti. Also note this is eBPF tc based so interception
only occurs for traffic ingressing on the interface that the eBPF program is attached to. To intercept packets generated
locally by the router itself the eBPF program would need to be attached to the loopback interface. The eBPF program also
provides stateful inbound firewalling and only allows ssh, dhcp and arp bypass by default. Initially the program will
allow ssh to any address inbound however after the first tproxy mapping is inserted by the map_update tool it will only
allow ssh addressed to the IP address of the interface that tc has loaded the eBPF program.  All other traffic must be
configured as a service in an OpenZiti Controller which then informs the edge-router which traffic flows to accept. The
open ziti edge-router then uses the map_update user space app to insert rules to allow traffic in on the interface tc is
running on. For those interested in additional background on the project please visit: 
https://openziti.io/using-ebpf-tc-to-securely-mangle-packets-in-the-kernel-and-pass-them-to-my-secure-networking-application.

Note: While this program was written with OpenZiti edge-routers in mind it can be used to redirect incoming udp/tcp
traffic to any application with a listening socket bound to the loopback IP. If you are testing without OpenZiti the
Destination IP or Subnet must be bound to an existing interface on the system in order to intercept traffic. For
external interface IP(s) this is taken care of.  If you want to intercept another IP that falls into the same range as
the physical interface then you would need to add it as a secondary ip.  Subnets won't work for binding on the external
interface it needs to be a host address. Subnets will work on the loopback however. OpenZiti binds intercept 
addresses/prefixes to the "lo" interface i.e. sudo ip addr add 172.20.1.0/24 dev lo scope host. I've added similar
functionality with the -r,--route optional argument. For safety reasons this will only add a IP/Prefix to the loopback
if the destination ip/prefix does not fall within the subnet range of an external interface.

prereqs: **Ubuntu 22.04 server** (kernel 5.15 or higher)

  ```
  sudo apt update
  sudo apt upgrade
  sudo reboot
  sudo apt install -y gcc clang libc6-dev-i386 libbpfcc-dev libbpf-dev
  ```          

compile:

  ```      
  mkdir ~/repos
  cd repos
  git clone https://github.com/r-caamano/ebpf-tproxy-splicer.git 
  cd ebpf-tproxy-splicer/src
  clang -g -O2 -Wall -Wextra -target bpf -c -o tproxy_splicer.o tproxy_splicer.c
  clang -O2 -Wall -Wextra -o map_update map_update.c 
  ```     

attach:

  ```   
  sudo tc qdisc add dev <interface name>  clsact
  sudo tc filter add dev <interface name> ingress bpf da obj tproxy_splicer.o sec action
  sudo ufw allow in on <interface name> to any
  ```

ebpf will now take over firewalling this interface and only allow ssh, dhcp and arp till ziti
services are provisioned as inbound intercepts via the map_udate app. Router will statefully allow responses to router
initiated sockets as well. tc commands above do not survive reboot so would need to be added to startup service / script.

Test with ziti-router after attaching -
if you want to run with ziti-router build a ziti network and create services as explained at https://openziti.github.io
select "Host It Anywhere"

The router you run with ebpf should be on a separate VM and you will want to build the binary as described in the README.md at
https://github.com/r-caamano/edge/tree/v0.26.11

Copy the user space map program to folder in $PATH i.e
sudo cp map_update /usr/bin

In the router config.yml set tunnel mode to ebpf i.e.

  ```     
  - binding: tunnel
    options:
       mode: ebpf
       resolver: udp://192.168.1.1:53
       dnsSvcIpRange: 100.64.0.1/10
  ```

You can then run it with the following command "sudo ziti-router run config.yml" assuming ziti-router and config.yml are
in your PATH.

detach:

  ```
  sudo tc qdisc del dev <interface name>  clsact
  ```

Example: Insert map entry to direct SIP traffic destined for 172.16.240.0/24


Usage: ./map_update -I `<ip dest address or prefix>` -m `<prefix length>` -l `<low_port>` -h `<high_port>` -t `<tproxy_port>` -p `<protocol>`

  ```
  sudo ./map_update -I -c 172.16.240.0 -m 24 -l 5060 -h 5060 -t 58997 -p udp
  ```

As mentioned earlier if you add -r, --route as argument the program will add 172.16.240.0/24 to the "lo" interface if it
does not overlap with an external LAN interface subnet.


Example: Insert FW rule for local router tcp listen port 443 where local router's tc interface ip address is 10.1.1.1
with tproxy_port set to 0 signifying local connect rule

  ```
  sudo ./map_update -I -c 10.1.1.1 -m 32 -l 443 -h 443 -t 0 -p tcp  
  ```

Example: Monitor ebpf trace messages

  ```
  sudo cat /sys/kernel/debug/tracing/trace_pipe
  ```         
````
<idle>-0       [000] dNs3. 23100.582441: bpf_trace_printk: tproxy_mapping->5060 to 33626
<idle>-0       [000] d.s3. 23101.365172: bpf_trace_printk: ens33 : protocol_id=17
<idle>-0       [000] dNs3. 23101.365205: bpf_trace_printk: tproxy_mapping->5060 to 33626
<idle>-0       [000] d.s3. 23101.725048: bpf_trace_printk: ens33 : protocol_id=17
<idle>-0       [000] dNs3. 23101.725086: bpf_trace_printk: tproxy_mapping->5060 to 33626
<idle>-0       [000] d.s3. 23102.389608: bpf_trace_printk: ens33 : protocol_id=17
<idle>-0       [000] dNs3. 23102.389644: bpf_trace_printk: tproxy_mapping->5060 to 33626
<idle>-0       [000] d.s3. 23102.989964: bpf_trace_printk: ens33 : protocol_id=17
<idle>-0       [000] dNs3. 23102.989997: bpf_trace_printk: tproxy_mapping->5060 to 33626
<idle>-0       [000] d.s3. 23138.910079: bpf_trace_printk: ens33 : protocol_id=6
<idle>-0       [000] dNs3. 23138.910113: bpf_trace_printk: tproxy_mapping->22 to 39643
<idle>-0       [000] d.s3. 23153.458326: bpf_trace_printk: ens33 : protocol_id=6
<idle>-0       [000] dNs3. 23153.458359: bpf_trace_printk: tproxy_mapping->22 to 39643
````
Example: Remove previous entry from map

Usage: ./map_update -D -c `<ip dest address or prefix>` -m `<prefix len>` -l `<low_port>` -p `<protocol>`

  ```
  sudo ./map_update -D -c 172.16.240.0 -m 24 -l 5060 -p udp [-r]
  ```

Example: Remove all entries from map

Usage: ./map_update -F [-r]

  ```
  sudo ./map_update -F
  ```

Example: List all rules in map

Usage: ./map_update -L

  ```
  sudo ./map_update -L
  ```
  ```
  target     proto    source          destination               mapping:
  ------     -----    --------        ------------------        ---------------------------------------------------------
  TPROXY     tcp      anywhere        10.0.0.16/28              dpts=22:22                TPROXY redirect 127.0.0.1:33381
  TPROXY     tcp      anywhere        10.0.0.16/28              dpts=30000:40000          TPROXY redirect 127.0.0.1:33381
  TPROXY     udp      anywhere        172.20.1.0/24             dpts=5000:10000           TPROXY redirect 127.0.0.1:59394
  TPROXY     tcp      anywhere        172.16.1.0/24             dpts=22:22                TPROXY redirect 127.0.0.1:33381
  TPROXY     tcp      anywhere        172.16.1.0/24             dpts=30000:40000          TPROXY redirect 127.0.0.1:33381
  PASSTHRU   udp      anywhere        192.168.3.0/24            dpts=5:7                  PASSTHRU to 192.168.3.0/24 
  PASSTHRU   udp      anywhere        192.168.100.100/32        dpts=50000:60000          PASSTHRU to 192.168.100.100/32
  PASSTHRU   tcp      anywhere        192.168.100.100/32        dpts=60000:65535          PASSTHRU to 192.168.100.100/32
  TPROXY     udp      anywhere        192.168.0.3/32            dpts=5000:10000           TPROXY redirect 127.0.0.1:59394
  PASSTHRU   tcp      anywhere        192.168.100.100/32        dpts=60000:65535          PASSTHRU to 192.168.100.100/32
  ```
Example: List rules in map for a given prefix and protocol

Usage: ./map_update -L -c `<ip dest address or prefix>` -m `<prefix len>` -p `<protocol>`

  ```     
  sudo map_update -L -c 192.168.100.100 -m 32 -p udp
  ```
  ```     
  target     proto    source           destination              mapping:
  ------     -----    --------         ------------------       ---------------------------------------------------------
  PASSTHRU   udp      anywhere         192.168.100.100/32       dpts=50000:60000 	      PASSTHRU to 192.168.100.100/32
  ``` 
Example: List rules in map for a given prefix


Usage: ./map_update -L -c `<ip dest address or prefix>` -m `<prefix len>` -p `<protocol>`

  ```
  sudo map_update -L -c 192.168.100.100 -m 32
  ```
  ```     
  target     proto    source           destination              mapping:
  ------     -----    --------         ------------------       ---------------------------------------------------------
  PASSTHRU   udp      anywhere         192.168.100.100/32       dpts=50000:60000 	      PASSTHRU to 192.168.100.100/32
  PASSTHRU   tcp      anywhere         192.168.100.100/32       dpts=60000:65535	      PASSTHRU to 192.168.100.100/32
  ```

Additional Distro testing:

Fedora 36 kernel 6.0.5-200

  ```
  sudo yum clean all
  sudo yum check-update
  sudo yum upgrade --refresh
  sudo yum install -y clang bcc-devel libbpf-devel iproute-devel iproute-tc glibc-devel.i686 git
  ```

On fedora I found that NetworkManager interferes with eBPF socket redirection and can
be unpredictable so belowis what I changed to get it working consistently. Other less
intrusive methods not requiring removal of NM might also be possible.

  ```
  sudo yum install network-scripts
  sudo systemctl enable network
  sudo yum remove NetworkManager
  ```

  ```
  sudo vi /etc/sysconfig/network-scripts/ifcfg-eth0
  ```

if eth0 will be dhcp then something like:
```
BOOTPROTO=dhcp
DEVICE=eth0
ONBOOT=yes
```

or if static

 ```
 BOOTPROTO=static
 IPADDR=192.168.61.70
 NETMASK=255.255.255.0
 DEVICE=eth1
 ONBOOT=yes
 ```

The following grub change is only necessary on systems that do not use ethX naming by
default like vmware. this changes fedora back to using ethX for interface naming network-scripts looks
for this nomenclature and will fail DHCP otherwise

  ``` 
  sudo vi /etc/default/grub
  ```

change:
  ```
  GRUB_CMDLINE_LINUX="rd.lvm.lv=fedora_fedora/root rhgb quiet"
  ```
to:
  ```
  GRUB_CMDLINE_LINUX="rd.lvm.lv=fedora_fedora/root rhgb quiet net.ifnames=0 biosdevname=0"
  ```
then:
  ```
  sudo grub2-mkconfig -o /boot/grub2/grub.cfg
  ```
This updates dhcp script to dynamically update systemd-resolved on per interface resolver

  ```
  sudo vi /usr/sbin/dhclient-script
  ```
change:
````
    if [ -n "${new_domain_name_servers}" ]; then
       for nameserver in ${new_domain_name_servers} ; do
           echo "nameserver ${nameserver}" >> "${rscf}"
       done
````
to:

````    
    if [ -n "${new_domain_name_servers}" ]; then
       for nameserver in ${new_domain_name_servers} ; do
           echo "nameserver ${nameserver}" >> "${rscf}"
           systemd-resolve --interface "${interface}" --set-dns "${nameserver}"
       done
````

Analisys:

                                                        DIAGRAMS

![Diagram](packet-flow.drawio.png) 
