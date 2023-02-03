## Build from source
---
1. Distro 

    **Ubuntu 22.04 server** (kernel 5.15 or higher)

    ```bash
    sudo apt update
    sudo apt upgrade
    sudo reboot
    sudo apt install -y gcc clang libc6-dev-i386 libbpfcc-dev libbpf-dev
    ```          

    **Fedora 36** (kernel 6.0.5-200)

    ```bash
    sudo yum clean all
    sudo yum check-update
    sudo yum upgrade --refresh
    sudo yum install -y clang bcc-devel libbpf-devel iproute-devel iproute-tc glibc-devel.i686 git
    ```

1. Compile:

    ```bash      
    mkdir ~/repos
    cd repos
    git clone https://github.com/r-caamano/ebpf-tproxy-splicer.git 
    cd ebpf-tproxy-splicer/src
    clang -g -O2 -Wall -Wextra -target bpf -c -o tproxy_splicer.o tproxy_splicer.c
    clang -O2 -Wall -Wextra -o etables etables.c 
    ```  
    **Important Note:** 
    
    By default the tproxy map compiles with 100 entries allowed. If more is needed, then one needs to pass macro name `BPF_MAX_ENTRIES` with the desired number of entries as shown.
    ```bash
    clang -D BPF_MAX_ENTRIES=${{map_size}} -g -O2 -Wall -Wextra -target bpf -c -o files/objects/tproxy_splicer.o src/tproxy_splicer.c
    ``` 
