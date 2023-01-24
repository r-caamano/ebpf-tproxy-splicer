#!/bin/bash
# get local ip for lanIf
# First check if the edge router config file exists
router_config_file=/opt/netfoundry/ziti/ziti-router/config.yml
if [ -f "$router_config_file" ]; then
    # Look up the value of lanIf
    MYIF=$(cat /opt/netfoundry/ziti/ziti-router/config.yml |yq '.listeners[] | select(.binding == "tunnel").options.lanIf')
    # Check if lanIf is not empty
    if [ "$MYIF" ]; then
        # Then get IP
        MYIP=$(/sbin/ip add show "${MYIF}"|awk '$1=="inet" {print $2;}'|awk -v FS='/' '{print $1}')
        # check if the ebpf is attached 
        ATTACHED=`eval tc filter show dev $MYIF ingress`
        if [ $(echo  $ATTACHED | grep -w -c tproxy_splicer.o) == 1 ]; then
            echo "Found ebpf program tproxy_splicer and will re-add it to $MYIF now"
            tc qdisc del dev $MYIF clsact
            tc qdisc add dev $MYIF clsact
            tc filter add dev $MYIF ingress bpf da obj /opt/netfoundry/ebpf/objects/tproxy_splicer.o sec action
            ufw allow in on $MYIF to any
        else
            echo "Not Found ebpf program tproxy_splicer and will add it to $MYIF now"
            tc qdisc add dev $MYIF clsact
            tc filter add dev $MYIF ingress bpf da obj /opt/netfoundry/ebpf/objects/tproxy_splicer.o sec action
            ufw allow in on $MYIF to any
        fi
        # Save full path of map update into a variable
        map_update=/opt/netfoundry/ebpf/objects/map_update
        # Get Ziti Fabric Port/Transport
        ZITI_FPORT=$(cat /opt/netfoundry/ziti/ziti-router/config.yml |yq .ctrl.endpoint |awk -v FS=':' '{print $3}')
        ZITI_FTRANSPORT=$(cat /opt/netfoundry/ziti/ziti-router/config.yml |yq .ctrl.endpoint |awk -v FS=':' '{print $1}')
        if [ "$ZITI_FTRANSPORT" == "tls" ]; then
            $map_update -I -c $MYIP -m 32 -l $ZITI_FPORT -h $ZITI_FPORT -t 0 -p tcp
        fi
        # Get Ziti Client Port/Transport
        ZITI_CPORT=$(cat /opt/netfoundry/ziti/ziti-router/config.yml |yq '.listeners[] | select(.binding == "edge").address' |awk -v FS=':' '{print $3}')
        ZITI_CTRANSPORT=$(cat /opt/netfoundry/ziti/ziti-router/config.yml |yq '.listeners[] | select(.binding == "edge").address' |awk -v FS=':' '{print $1}')
        if [ "$ZITI_CTRANSPORT" == "tls" ]; then
            $map_update -I -c $MYIP -m 32 -l $ZITI_CPORT -h $ZITI_CPORT -t 0 -p tcp
        fi
        # DNS
        $map_update -I -c $MYIP -m 32 -l 53 -h 53 -t 0 -p udp
        # Get Health-Check Port
        ZITI_HCPORT=$(cat /opt/netfoundry/ziti/ziti-router/config.yml |yq '.web[] | select(.name == "health-check").bindPoints[].address' | awk -v FS=':' '{print $2}')
        if [ "$ZITI_HCPORT" ]; then
            $map_update -I -c $MYIP -m 32 -l $ZITI_HCPORT -h $ZITI_HCPORT -t 0 -p tcp
        fi
    fi
fi
