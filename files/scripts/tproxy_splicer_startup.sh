#!/bin/bash

# Help menu
function usage() 
{
    cat <<USAGE

    Usage: tproxy_splicer_startup.sh [--initial-setup] [--revert-tproxy]

    Options:
        --initial-setup  true if setting up ebpf for first time
        --revert-tproxy  true if reverting back to tproxy with iptables
        -V, --version    current version
        -h, --help       help menu
USAGE
    exit 1
}

# Shows current version
function version()
{
    echo "0.1.0"
    exit 1
}

# Fucntion to check if ebpf program is attached if not re-attach it
attach_ebpf_program()
{
    # Look up the value of lanIf
    LANIF=$(cat $router_config_file |yq '.listeners[] | select(.binding == "tunnel").options.lanIf')
    # Check if lanIf is not empty
    if [ "$LANIF" ]; then
        # Then get IP
        LANIP=$(/sbin/ip add show "${LANIF}"|awk '$1=="inet" {print $2;}'|awk -v FS='/' '{print $1}')
        # Attach ebpf program to lanif interface
        ATTACHED=`eval /usr/sbin/tc filter show dev $LANIF ingress`
        # Check if tproxy splicer ebpf is attached 
        if [ $(echo  $ATTACHED | grep -w -c tproxy_splicer.o) == 1 ]; then  
            echo "Found ebpf program tproxy_splicer and will re-add it to $LANIF now"
            /usr/sbin/tc qdisc del dev $LANIF clsact
            /usr/sbin/tc qdisc add dev $LANIF clsact
            /usr/sbin/tc filter add dev $LANIF ingress bpf da obj $EBPF_HOME/objects/tproxy_splicer.o sec action || /usr/sbin/tc qdisc del dev $LANIF clsact; exit 1
            ufw allow in on $LANIF to any            
        else
            echo "Not Found ebpf program tproxy_splicer and will add it to $LANIF now"
            /usr/sbin/tc qdisc add dev $LANIF clsact
            /usr/sbin/tc filter add dev $LANIF ingress bpf da obj $EBPF_HOME/objects/tproxy_splicer.o sec action || /usr/sbin/tc qdisc del dev $LANIF clsact; exit 1
            ufw allow in on $LANIF to any
        fi
        update_map_local
    else
        echo "ERROR: lanIf not found in $router_config_file, check the config file"
    fi
}

# Update tproxy map with access to local ports
function update_map_local() 
{
    # Save full path of map update into a variable
    if [ -f "$map_update" ]; then
        # Get Ziti Fabric Port/Transport
        ZITI_FPORT=$(cat $router_config_file |yq .ctrl.endpoint |awk -v FS=':' '{print $3}')
        ZITI_FTRANSPORT=$(cat $router_config_file |yq .ctrl.endpoint |awk -v FS=':' '{print $1}')
        if [ "$ZITI_FTRANSPORT" == "tls" ]; then
            $map_update -I -c $LANIP -m 32 -l $ZITI_FPORT -h $ZITI_FPORT -t 0 -p tcp
        fi
        # Get Ziti Client Port/Transport
        ZITI_CPORT=$(cat $router_config_file |yq '.listeners[] | select(.binding == "edge").address' |awk -v FS=':' '{print $3}')
        ZITI_CTRANSPORT=$(cat $router_config_file |yq '.listeners[] | select(.binding == "edge").address' |awk -v FS=':' '{print $1}')
        if [ "$ZITI_CTRANSPORT" == "tls" ]; then
            $map_update -I -c $LANIP -m 32 -l $ZITI_CPORT -h $ZITI_CPORT -t 0 -p tcp
        fi
        # DNS
        $map_update -I -c $LANIP -m 32 -l 53 -h 53 -t 0 -p udp
        # Get Health-Check Port
        ZITI_HCPORT=$(cat $router_config_file |yq '.web[] | select(.name == "health-check").bindPoints[].address' | awk -v FS=':' '{print $2}')
        if [ "$ZITI_HCPORT" ]; then
            $map_update -I -c $LANIP -m 32 -l $ZITI_HCPORT -h $ZITI_HCPORT -t 0 -p tcp
        fi
    fi
}

################
##### Main #####
################

# Process the input options.
# Get Input Flags

INITIAL_SETUP=false
REVERT_TPROXY=false

while [ "$1" != "" ]; do
    case $1 in
    --initial-setup)
        INITIAL_SETUP=true;;
    --revert-tproxy)
        REVERT_TPROXY=true;;
    -h | --help)
        usage;;
    -V | --version)
        version;;
    *)
        usage;;
    esac
    shift
done

# get local ip for lanIf
# First check if the edge router config file exists
CLOUD_ZITI_HOME="/opt/netfoundry"
EBPF_HOME="$CLOUD_ZITI_HOME/ebpf"
router_config_file="$CLOUD_ZITI_HOME/ziti/ziti-router/config.yml"
map_update="$EBPF_HOME/objects/map_update"
# Is router config file present?
if [ -f "$router_config_file" ]; then
    # Look up tunnel edge binding
    TUNNEL=$(cat $CLOUD_ZITI_HOME/ziti/ziti-router/config.yml |yq '.listeners[] | select(.binding == "tunnel")')
    if [ "$TUNNEL" ]; then
        # Get Tunnel Mode
        TMODE=$(cat $CLOUD_ZITI_HOME/ziti/ziti-router/config.yml |yq '.listeners[] | select(.binding == "tunnel").options.mode')
        # If tproxy is set and initial set flag is set, both true?
        if [ "$TMODE" == null ] || [ "$TMODE" == "tproxy" ]; then
            if [ $INITIAL_SETUP == true ] && [ -f "$EBPF_HOME/services/ziti-router.service" ]; then
                echo "Inital set up starting"
                attach_ebpf_program
                # set it to env var
                export map_update
                yq -i '(.listeners[] | select(.binding == "tunnel").options | .mode) = "tproxy:"+strenv(map_update)' $router_config_file 
                # unset it to env var
                unset map_update
                cp $EBPF_HOME/services/ziti-router.service /etc/systemd/system/
                /usr/bin/systemctl daemon-reload 
                /usr/bin/systemctl restart ziti-router.service
            else
                echo "INFO: MODE $TMODE is configured and initial setup flag is $INITIAL_SETUP. Nothing to do"
            fi 
        else 
            # Check if tproxy is already set for ebpf mode by evaluating value of mode furthur
            tproxy_ebpf_path=`echo $TMODE | awk -v FS=':' '{print $2}'`
            if [ "$tproxy_ebpf_path" == "$map_update" ]; then
                if [ $REVERT_TPROXY == true ]; then
                    echo "Reverting back to tproxy iptables"
                    # Look up the value of lanIf
                    LANIF=$(cat $router_config_file |yq '.listeners[] | select(.binding == "tunnel").options.lanIf')
                    # Check if lanIf is not empty
                    if [ "$LANIF" ]; then
                        yq -i '(.listeners[] | select(.binding == "tunnel").options | .mode) = "tproxy"' $router_config_file 
                        /usr/sbin/tc qdisc del dev $LANIF clsact
                        /usr/bin/rm /sys/fs/bpf/tc/globals/zt_tproxy_map
                        # delete ufw rule associated with ebpf
                        ufw_rule_num=$(ufw status numbered | jc --ufw -p | jq -r --arg LANIF "$LANIF" '.rules[] | select(.to_interface == $LANIF).index' | sort -r)
                        for index in $ufw_rule_num
                        do
                            ufw --force delete $index
                        done
                        # Restart ziti router service after reverting all changes
                        /usr/bin/systemctl restart ziti-router.service
                    else
                        echo "ERROR: lanIf value is missing, could not revert config back to tproxy with iptables"
                    fi
                else
                    echo "INFO: Re-attaching ebpf program"
                    attach_ebpf_program
                fi
            else
                echo "INFO: TMODE $TMODE, nothing to do"
            fi
        fi
    else
        echo "INFO: tunnel mode not set, nothing to do"
    fi
else
    echo "INFO: router config file not found, perhaps it is expected!?"
fi

