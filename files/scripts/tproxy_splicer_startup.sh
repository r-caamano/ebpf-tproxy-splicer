#!/bin/bash

# Help menu
function usage() 
{
    cat <<USAGE

    Usage: tproxy_splicer_startup.sh [--initial-setup] [--revert-tproxy] [--check-ebpf-status] [--add-user-ingress-rules] [--delete-user-ingress-rules]

    Options:
        --initial-setup                 true if setting up ebpf for first time
        --revert-tproxy                 true if reverting back to tproxy with iptables
        --check-ebpf-status             true if just checking the status of ebpf program
        --add-user-ingress-rules        true if adding user ingress rules to ebpf map
        --delete-user-ingress-rules     true if deleting user ingress rules from ebpf map
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
            if [ $CHECK_EBPF_STATUS == false ] && [ $ADD_USER_INGRESS_RULES == false ] && [ $DELETE_USER_INGRESS_RULES == false ]; then
                echo "INFO: Found ebpf program tproxy_splicer and will re-add it to $LANIF now"
                /usr/sbin/tc qdisc del dev $LANIF clsact
                /usr/sbin/tc qdisc add dev $LANIF clsact
                /usr/sbin/tc filter add dev $LANIF ingress bpf da obj $tproxy_splicer_path sec action || { /usr/sbin/tc qdisc del dev $LANIF clsact; exit 1; }
                ufw allow in on $LANIF to any 
            else
                # Check if user ingress urle update was initiated
                if [ $ADD_USER_INGRESS_RULES == true ] || [ $DELETE_USER_INGRESS_RULES == true ]; then
                    update_map_user
                # Then it is status check
                else
                    echo "INFO: Ebpf is enabled; tproxy splicer is attached to $LANIF"
                    echo "TRACE: $ATTACHED"
                fi
            fi           
        else
            if [ $CHECK_EBPF_STATUS == false ] && [ $ADD_USER_INGRESS_RULES == false ] && [ $DELETE_USER_INGRESS_RULES == false ]; then
                echo "INFO: Not Found ebpf program tproxy_splicer and will add it to $LANIF now"
                /usr/sbin/tc qdisc add dev $LANIF clsact
                /usr/sbin/tc filter add dev $LANIF ingress bpf da obj $tproxy_splicer_path sec action || { /usr/sbin/tc qdisc del dev $LANIF clsact; exit 1; }
                ufw allow in on $LANIF to any
            else
                # Check if user ingress rule update was initiated
                if [ $ADD_USER_INGRESS_RULES == true ] || [ $DELETE_USER_INGRESS_RULES == true ]; then
                    update_map_user
                # Then it is status check
                else
                    echo "INFO: Ebpf is not enabled; tproxy splicer is not attached to $LANIF"
                fi
            fi
        fi
        if [ $CHECK_EBPF_STATUS == false ] && [ $ADD_USER_INGRESS_RULES == false ]; then
            update_map_local
        fi
    else
        echo "ERROR: lanIf not found in $router_config_file, check the config file"
    fi
}

# Update tproxy map with access to local ports
function update_map_local() 
{
    # Save full path of map update into a variable
    if [ -f "$etables" ]; then
        # Get Ziti Fabric Port/Transport
        ZITI_FPORT=$(cat $router_config_file |yq '.link.listeners[] | select(.binding == "transport").advertise' |awk -v FS=':' '{print $3}')
        ZITI_FTRANSPORT=$(cat $router_config_file |yq '.link.listeners[] | select(.binding == "transport").advertise' |awk -v FS=':' '{print $1}')
        if [ "$ZITI_FTRANSPORT" == "tls" ]; then
            $etables -I -c $LANIP -m 32 -l $ZITI_FPORT -h $ZITI_FPORT -t 0 -p tcp
        fi
        # Get Ziti Client Port/Transport
        ZITI_CPORT=$(cat $router_config_file |yq '.listeners[] | select(.binding == "edge").address' |awk -v FS=':' '{print $3}')
        ZITI_CTRANSPORT=$(cat $router_config_file |yq '.listeners[] | select(.binding == "edge").address' |awk -v FS=':' '{print $1}')
        if [ "$ZITI_CTRANSPORT" == "tls" ]; then
            $etables -I -c $LANIP -m 32 -l $ZITI_CPORT -h $ZITI_CPORT -t 0 -p tcp
        fi
        # DNS
        $etables -I -c $LANIP -m 32 -l 53 -h 53 -t 0 -p udp
        # Get Health-Check Port
        ZITI_HCPORT=$(cat $router_config_file |yq '.web[] | select(.name == "health-check").bindPoints[].address' | awk -v FS=':' '{print $2}')
        if [ "$ZITI_HCPORT" ]; then
            $etables -I -c $LANIP -m 32 -l $ZITI_HCPORT -h $ZITI_HCPORT -t 0 -p tcp
        fi
        # invoke function to update ingress fw rules parsed from user file
        update_map_user
    fi
}

function update_map_user()
{
    # if user file exists
    if [ -f $ebpf_user_file ]; then
        if [[ -n  `yq '.rules' $ebpf_user_file` ]]; then
            RULES_NUM=`yq '.rules | keys | length' $ebpf_user_file`
            for ((i = 0 ; i < $RULES_NUM ; i++)); do 
                export ikey=$i
                PORTS=`yq '.rules[env(ikey)] | .ports' $ebpf_user_file`
                PROTOCOLS=`yq '.rules[env(ikey)] | .protocols' $ebpf_user_file`
                PROTO_LEN=`yq '.rules[env(ikey)] | .protocols | length' $ebpf_user_file`
                SOURCE_PREFIX=`yq '.rules[env(ikey)] | .source_prefix' $ebpf_user_file`
                for ((j = 0 ; j < $PROTO_LEN ; j++)); do 
                    export jkey=$j
                    if [[ -n $PORTS ]] && [[ -n $PROTOCOLS ]] && [[ -n $SOURCE_PREFIX ]]; then
                        LP=`yq '.rules[env(ikey)] | .ports[0]' $ebpf_user_file`
                        HP=`yq '.rules[env(ikey)] | .ports[1]' $ebpf_user_file`
                        P=`yq '.rules[env(ikey)] | .protocols[env(jkey)]' $ebpf_user_file`
                        SP=`yq '.rules[env(ikey)] | .source_prefix[0]' $ebpf_user_file`
                        SPL=`yq '.rules[env(ikey)] | .source_prefix[1]' $ebpf_user_file`
                        if [ $DELETE_USER_INGRESS_RULES == true ]; then
                            $etables -D -c $LANIP -m 32 -o $SP -n $SPL -l $LP -h $HP -t 0 -p $P
                        else 
                            $etables -I -c $LANIP -m 32 -o $SP -n $SPL -l $LP -h $HP -t 0 -p $P
                        fi
                    fi
                done
            done
            unset ikey
            unset jkey
        else
           echo "INFO: No rules found in $ebpf_user_file, nothing to do" 
        fi
        # Enable or disable icmp on $LANIF
        if [[ -n  `yq '.icmp' $ebpf_user_file` ]]; then
            ICMP=`yq '.icmp.enable' $ebpf_user_file`
            if [ $ICMP == true ]; then
                echo "INFO: ICMP is set to $ICMP"
                $etables -e $LANIP
            else
                echo "INFO: ICMP is set to $ICMP"
                $etables -e $LANIP -d
            fi
        else
            echo "INFO: No icmp found in $ebpf_user_file, nothing to do"
        fi
    else
        echo "INFO: File $ebpf_user_file not found, nothing to do"
    fi
}

################
##### Main #####
################

# Process the input options.
# Get Input Flags

INITIAL_SETUP=false
REVERT_TPROXY=false
CHECK_EBPF_STATUS=false
ADD_USER_INGRESS_RULES=false
DELETE_USER_INGRESS_RULES=false

while [ "$1" != "" ]; do
    case $1 in
    --initial-setup)
        INITIAL_SETUP=true;;
    --revert-tproxy)
        REVERT_TPROXY=true;;
    --check-ebpf-status)
        CHECK_EBPF_STATUS=true;;
    --add-user-ingress-rules)
        ADD_USER_INGRESS_RULES=true;;
    --delete-user-ingress-rules)
        DELETE_USER_INGRESS_RULES=true;;
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
etables="$EBPF_HOME/objects/etables"
tproxy_splicer_path="$EBPF_HOME/objects/tproxy_splicer.o"
zt_router_service_path="$EBPF_HOME/services/ziti-router.service"
ebpf_user_file="$EBPF_HOME/user_ingress_rules.yml" 
ebpf_map_home="/sys/fs/bpf/tc/globals"
# Is router config file present?
if [ -f "$router_config_file" ]; then
    # Look up tunnel edge binding
    TUNNEL=$(cat $CLOUD_ZITI_HOME/ziti/ziti-router/config.yml |yq '.listeners[] | select(.binding == "tunnel")')
    if [ "$TUNNEL" ]; then
        # Get Tunnel Mode
        TMODE=$(cat $CLOUD_ZITI_HOME/ziti/ziti-router/config.yml |yq '.listeners[] | select(.binding == "tunnel").options.mode')
        # If tproxy is set and initial set flag is set, both true?
        if [ "$TMODE" == null ] || [ "$TMODE" == "tproxy" ]; then
            if [ $INITIAL_SETUP == true ] ; then
                echo "INFO: Checking if diverter installed"
                if [ ! -f $tproxy_splicer_path ] || [ ! -f $zt_router_service_path ]; then
                    echo "ERROR: Diverter not installed, please run diverter-update command to install it"
                else
                    echo "INFO: Initial setup starting"
                    attach_ebpf_program
                    # set it to env var
                    export etables
                    yq -i '(.listeners[] | select(.binding == "tunnel").options | .mode) = "tproxy:"+strenv(etables)' $router_config_file 
                    # unset it to env var
                    unset etables
                    cp $EBPF_HOME/services/ziti-router.service /etc/systemd/system/
                    /usr/bin/systemctl daemon-reload 
                    /usr/bin/systemctl restart ziti-router.service
                fi
            else
                echo "INFO: MODE $TMODE is configured and initial setup flag is $INITIAL_SETUP. Nothing to do"
                if [ $CHECK_EBPF_STATUS == true ]; then
                    echo "INFO: Ebpf is not enabled; tproxy splicer is not attached to LANIF"
                fi
            fi 
        else 
            # Check if tproxy is already set for ebpf mode by evaluating value of mode furthur
            tproxy_ebpf_path=`echo $TMODE | awk -v FS=':' '{print $2}'`
            if [ "$tproxy_ebpf_path" == "$etables" ]; then
                if [ $REVERT_TPROXY == true ]; then
                    echo "INFO: Reverting back to tproxy iptables"
                    # Look up the value of lanIf
                    LANIF=$(cat $router_config_file |yq '.listeners[] | select(.binding == "tunnel").options.lanIf')
                    # Check if lanIf is not empty
                    if [ "$LANIF" ]; then
                        yq -i '(.listeners[] | select(.binding == "tunnel").options | .mode) = "tproxy"' $router_config_file 
                        /usr/sbin/tc qdisc del dev $LANIF clsact
                        /usr/bin/rm $ebpf_map_home/zt_tproxy_map
                        /usr/bin/rm $ebpf_map_home/ifindex_ip_map
                        /usr/bin/rm $ebpf_map_home/matched_map
                        /usr/bin/rm $ebpf_map_home/prog_map
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
                    # Otherwise just run the main ebpf function                        
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

