#! /bin/bash

# Copyright (c) 2014, Yahoo! Inc.
# Copyrights licensed under the New BSD License. See the accompanying LICENSE.txt file for terms.
# Author Binu P. Ramakrishnan
# Created 07/04/2014
 
# root directory
root="/"

# CMD options
cmd_options=(allow deny destroy add list del reset)
# CMD for iptables; note the order is important and is dependent
# on 'cmd_options'
cmd_iptables=(ACCEPT REJECT)

# stype options
stype_options=(ip net)
# stype_options_regex  The correspending regex for the above stype_options.
# The ordering is important
stype_options_regex=("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[1-9][0-9]")

# excluded ports from being filtered
excluded_port="22"

# Initialize our own variables:
cmd=""
in_file=""
verbose=0
yipf_set=""
port=443 # multi-port support?
stype=ip
dryrun=0
timeout=0
maxelem=65536
element=""

# verbosity/debug level
V0=0
V1=1
V2=2
V3=3

# Usage info
yipf_help() {
cat << EOF

Usage: ${0##*/} COMMAND -s SET [-hvd] [-p PORT] [-t TYPE] [-f FILE] [-e TIMEOUT] [-E ELEMENT] [-m MAXELEM]

COMMANDS:    
    allow -s SET         Creates a whitelist set
    deny -s SET          Creates a blacklist set
    destroy -s SET       Delete/Remove a set
    list [-s SET]        List the entries of a named set or all sets
    add -s SET           Add one or more ip/netblocks to an existing set
    del -s SET           Delete entry from the named set 
    test -s SET -E ELEM  Test entry in the named set
    reset                Remove/destroy all filter sets from the system
    save -s SET          Save current settings to stdout
    restore              Restore a saved state from the given state file (-f)
                         Use restore for batch addition of ips

OPTIONS:
    -s SET               The name of the filter set
    -p PORT[,PORT,..]    The destination TCP port number for allow/deny. Default
                         port is 443. You also can specify multiple ports 
                         seperated by ',' eg. 443,80,4080
    -t TYPE              {net | ip} Address family. IPv4 netblock (CIDR) address
                         or a host IPv4 address. Default is 'ip'. 
    -f FILE              Input file with the list of IPv4 ips or ip net blocks.
                         With no FILE or when FILE is -, read standard input. 
                         No IPv6 support in this release
    -w http[s]           HTTP[S] location. (not supported yet)
    -e TIMEOUT           Expiry timeout in seconds. Eg. block ips 'n' seconds
    -E ELEMENT           One ip or a netblock, primarly used with 'test' command
                         -E and -f options are mutually exclusive
    -m MAXELEM           The maximal number of elements which can be stored in 
                         the set, default 65536.  
    -v                   Verbose mode. Can be used multiple times for increased
                         verbosity
    -d                   Dryrun - Check to see the input IPs/netblocks are valid
                         (not supported yet)
    -h                   Display this help and exit
                
EXAMPLES:
    ${0##*/} allow -s whitelist -p 443 -t ip -f whitelist.txt
    
    ${0##*/} deny -s blacklist -p 443 -t ip -f blacklist.txt

    ${0##*/} destroy -s blacklist

    ${0##*/} list -s blacklist

    ${0##*/} list

    ${0##*/} add -s blacklist -e 600 -E 72.134.234.56

    ${0##*/} test -s blacklist -E 72.134.234.56

    echo "72.134.234.56" | ${0##*/} add -s blacklist -e 600

    ${0##*/} save -s blacklist > blacklist.yipf

    ${0##*/} restore -s blacklist -f blacklist.yipf

Report bugs to <rbinu@yahoo-inc.com>.

EOF
}

# check return status of previous cmd and exit the process
exit_check() {
    if [ "$?" -ne "0"  ]
    then
        if [ ! -z "$1" ] 
        then
            # custom error message
            echo "$1" >&2
        fi
        exit 1;
    fi
}

yipf_verbose() {
    # print all user provided cmd-line options
    if [ "$verbose" -ge "$1" ]
    then
        printf "$2" >&2
    fi
}

# Used for cmd-line parameter validation
yipf_op_validate() {
    local found=0
    local options=$1[@]
    local item=$2
    local a=("${!options}")

    for index in ${!a[*]}
    do
        if [ "${a[$index]}" = "$item" ]
        then
            found=1
            # Note: this is the return value of this fn (to stdout).
            echo $index
            return 0
        fi
    done
    
    if [ "$found" -eq "0" ]
    then
        echo "Error: Invalid option '${item}'. Try -h to find all options" >&2
        return 1        
    fi
}

yipf_destroy() {
    local yipf_set="$1"
    local bl=""
    # does this rule exists in INPUT chain?
    local input_rule=$(iptables --list INPUT --line-numbers 2>/dev/null | egrep --regexp "match-set [a-zA-Z0-9_-]+" | egrep --regexp "${yipf_set}" | awk '{print $1}' | head -1)
    while [ ! -z "$input_rule" ]
    do
        # this is a blacklist
        iptables -D INPUT "${input_rule}"
        exit_check "Error: iptables delete rule (${yipf_set}) failed\n"
        input_rule=$(iptables --list INPUT --line-numbers 2>/dev/null | egrep --regexp "match-set [a-zA-Z0-9_-]+" | egrep --regexp "${yipf_set}" | awk '{print $1}' | head -1)
        bl="true"
    done

    if  [ ! -z "$bl" ]
    then
        ipset destroy "${yipf_set}"
        exit_check "Error: ipset destroy ${yipf_set} failed\n"
        return 0
    fi

    # Check if the rule is a whitelist
    local dindex2=$(iptables --list YIPF_WL_"${yipf_set}" --line-numbers 2>/dev/null | egrep --regexp "match-set [a-zA-Z0-9_-]+" | egrep --regexp "${yipf_set}" | awk '{print $1}')
    exit_check "Error: iptables --list ${yipf_set} failed\n"
    local dindex3=$(iptables --list YIPF_WL_"${yipf_set}" --line-numbers 2>/dev/null | awk -v chain="YIPF_WL_${yipf_set}" '{if ($2 == chain) {print $2}}') 
    exit_check "Error: iptables --list ${yipf_set} failed\n"

    if [[ -z "$dindex2" && -z "$dindex3" ]]
    then
        yipf_verbose $V1 "The rule with the given name does not exist\n"
    else
        # rule exists in iptable YIPF_WL_{yipf_set} chain
        # remove/flush all rules from the chain
        iptables -F YIPF_WL_"${yipf_set}" 
        exit_check "Error: iptables flush (${yipf_set}) failed\n"

        # remove given WL rules from INPUT chain
        local wl_input_rule=$(iptables --list INPUT  --line-numbers --numeric | awk -v chain="YIPF_WL_${yipf_set}" '{if ($2 == chain) {print $1}}' | head -1)
        while [ ! -z "$wl_input_rule" ]
        do
            yipf_verbose $V2 "Deleting ${wl_input_rule} from iptable INPUT chain\n"
            iptables -D INPUT "${wl_input_rule}"
            exit_check "Error: iptables delete rule (${wl_input_rule}) failed\n"
            wl_input_rule=$(iptables --list INPUT  --line-numbers --numeric | awk -v chain="YIPF_WL_${yipf_set}" '{if ($2 == chain) {print $1}}' | head -1)
        done

        # Delete the WL chain
        iptables -X YIPF_WL_"${yipf_set}"
        exit_check "Error: iptables delete chain (${yipf_set}) failed\n"
    fi

    ipset destroy "${yipf_set}"
    exit_check "Error: ipset destroy ${yipf_set} failed\n"
    return 0
}

yipf_get_input() {
    local tmpfile="$1"
    if [ -f "$tmpfile" ]
    then
        echo -n "${tmpfile} exists; deleting..." >&2
        rm "${tmpfile}" >&2
        exit_check
        echo " [OK]" >&2
    fi

    if [ -z "$element" ]
    then
        yipf_verbose $V1 "Reading input from ${in_file}... "
        # read input file
        while read -r line
        do
            ip="$line"
            echo "${ip}" | egrep -o --regexp "${stype_options_regex[$stype_index]}" >> "${tmpfile}"
        done < $in_file
    else
        echo "${element}" > "${tmpfile}"
    fi

    yipf_verbose $V1 "[OK]\n"
    return 0
}

yipf_list() {
    local yipf_set="$1"
    if [ -z "$yipf_set" ]
    then
        ipset list 
        exit_check
    else
        echo "------------"
        echo "Filter Rule:"
        echo "------------"
        echo $(iptables -L | grep -m 1 target)
        echo $(iptables -L --numeric | grep -m 1 " ${yipf_set} ")
        echo "------------"
        echo "Set:"
        echo "------------"
        ipset list ${yipf_set} 
        exit_check
    fi
    return 0
}

yipf_test() {
    local yipf_set="$1"
    local yipf_element="$2"
    if [ -z "$yipf_set" ]
    then
        yipf_verbose $V0 "The set with the given name does not exist\n"
        return 1
    else
        ipset test ${yipf_set} ${yipf_element}
        exit_check
    fi
    return 0
}

yipf_add() {
    local yipf_set="$1"
    if [ -z "$yipf_set" ]
    then
        yipf_verbose $V0 "Set name is missing\n"
        return 1
    else
        exists=$(ipset list -name | grep ${yipf_set})
        if [ -z "$exists" ]
        then
            yipf_verbose $V0 "The set with the given name does not exist\n"
            return 1
        fi

        temp_ipset_file="${root}/tmp/${yipf_set}_add_${$}.txt"
        yipf_verbose $V2 "Add: temp_ipset_file: ${temp_ipset_file}\n"
        # read and store user inputs to the tempfile
        yipf_get_input "$temp_ipset_file"
        # read input file
        while read -r line
        do
            ip=$line
            ipset add ${yipf_set} ${ip} "timeout" ${timeout}
        done < "$temp_ipset_file"

        # we no longer need this file
        rm "$temp_ipset_file"
    fi
    return 0
}

yipf_del() {
    local yipf_set="$1"
    if [ -z "$yipf_set" ]
    then
        yipf_verbose $V0 "Set name is missing\n"
        return 1
    else
        exists=$(ipset list -name | grep ${yipf_set})
        if [ -z "$exists" ]
        then
            yipf_verbose $V0 "The set with the given name does not exist\n"
            return 1
        fi

        temp_ipset_file="${root}/tmp/${yipf_set}_del_${$}.txt"
        yipf_verbose $V2 "Del: temp_ipset_file: ${temp_ipset_file}\n"
        # read and store user inputs to the tempfile
        yipf_get_input "$temp_ipset_file"
        # read input file
        while read -r line
        do
            ip=$line
            ipset del ${yipf_set} ${ip}
        done < "$temp_ipset_file"

        # we no longer need this
        rm "$temp_ipset_file"
    fi
    return 0
}

yipf_reset() {
    for yipfset in $(ipset list -n | sort -u)
    do
        yipf_destroy $yipfset
    done
}

yipf_save() {
    local yipf_set="$1"
    if [ -z "$yipf_set" ]
    then
        yipf_verbose $V0 "Set name is missing\n"
        return 1
# TODO:Do not Remove. We may need to support saving state of all sets in future
#        local sets=$(ipset list -n | sort -u)
#        while read -r line; do
#            local ports=$(iptables --list INPUT  --line-numbers --numeric | egrep --regexp "match-set [a-zA-Z0-9_-]+" |  egrep --regexp "${line}" |  egrep -o --regexp "[ ]([0-9]{1,5}[,]?)+([0-9]{1,5}[ ])")
#            local settype=$(iptables --list  | egrep --regexp "match-set [a-zA-Z0-9_-]+" | egrep --regexp "${line}" | awk '{print $1}')
#            echo "${settype} ${line} ${ports}"
#        done <<< "$sets"
#
#        ipset save
    else
        exists=$(ipset list -name | grep "${yipf_set}")
        if [ -z "$exists" ]
        then
            yipf_verbose $V0 "The set with the given name does not exist\n"
            return 1
        fi

        local ports=$(iptables --list --line-numbers --numeric | egrep --regexp "match-set [a-zA-Z0-9_-]+" |  egrep --regexp "${yipf_set}" |  egrep -o --regexp "[ ]([0-9]{1,5}[,]?)+([0-9]{1,5})")
        local settype=$(iptables --list  | egrep --regexp "match-set [a-zA-Z0-9_-]+" | egrep --regexp "${yipf_set}" | awk '{print $1}')
        echo "[__YIPF_METADATA_START__]"
        echo "${settype} ${yipf_set} ${ports}"
        echo "[__YIPF_METADATA_END__]"
        ipset save ${yipf_set} 
    fi 

    return 0 
}

yipf_restore() {
    local metaend=$(cat "${in_file}" | egrep  --regexp "\[__YIPF_METADATA_END__\]" -n |  cut -d: -f1)
    if [ -z "$metaend" ]
    then
         yipf_verbose $V0 "Error: Unknown file format: ${in_file}\n"
         return 1        
    fi

    tail -n +"$((metaend + 1))" "${in_file}" | sed "s/timeout [0-9]*/timeout ${timeout}/" | ipset restore 
    exit_check

    # read input file
    while read -r line
    do
        yipf_verbose $V2 "${line}\n"
        if [ "$line" == "[__YIPF_METADATA_START__]" ]
        then
            continue;
        fi

        if [ "$line" == "[__YIPF_METADATA_END__]" ]
        then
            break;
        fi

        stringarray=($line)
        local cmd="${stringarray[0]}"
        local yipf_set="${stringarray[1]}"
        local port="${stringarray[2]}"

        if [ "$cmd" = "ACCEPT" ]
        then
            # whitelist case is special as it requires a REJECT/DENY rule at the
            # end if prior ACCEPT rule fails to match
            iptables -N YIPF_WL_"${yipf_set}"
            iptables -A YIPF_WL_"${yipf_set}" -m set --match-set "${yipf_set}" src -p TCP -m multiport --dports "${port}" -j ACCEPT
            iptables -A YIPF_WL_"${yipf_set}" -p TCP -m multiport --dports "${port}" -j REJECT
            iptables -A INPUT -p TCP -m multiport --dports  "${port}" -j YIPF_WL_"${yipf_set}"
            if [ "$?" -ne "0"  ]
            then
                yipf_verbose $V0 "Error: iptable rule append failed\n"
                # rollback to previous stable state
                ipset destroy ${yipf_set}
                return 1
            fi
        elif [  "$cmd" = "REJECT" ]
        then
            iptables -A INPUT -m set --match-set "${yipf_set}" src -p TCP -m multiport --dports "${port}" -j REJECT
            if [ "$?" -ne "0"  ]
            then
                yipf_verbose $V0 "Error: iptable rule append failed\n"
                # rollback to previous stable state
                ipset destroy ${yipf_set}
                return 1
            fi
        fi

    done < $in_file

    return 0
}

# No paramaters passed to this function. Instead it depends on
# global variables populated by yipf_main()
yipf_create() {
    # validate port
    validate_port=$( echo "$port" | tr -d ' ' | tr ',' '\n' | sed '/^$/d' | egrep --regexp="^(22)$")
    if [ ! -z "$validate_port" ]
    then
        yipf_verbose $V0 "TCP port 22 (SSH) is not allowed to block, remove 22 and try again\n"
        return 1
    fi

    # validate cmd
    cmd_index=$(yipf_op_validate cmd_options "${cmd}")
    exit_check
    # validate type option
    stype_index=$(yipf_op_validate stype_options "${stype}")
    exit_check

    if [ -f "${root}/tmp/${yipf_set}.txt" ]
    then
        yipf_verbose $V1 "${root}/tmp/${yipf_set}.txt exists; deleting... "
        rm "${root}/tmp/${yipf_set}.txt" >&2
        exit_check
        yipf_verbose $V1 "[OK]\n"
    fi

    if [ -z "$element" ]
    then
        yipf_verbose $V1 "Reading input from ${in_file}... "

        # read input file
        while read -r line
        do
            ip=$line
            echo "${ip}" | egrep -o --regexp "${stype_options_regex[$stype_index]}" >> "${root}/tmp/${yipf_set}.txt"
        done < $in_file
    else
        # just one entry in this case
        echo "${element}" > "${root}/tmp/${yipf_set}.txt"
    fi

    yipf_verbose $V1 "[OK]\nInput processed and stored to ${root}/tmp/${yipf_set}.txt file\n"

    # count total no. of ips/netblocks
    count=$(cat "${root}/tmp/${yipf_set}.txt" | wc -l )
    if [ "$count" -gt "$maxelem" ] 
    then 
        maxelem=$count
    fi

    ipset_params="hash:${stype_options[$stype_index]}  maxelem ${maxelem} timeout ${timeout}"
    temp_ipset="${yipf_set}_temp"
    # create a temporary ipset
    ipset create ${temp_ipset} ${ipset_params}
    exit_check

    yipf_verbose $V1 "Temp ipset ${temp_ipset} created successfully\n"

    # read input file
    while read -r line
    do
        ip=$line
        # add ips/netblocks to the temp set
        ipset add ${temp_ipset} ${ip}
        if [ "$?" -ne "0"  ]
        then
            ipset destroy ${temp_ipset}
            return 1
        fi
    done < "${root}/tmp/${yipf_set}.txt"

    yipf_verbose $V1 "Input added to set\n"

    # if ipset does not exist, create it
    ipset create -exist ${yipf_set} ${ipset_params}
    if [ "$?" -ne "0"  ]
    then
        yipf_verbose $V0 "Error: ipset create failed\n"
        ipset destroy ${temp_ipset}
        return 1
    fi

    # swap the temp ipset for the live one
    ipset swap ${temp_ipset} ${yipf_set}
    if [ "$?" -ne "0"  ]
    then
        yipf_verbose $V0 "Error: ipset swap failed\n"
        ipset destroy ${temp_ipset}
        return 1
    fi

    ipset destroy ${temp_ipset}
    # Check if the rule exists in the iptable 
    yipf_set_exists=$(iptables --list-rules | egrep -o  --regexp "match-set [a-zA-Z0-9_-]+ " |  egrep -o  --regexp "${yipf_set}")

    if [[ ! -z "${yipf_set_exists}" && "${yipf_set}" = "${yipf_set_exists}" ]]
    then
        yipf_verbose $V0 "Rule already exists in firewall; only the sets are updated\n"
    else
        if [ "${cmd_iptables[$cmd_index]}" = "ACCEPT" ]
        then
            # whitelist case is special as it requires a REJECT/DENY rule at the
            # end if prior ACCEPT rule fails to match
            iptables -N YIPF_WL_"${yipf_set}"
            iptables -A YIPF_WL_"${yipf_set}" -m set --match-set "${yipf_set}" src -p TCP -m multiport --dports "${port}" -j ACCEPT
            iptables -A YIPF_WL_"${yipf_set}" -p TCP -m multiport --dports "${port}" -j REJECT
            iptables -A INPUT -p TCP -m multiport --dports  "${port}" -j YIPF_WL_"${yipf_set}"
            if [ "$?" -ne "0"  ]
            then
                yipf_verbose $V0 "Error: iptable rule append failed\n"
                # rollback to previous stable state
                ipset destroy ${temp_ipset}
                ipset destroy ${yipf_set}
                return 1
            fi
        elif [  "${cmd_iptables[$cmd_index]}" = "REJECT" ]
        then
            iptables -A INPUT -m set --match-set "${yipf_set}" src -p TCP -m multiport --dports "${port}" -j REJECT
            if [ "$?" -ne "0"  ]
            then
                yipf_verbose $V0 "Error: iptable rule append failed\n"
                # rollback to previous stable state
                ipset destroy ${temp_ipset}
                ipset destroy ${yipf_set}
                return 1
            fi
        fi

        yipf_verbose $V1 "Rule successfully added to the firewall\n"
    fi
}


#####################################
## yipf_main() - starting function ##
#####################################
yipf_main() {
    if [ $# -lt 3 ]
    then
        # help (used by html2man for generating man pages)
        if [[ ! -z "$1" && ( "$1" = "-h" || "$1" = "--help" )]]
        then
            yipf_help
            exit 0   
        fi  

        # version (used by html2man for generating man pages)
        if [[ ! -z "$1" && "$1" = "--version" ]]
        then
            echo -n "${0##*/} "
            echo `grep '^Version' README | head -1 | awk '{print $2;}'`
            exit 0
        fi  

        if [[ -z "$1" || ( ! -z "$1" && "$1" != "list" && "$1" != "reset" ) ]]
        then
            echo "Error: Missing CMD or -r SET command-line parameters. 
Try -h to find all options" >&2
            exit 1
        fi
    fi

    # get sub-command
    cmd="$1"

    # Reset is necessary if getopts was used previously in the script
    OPTIND=2 
    while getopts "hds:p:t:f:e:vE:m:" opt; do
        case "$opt" in
            h)
                yipf_help
                exit 0
                ;;
            s)  yipf_set=$OPTARG
                ;;
            p)  port=$(echo "$OPTARG" | tr ' ' ',' | tr ',' '\n' | sed '/^$/d' | tr '\n' ',' | sed 's@,$@@')
                ;;
            t)  stype=$OPTARG
                ;;                                        
            f)  in_file=$OPTARG
                ;;
            e)  timeout=$OPTARG
                ;;
            E)  element=$OPTARG
                ;;
            m)  maxelem=$OPTARG
                ;;
            v)  verbose=$(($verbose+1))
                ;;
            d)  dryrun=1
                ;;
            '?')
                yipf_help >&2
                exit 1
                ;;
        esac
    done
    shift "$((OPTIND-2))" # Shift off the options and optional --.

    if [[ ! -z "$in_file" && ! -z "$element" ]]
    then
        yipf_verbose $V0 "Error: -f and -E options are mutualy exclusive. Use either -f or -E\n"
        exit 1
    # read ips from stdin?
    elif [[ -z "$in_file" || "$in_file" = "-" ]]
    then
        in_file="/dev/stdin"
    fi

    yipf_verbose $V2 "Cmd-line options:\n\tCMD: ${cmd}\n\t-r: ${yipf_set}\n\t\
-p: ${port}\n\t-t: ${stype}\n\t-f: ${in_file}\n\t-v: ${verbose}\n\t-d: ${dryrun}\n\t\
-e: ${timeout}\n\t-E: ${element}\n\t-m: ${maxelem}\n"

    user=$(id -u)
    if [ $user -ne "0" ]
    then
        yipf_verbose $V0 "You must be root user to run this command\n"
        exit 1
    fi

    # route based on the cmd
    case "${cmd}" in
            'allow')  
                yipf_create
                exit $?
                ;;
            'deny')  
                yipf_create
                exit $?
                ;;
            'destroy')
                yipf_destroy $yipf_set
                exit $?
                ;;
            'list')  
                yipf_list $yipf_set
                exit $?
                ;;
            'add')  
                yipf_add $yipf_set
                exit $?
                ;;
            'del')  
                yipf_del $yipf_set
                exit $?
                ;;
            'test')  
                yipf_test $yipf_set $element
                exit $?
                ;;
            'reset')  
                yipf_reset
                exit $?
                ;;
            'save')  
                yipf_save $yipf_set
                exit $?
                ;;
            'restore')  
                yipf_restore $yipf_set
                exit $?
                ;;
            '?')
                yipf_help >&2
                exit 1
                ;;
        esac
}


##########################
## main() starts here!  ##
##########################
yipf_main "$@"

# End of file

