#! /bin/bash

_env_file="$( basename "$0" ".sh" ).env"

if [[ -r "${_env_file}" ]]
then
    source "${_env_file}"
fi

#declare -a trusted_domain_prefix=( 127 192.168 90 86.205 )
#!! FIXME: unable de ban subdomain

if [[ -z "${trusted_domain_prefix}" ]]
then
    declare -a trusted_domain_prefix=( 127.0 192.168 90 86 80.12 193.252 )
    declare -a trusted_domain_prefix=( 127.0 192.168 80.12 193.252 )
fi

: ${jail:=sshd}

_config_unchanged=false
until ${_config_unchanged}
do

    _config_unchanged=true
    
    banned_ips_line=$( fail2ban-client status sshd | sed -n -e '/Banned IP list:/p' )

    banned_ips=$( echo "${banned_ips_line}" | sed -e 's/.*- Banned IP list:[ \t]*//' )

    declare -a banned_ips_without_mask=( $(

	for ip in ${banned_ips}
	do
	    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
	    then
		# we still go a valid address
		:
	    else
		# no more address found
		continue
	    fi

	    if [[ "${ip%/*}" == "${ip}" ]]
	    then
		echo "${ip}"
	    fi
	done
    )
    )

    # For test
    # banned_ips_without_mask=( 192.168.5.8  2.224.168.43 61.146.72.252 )

    ip=$(

	# pick the first untrusted address

	for addr in "${banned_ips_without_mask[@]}"
	do
	    # check if it is trusted
	    _untrusted=true
	    for prefix in "${trusted_domain_prefix[@]}"
	    do
		if [[ "${addr#${prefix}}" != "${addr}" ]]
		then
		    # trusted domain
		    _untrusted=false
		    break
		fi
	    done
	    if ${_untrusted}
	    then
		echo "${addr}"
		break
	    fi
	done
    )

    if [[ -n "${ip}" ]]
    then

	ip_sub_classes=( $( echo "${ip}" | cut --delimiter='.'  --output-delimiter=' ' -f 1-4 ) )

	addr_with_mask="${ip_sub_classes[0]}.${ip_sub_classes[1]}.0.0/16"
	echo "BAN A class: ${addr_with_mask}"
	echo fail2ban-client set sshd banip "${addr_with_mask}"
	_config_unchanged=false
	for baned_ip in "${banned_ips_without_mask[@]}"
	do
	    baned_ip_sub_classes=( $( echo "${baned_ip}" | cut --delimiter='.'  --output-delimiter=' ' -f 1-4 ) )
	    if [[ "${baned_ip_sub_classes[0]}" == "${ip_sub_classes[0]}" && "${baned_ip_sub_classes[1]}" == "${ip_sub_classes[1]}" ]]
	    then
		echo "UNBAN host: ${baned_ip}"
		echo fail2ban-client set sshd unbanip "${baned_ip}"
	    fi
	done
    fi

done
