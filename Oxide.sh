#!/usr/bin/bash

# Oxide v1.1.3
# W315 2019

# Colors:
red="\e[31m"
green="\e[32m"
normal="\e[0m"
yellow="\e[33m"
ciano="\e[36m"
purple="\e[35m"

# Functions

setpj() {

	banner

	chrlen=${#pentest}
	if [ $chrlen -gt 50 ]; then
		echo " [!] Name too long. Please choose a shorter name (< 50 chars)"
		exit
	fi

	# Create project folder
	echo $pentest > newprj.tmp
	cat 'newprj.tmp' | tr -cd "[:alnum:]-" > newprjc.tmp
	pentest=$(cat 'newprjc.tmp')
	rm newprj.tmp
	rm newprjc.tmp

	# if folder exists ask to resume or start again
	alreadythere() {

		echo -e $yellow" [Warning] A folder already exists with this name."$normal
		echo " Would you like to overwrite it?"
		echo
		echo " 1. Quit"
		echo " 2. Overwrite previous test"
		echo
		read -s -n1 resumeornot

		case $resumeornot in

			1) 
				exit
			;;
			2)
				echo " [+] Removing previous files.."
				rm -rf ./$pentest
			;;
			*)
				echo -e $red" [!] Input Error: please choose again.."
				alreadythere
			;;
		esac

	}

	if [ -d ./$pentest ]; then
		alreadythere
	fi

	mkdir "./$pentest"
	echo " [+] Initialising new project: "$pentest
	echo " [+] Project folder created."
	
	echo "Project#"$pentest > ./$pentest/info.txt 
	echo "Created#"$(date "+%H:%M %d/%m/%Y") >> ./$pentest/info.txt
	echo
	echo " ------------------------------------------" 
	echo " Press ENTER to Insert/Review your targets"
	echo " ------------------------------------------"
    	read enter
    	nano ./$pentest/targets.txt

}

formatter() {

	# Consider if replacing with: nmap -sL -n -iL targets.txt | grep -i "scan report for" | cut -d " " -f5

	banner
	echo -e " [+] Checking targets.."
	# Check if file exist
	if [ ! -e "./$pentest/targets.txt" ]; then
		echo -e $red" [ERROR] No targets file found \n"$normal
		exit
	fi

	# Check if list is empty
	targetnum=$(wc -l < ./$pentest/targets.txt)

	if [ ${targetnum} -eq 0 ]; then
		echo -e $red" [ERROR] The targets file is empty \n"$normal
		exit
	fi

	# Check for invalid characters
	for ip in $(cat "./$pentest/targets.txt"); do
		if [[ "$ip" =~ [a-zA-Z] ]]; then
	    		echo -e $red" [ERROR] The targets file contain invalid targets \n"$normal
			exit
		fi
	done

	# Replace SPACE with \n
	cat ./$pentest/targets.txt > ./$pentest/targets.tmp
	sed -e 's/\s\+/\n/g' ./$pentest/targets.tmp > ./$pentest/targets.txt
	
	# Remove commas 
	cat ./$pentest/targets.txt > ./$pentest/targets.tmp
	sed -e 's/,//g' ./$pentest/targets.tmp > ./$pentest/targets.txt

	# Check for CIDR Ranges
	# 10.11.1.1-10.11.1.255, 10.11.1.1-255
	grep "-" "./$pentest/targets.txt" > ./$pentest/targets.tmp

	for ip in $(cat "./$pentest/targets.tmp"); do

		# Check what type of range
		rangetype=$(echo $ip | cut -d "-" -f2)
		before=$(echo $ip | cut -d '.' -f1-3)
		primo=$(echo $ip | cut -d "-" -f1 | cut -d "." -f4)

		if [[ ${#rangetype} -lt 4 ]]; then
	    		ultimo=$(echo $ip | cut -d "-" -f2)
		else
			after=$(echo $rangetype | cut -d '.' -f1-3)
			if [ "$before" != "$after" ]; then
				echo -e $red" [ERROR] Invalid range found \n"$normal
				exit
			fi

			ultimo=$(echo $rangetype | cut -d '.' -f4)
		fi

		for ((i=$primo; i<=$ultimo; i++)); do
			echo $before'.'$i >> ./$pentest/targets.txt
		done

	done

	# 10.11.1.1/24
	grep "/" "./$pentest/targets.txt" > ./$pentest/targets.tmp

	for ip in $(cat "./$pentest/targets.tmp"); do

		# Assign each octet to variable
		# $w.$x.$y.$z/$mask

		w=$(echo $ip | cut -d '.' -f1)
		x=$(echo $ip | cut -d '.' -f2)
		y=$(echo $ip | cut -d '.' -f3)
		z=$(echo $ip | cut -d '.' -f4 | cut -d '/' -f1)
		mask=$(echo $ip | cut -d '/' -f2)

		# Check if each octet is a number (no characters, no symbols) and not > 255

		if [[ ! $w =~ ^[0-9]+$ ]]
		then
			echo -e $red" [ERROR] Invalid range found \n"$normal
			exit
		fi
		if [[ ! $x =~ ^[0-9]+$ ]]
		then
			echo -e $red" [ERROR] Invalid range found \n"$normal
			exit
		fi
		if [[ ! $y =~ ^[0-9]+$ ]]
		then
			echo -e $red" [ERROR] Invalid range found \n"$normal
			exit
		fi
		if [[ ! $z =~ ^[0-9]+$ ]]
		then
			echo -e $red" [ERROR] Invalid range found \n"$normal
			exit
		fi
		if [[ ! $mask =~ ^[0-9]+$ ]]
		then
			echo -e $red" [ERROR] Invalid range found \n"$normal
			exit
		fi
			# Check if /mask is beetween ($mask < 16 || $mask > 32) (also no characters, symbols)

		if [[ $mask -lt 16 ]] || [[ $mask -gt 32 ]]
		then
			echo -e $red" [ERROR] Invalid range found \n"$normal
			exit
		fi

		# Math start

		num=$((2 ** (32 - $mask)))
			
		for (( i=$num; $i>0; i-- )); do
			
			echo $w'.'$x'.'$y'.'$z >> ./$pentest/targets.txt
			(( z++ ))
			
			if [[ $z -gt 255 ]]; then
				(( y++ ))
				z=0
			fi
			if [[ $y -gt 255 ]]; then
				(( x++ ))
				y=0
			fi
			if [[ $x -gt 255 ]]; then
				(( w++ ))
				x=0
			fi
		done
	done

	# Remove ranges from targets
	sed -i '/-/d' ./$pentest/targets.txt
	sed -i '/\//d' ./$pentest/targets.txt

	# Sort and Uniq the targets

	cat ./$pentest/targets.txt > ./$pentest/targets.tmp
	sort -u ./$pentest/targets.tmp > ./$pentest/targets.txt

	rm ./$pentest/targets.tmp

}

alive() {

	if [ ! -d "./$pentest" ]; then
		setpj
	fi

	# Check for live host (ICMP)
	timestamp=$(date "+%H:%M %d/%m/%Y")
	echo -e $green"\n [+] Performing Ping Sweep"$normal
	nmap -sn -n -iL ./$pentest/targets.txt | grep "for" | cut -d " " -f5 > ./$pentest/live-targets.txt

	echo "ICMP#"$timestamp" - "$(date "+%H:%M %d/%m/%Y") >> ./$pentest/info.txt

	# Separate live / non live targets
	cp ./$pentest/targets.txt ./$pentest/dead-targets.txt
	for ip in $(cat "./$pentest/live-targets.txt"); do
		sed -i '/'$ip'/d' ./$pentest/dead-targets.txt
	done

	cat ./$pentest/live-targets.txt > ./$pentest/targets.tmp
	sort -u ./$pentest/targets.tmp > ./$pentest/live-targets.txt

	cat ./$pentest/dead-targets.txt > ./$pentest/targets.tmp
	sort -u ./$pentest/targets.tmp > ./$pentest/dead-targets.txt

	rm ./$pentest/targets.tmp

	echo -e " [-] Number of Targets: "$(wc -l < ./$pentest/targets.txt)
	echo -e " [-] Live Targets (icmp): "$(wc -l < ./$pentest/live-targets.txt)
	echo -e " [-] Offline Targets: "$(wc -l < ./$pentest/dead-targets.txt)
	echo

}

whoown() {

	if [ ! -d ./$pentest ]; then
		setpj
	fi
	if [ -e ./$pentest/whois.txt ]; then
		rm "./$pentest/whois.txt"
	fi
	
	# Check host providers (range owners)
	echo -e $green" [+] Checking targets ownership (WHOIS)"$normal
	i=1
	num=$(wc -l < "./"$pentest"/targets.txt")
	
	for ip in $(cat "./"$pentest"/targets.txt"); do
	
        	echo -ne " [-] Targets checked: "$i" of "$num "\\r"
        	whois $ip > ./$pentest/whois.tmp
        	provider=$(grep "org-name:" ./$pentest/whois.tmp | cut -d ":" -f2)
        	if [ -z "$provider" ]; then
            		provider=$(grep "descr:" ./$pentest/whois.tmp | tail -n1 | cut -d ":" -f2)
        	fi
        	echo $ip':'$provider >> ./$pentest/whois.txt
        	(( i++ ))
	
	done
    	rm ./$pentest/whois.tmp
	
}

nmapscan() {

	echo -e $green"\n\n [+] Running TCP Port Scan"$normal
	echo " [-] NMAP Scan started ("$(date "+%H:%M %d/%m/%Y")")"
	# create nmap folders if not exist
	if [ ! -d "./$pentest/nmap" ]; then
		mkdir "./$pentest/nmap"
	fi

	# Tcp scan start time:
	timestamp=$(date "+%H:%M %d/%m/%Y")

	# Can't run with time updates as it would require -vv and would change the output number of lines
	# This would create problem in grepping the ports in the services function
	nmap -Pn -n -p- --min-hostgroup 20 -iL ./$pentest/targets.txt > ./$pentest/nmap/NmapTCP.txt
	
	# Tcp scan timestamp
	echo "TCP#"$timestamp" - "$(date "+%H:%M %d/%m/%Y") >> "./$pentest/info.txt"
	echo -e "\n [-] TCP Scan Finished ("$(date "+%H:%M %d/%m/%Y")")"
	echo -e $green"\n [+] Running UDP Port Scan"$normal
	echo " [-] NMAP Scan started ("$(date "+%H:%M %d/%m/%Y")")"
	# UDP scan start time:
	timestamp=$(date "+%H:%M %d/%m/%Y")

	nmap -sU --top-ports 200 --min-hostgroup 20 -Pn -iL ./$pentest/targets.txt > ./$pentest/nmap/NmapUDP.txt

	# UDP scan timestamp (print to info.txt file)
	echo "UDP#"$timestamp" - "$(date "+%H:%M %d/%m/%Y") >> "./$pentest/info.txt"
	echo -e "\n [-] UDP Scan Finished ("$(date "+%H:%M %d/%m/%Y")")"

}

services() {

	# Extract services from nmap scans
	echo -e $green'\n [+] Extracting Services'$normal

	if [ -e "./$pentest/services.txt" ]; then
		rm ./$pentest/services.txt
	fi

	# Extract Open Ports
	awk '/Nmap scan report/ { host=$NF } NF==3 && $2=="open" { print host, $1, $2, $NF }' ./$pentest/nmap/Nmap*.txt > ./$pentest/services.txt
	awk '/Nmap scan report/ { host=$NF } NF==3 && $2=="closed" { print host, $1, $2, $NF }' ./$pentest/nmap/Nmap*.txt >> ./$pentest/services.txt
	awk '/Nmap scan report/ { host=$NF } NF==5 && $4=="closed" { print host, $3, $4, $NF }' ./$pentest/nmap/NmapTCP.txt >> ./$pentest/firewall-misc.txt
	
	echo " [-] OPEN Services: "$(grep "open" ./$pentest/services.txt | wc -l)
	echo " [-] CLOSED Services: "$(grep "closed" ./$pentest/services.txt | wc -l)
	echo " [-] Hosts with large number of closed ports: "$(wc -l < ./$pentest/firewall-misc.txt)

}

tester() {

	# Setting IFS to ease awk of IP and Ports
	IFS=$'\n'

	# Run specific tests based on services found
	echo -e $green'\n [+] Checking known Services'$normal

	# 25 Simple Mail Transfer Protocol (SMTP)

			# VRFY username (verifies if username exists - enumeration of accounts)
			# EXPN username (verifies if username is valid - enumeration of accounts)
			
			# Mail Spoof Test
			# HELO anything 
			# MAIL FROM: spoofed_address
			# RCPT TO:valid_mail_account 
			# ./$pentest Penetration Test: If you receive this email please forward it to denni.pisoni@firstbase.co.uk 
			# QUIT

	# 69 Trivial File Transfer Protocol (TFTP)

			# tftp ip_address PUT local_file 
			# tftp ip_address GET conf.txt (or other files) 
			# Solarwinds TFTP server 
			# tftp - i <IP> GET /etc/passwd (old Solaris) 
			# TFTP Bruteforcing 

	# 110 POP3

	# 143 IMAP
	# PPTP

	# 3306 MySQL
		
			# nmap -A -n -PN --script:ALL -p3306 <IP Address> 
			# telnet IP_Address 3306 
			# use test; select * from test;
			# mysql -h <Hostname> -u root 

	# 3389 RDP
			# rdesktop IP

	# 5060 udp/tcp: SIP

	# ms-sql	
			# nmap -p 1433 --script ms-sql-info --script-args mssql.instance-port=1433 195.97.255.70

	telnet_check() {

		for line in $(awk "/telnet/ && /open /" "./$pentest/services.txt"); do 

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)
			nmap -p $port --script telnet-ntlm-info $ip > "./$pentest/scans/telnet-"$ip"-"$port".txt"
			# nmap -p $port  --script telnet-brute --script-args userdb=myusers.lst,passdb=mypwds.lst,telnet-brute.timeout=8s <target>

		done

	}

	ftp_check() {

		# Anonymous login (anonymous, anonymous / ftp, ftp / anon, anon)
		# If login: execute 'quote help' and 'syst'
		# banner grab: telnet [ip] [port]

		# use auxiliary/scanner/ftp/anonymous
		# msf auxiliary(anonymous) >set rhosts 192.168.0.106
		# msf auxiliary(anonymous) >exploit
		
		for line in $(awk "/ftp/ && /open /" "./$pentest/services.txt"); do 

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)

			# Banner retrieve
			nmap -sV --script=banner -p $port $ip --host-timeout 30s > "./$pentest/scans/ftp-"$ip"-"$port".tmp"
			awk "/banner:/" "./$pentest/scans/ftp-"$ip"-"$port".tmp" | cut -d ":" -f2 > "./$pentest/scans/ftp-"$ip"-"$port".txt"

			# Anonymous login check
			nmap --script=ftp-anon -p $port $ip --host-timeout 30s > "./$pentest/scans/ftp-"$ip"-"$port".tmp"
			awk "/ftp-anon:/" "./$pentest/scans/ftp-"$ip"-"$port".tmp" | cut -d ":" -f2 >> "./$pentest/scans/ftp-"$ip"-"$port".txt"

		done

		rm "./$pentest/scans/"*".tmp"
	
	}

	ssh_check() {

		# 22 SSH Remote Login Protocol		
			# telnet IP PORT

			# use auxiliary/scanner/ssh/ssh_login
			# msf auxiliary(ssh_login) >set rhost 192.168.1.17
			# msf auxiliary(ssh_login) >set rport 22
			# msf auxiliary(ssh_login) > set userpass_file /root/Desktop/ssh.txt
			# msf auxiliary(ssh_login) >exploit
	
		for line in $(awk "/ssh/ && /open /" "./"$pentest"/services.txt"); do

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)

			# run check here
			nmap -sV --script=banner $ip -p $port --host-timeout 30s > "./"$pentest"/scans/ssh-"$ip"-"$port".tmp"
			awk "/banner:/" "./$pentest/scans/ssh-"$ip"-"$port".tmp" | cut -d ":" -f2 > "./$pentest/scans/ssh-"$ip"-"$port".txt"
			# add more:
			# Brute-force check

		done

		rm "./$pentest/scans/"*".tmp"

	}
	
	dns_check() {

		# 53 Domain Name System (DNS)

			# nmap --script dns-zone-transfer IP -p Port
			# nslookup -port=53 10.10.10.1

		for line in $(awk "/domain/ && /open /" "./$pentest/services.txt"); do

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)

			# run check here
			nmap --script dns-zone-transfer $ip -p $port --host-timeout 30s > "./$pentest/scans/dns-"$ip"-"$port".txt"
			echo -e "\nReverse DNS Lookup:\n" >> "./$pentest/scans/dns-"$ip"-"$port".txt"
			nslookup -port=$port $ip >> "./$pentest/scans/dns-"$ip"-"$port".txt"
		done

	}

	smb_check() {

		# 445 SMB

			# enum4linux -a $target_ip
			# smbclient \\\\$ip\\$share
			# nmblookup -A target
			# smbclient //MOUNT/share -I target -N
			# rpcclient -U "" target
			# smbmap -H 10.10.10.10 -u null -p null

		for line in $(awk "/microsoft-ds/ && /open /" "./$pentest/services.txt"); do

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)

			# run check here
			enum4linux -a $ip | tee "./$pentest/scans/smb-"$ip"-"$port".txt" > /dev/null 2>&1

		done

	}

	finger_check() {

		# 79 Finger

			# finger @IP-Address
			# finger 'a b c d e f g h' @example.com 
			# finger admin@example.com
			# finger "|/bin/ls -a /@example.com"
			# finger "|/bin/id@example.com"

			# Could run a small user list: "finger username@IPAddress

		for line in $(awk "/finger/ && /open /" "./$pentest/services.txt"); do

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)

			# run check here
			finger @$ip > "./$pentest/scans/finger-"$ip"-"$port".txt"

		done

	}

	snmp_check() {

		# 161 SNMP

			# snmp-check IP_Address
			# snmpwalk -v2c -c public IP_Address 
			# snmpget -v2c -c public IP_Address 

		for line in $(awk "/snmp/ && /open /" "./$pentest/services.txt"); do

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)

			# run check here
			# Check for v1 and v2c and output results in the same file
			echo "SNMP v1:" > "./$pentest/scans/snmp-"$ip"-"$port".txt"
			echo " ---------------------------------------------------------"
			snmp-check -p $port $ip >> "./$pentest/scans/snmp-"$ip"-"$port".txt"
			echo "" >> "./$pentest/scans/snmp-"$ip"-"$port".txt"
			echo "SNMP v2c:" >> "./$pentest/scans/snmp-"$ip"-"$port".txt"
			snmp-check -p $port $ip -v2c >> "./$pentest/scans/ssl-"$ip"-"$port".txt"

		done

	}

	ntp_check() {

		# 123 NTP	
			# nmap -sU -p 123 --script ntp-info <target>
			# ntpdc -c monlist IP_ADDRESS 
			# ntpdc -c sysinfo IP_ADDRESS 

		for line in $(awk "/ntp/ && /open /" "./$pentest/services.txt"); do

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)

			# run check here
			nmap -sU -p $port --script ntp-info $ip --host-timeout 30s > "./$pentest/scans/ntp-"$ip"-"$port".tmp"
			grep "|" "./$pentest/scans/ntp-"$ip"-"$port".tmp" | cut -d "|" -f2 > "./$pentest/scans/ntp-"$ip"-"$port".txt"

		done

		rm -f "./$pentest/scans/"*".tmp"

	}

	isakmp_check() {
	
		# 500 IKE

		for line in $(awk "/isakmp/ && /open /" "./$pentest/services.txt"); do

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)

			ike-scan -M -A $ip > "./$pentest/scans/ike-"$ip"-"$port".txt"

		done

	}
	
	ssl_check() {

		# SSL (SSLScan)
		for line in $(awk "/ssl/ && /open /" "./$pentest/services.txt"); do

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)

			# run check here
			sslscan --show-certificate --no-colour $ip':'$port > "./$pentest/scans/ssl-"$ip"-"$port".txt" 2>&1
		done
	
		# Repeat for HTTPS Services
		for line in $(awk "/https/ && /open /" "./$pentest/services.txt"); do

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)

			# run check here
			sslscan --show-certificate --no-colour $ip':'$port > "./$pentest/scans/ssl-"$ip"-"$port".txt" 2>&1
		done

	}

	sub_check() {

		sublister() {

			# if sslscan is found run sublist3r
			if [ -e "./"$pentest"/scans/ssl-"$ip"-"$port".txt" ]; then
				
				# Extract domain name from sslscan
				local domainame=$(grep "Subject:" "./"$pentest"/scans/ssl-"$ip"-"$port".txt" | cut -d " " -f3)
				
				# Remove www. if present
				if [[ $domainame == "www"* ]]; then
  					local domainame=$(echo ${domainame#www.})
				fi

				# run sublist3r - check for subdomains
				sublist3r -d $domainame -o "./"$pentest"/scans/subdomains.tmp" > /dev/null 2>&1

				# Print domain name found
				echo "Domain found in Certificate: "$domainame >> "./"$pentest"/scans/dom-"$ip"-"$port".txt"
				
				# Only run if subdomains found:

				if [ -e "./"$pentest"/scans/subdomains.tmp" ]; then

					# when finished resolve IP and compare with target
					for subd in $(cat "./"$pentest"/scans/subdomains.tmp"); do
						local inconsent=$(host $subd > /dev/null 2>&1)
						local inconsent=$(echo $inconsent | grep "address" | cut -d " " -f4)
						if grep -Fxq $inconsent "./"$pentest"/targets.txt"
						then
							echo $subd" ("$inconsent")" >> "./"$pentest"/scans/dom-"$inconsent"-"$port".txt"
						fi			
					
					done

					# Clear Temp Files
					rm -f "./"$pentest"/scans/subdomains.tmp"

				fi

			fi

		}

		# Check if SSLScan result is present
		
		for line in $(awk "/ssl/ && /open /" "./$pentest/services.txt"); do

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)
			sublister

		done
	
		# Repeat for HTTPS Services
		for line in $(awk "/https/ && /open /" "./$pentest/services.txt"); do

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)
			sublister

		done

	}
	
	http_check() {

		# Create folders:

		if [ ! -d "./$pentest/screenshots" ]; then
			mkdir "./$pentest/screenshots"
		fi

		# Start non-threaded checks
		
		for line in $(awk "/http/ && /open /" "./$pentest/services.txt"); do

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)
			local realserv=$(echo $line | cut -d " " -f3)

			if [ $realserv = "ssl/http" ]; then
				local realserv="https"
			fi

			# 1. Take a screenshot of index page:
			if [ $realserv = "https" ]; then
				cutycapt --url='https://'$ip':'$port --out='./'$pentest'/screenshots/'$ip'-'$port'.png' --max-wait=1500 --insecure > /dev/null 2>&1
			else
				cutycapt --url='http://'$ip':'$port --out='./'$pentest'/screenshots/'$ip'-'$port'.png' --max-wait=1500 > /dev/null 2>&1
			fi

			# 2. Checking for robots.txt file:
			if [ $realserv = "https" ]; then
				curl -s "https://"$ip":"$port"/robots.txt" -k -m 6 -o "./$pentest/scans/http-robots-"$ip"-"$port".txt" > /dev/null 2>&1
			else
				curl -s "http://"$ip":"$port"/robots.txt" -m 6 -o "./$pentest/scans/http-robots-"$ip"-"$port".txt" > /dev/null 2>&1
			fi

			# 3. Retrieving Response Headers:
			if [ $realserv = "https" ]; then
				curl -I "https://"$ip":"$port -k -m 6 -o "./$pentest/scans/http-header-"$ip"-"$port".txt" > /dev/null 2>&1
			else
				curl -I "http://"$ip":"$port -m 6 -o "./$pentest/scans/http-header-"$ip"-"$port".txt" > /dev/null 2>&1
			fi

			# 4. Error Pages
			# echo "  - Checking for default Error pages"

			# HTTP METHODS

				# status=$(curl -Iqs -A -u https://$target:$port -i -m 30 -X TRACE | awk 'NR==1 {print $2}')
				# if [ "$status" == "200" ]; then
				# 	echo "TRACE: Seems to be Enabled"
				# fi

				# WEBDAV 
				#	List filetypes you can upload with webdav: davtest -url http://10.11.1.13
				#	To upload a file use: cadaver IP << EOF
				#	put /filename
				# 	EOF

			# BREACH

				# openssl s_client -connect example.com:443

				# GET / HTTP/1.1
				# Host: example.com
				# Accept-Encoding: compress, gzip

				# if response:

				# HTTP/1.1 200 OK
				# Server: nginx/1.1.19
				# Date: Sun, 19 Mar 2015 20:48:31 GMT
				# Content-Type: text/html
				# Last-Modified: Thu, 19 Mar 2015 23:34:28 GMT
				# Transfer-Encoding: chunked
				# Connection: keep-alive
				# Content-Encoding: gzip
				#
				# Encoded characters here!!

				# than is vulnerable


			# 4. gobuster
			# Check if Dribuster wordlist exists and assign
			if [ -e '/usr/share/gobusteruster/wordlists/directory-list-2.3-medium.txt' ]; then
                		local wordpath="/usr/share/gobusteruster/wordlists/directory-list-2.3-medium.txt"
            		else
                		local wordpath=""
            		fi

			# Check how many threads are already running
			let conto=$(pgrep gobuster | wc -l)

			# If above max threads loop for 5s
			while [ $conto -gt 20 ]; do

				sleep 5s
				let conto=$(pgrep gobuster | wc -l)

			done

			# When free thread space start new scan
			if [ $realserv = "https" ]; then
				xterm -geometry 40x15+10+40 -e "gobuster -e -u 'https://'$ip':'$port'/' -w $wordpath | tee './$pentest/scans/gobuster-'$ip'-'$port'.txt'" &
			else
				xterm -geometry 40x15+10+40 -e "gobuster -e -u 'http://'$ip':'$port'/' -w $wordpath | tee './$pentest/scans/gobuster-'$ip'-'$port'.txt'" &
			fi

			# 5. Nikto
			# Check how many threads are already running
			let conto=$(pgrep nikto | wc -l)

			# If above max threads loop for 5s
			while [ $conto -gt 20 ]; do
				
				sleep 5s
				let conto=$(pgrep nikto | wc -l)

			done

			# When free thread space start new scan
			xterm -geometry 40x15+10+40 -e "nikto -h $ip -port $port -nointeractive -output './$pentest/scans/nikto-'$ip'-'$port'.txt'" &

		done

		# Wait for all processes to finish
	
		let conto=$(pgrep nikto | wc -l)
			
		if [ $conto -gt 0 ]; then
			
			echo -e "\n [Please wait] Waiting for all Nikto scans to finish.."
			while [ $conto -gt 0 ]; do
				sleep 5s
				let conto=$(pgrep nikto | wc -l)
			done

		fi
	
		let conto=$(pgrep gobuster | wc -l)

		# Wait for all processes to finish
		if [ $conto -gt 0 ]; then

			echo -e " [Please wait] Waiting for all gobuster scans to finish.."
			while [ $conto -gt 0 ]; do
				sleep 5s
				let conto=$(pgrep gobuster | wc -l)
			done

		fi

		# Clean-up: Removing white screenshots
		find ./$pentest/screenshots/ -name *'.png' -size -5k -delete

	}

	rpc_check(){

		# For now just run nmap script

		for line in $(awk "/rpcbind/ && /open /" "./$pentest/services.txt"); do

			local ip=$(echo $line | cut -d " " -f1)
			local port=$(echo $line | cut -d " " -f2 | cut -d "/" -f1)

			# run check here
			nmap -sV -p $port $ip > "./$pentest/scans/rpc-"$ip"-"$port".txt" 2>&1
		done	

	}

	# START

	if [ ! -d ./$pentest/scans ]; then
		mkdir "./$pentest/scans"
	fi

	# Check call-function
	serv_start() {

		scount=$(awk "/$2/ && /open /" "./$pentest/services.txt" | wc -l)

		if [ $scount -gt 0 ]; then
		
		echo -e " [-] Cheking: "$1" ("$scount" found)"
		
			$3 # call function

		fi

	}

	# Checks list
	serv_start TELNET telnet telnet_check
	serv_start FTP ftp ftp_check
	serv_start SSH ssh ssh_check
	serv_start DNS domain dns_check
	serv_start SMB microsoft-ds smb_check
	serv_start FINGER finger finger_check
	serv_start SNMP snmp snmp_check
	serv_start NTP ntp ntp_check
	serv_start IKE isakmp isakmp_check
	serv_start SSL ssl ssl_check
	serv_start "SSL-TLS (HTTPS)" https ssl_check
	serv_start SUBDOMAINS ssl sub_check
	serv_start "SUBDOMAINS (2)" https sub_check
	serv_start HTTP http http_check
	serv_start RPC rpcbind rpc_check

	# End of service
	echo -e " [-] Finished checking known services"

}


logger() {

	# Create a log file
	echo -e $green"\n [+] Generating Log File"$normal
	echo " [-] Collecting information"
	echo "External Infrastructure Security Assessment - Log File" > ./$pentest/log.txt
	echo "----------------------------------------------------------" >> ./$pentest/log.txt
	echo "" >> ./$pentest/log.txt
	if [ -e "./$pentest/info.txt" ]; then
		echo "Name: "$(grep "Project" "./$pentest/info.txt" | cut -d "#" -f2) >> ./$pentest/log.txt
        echo "" >> ./$pentest/log.txt
	echo "Total Targets: "$(wc -l < ./$pentest/targets.txt) >> ./$pentest/log.txt
	echo "Live Targets: "$(wc -l < ./$pentest/live-targets.txt) >> ./$pentest/log.txt
	echo "" >> ./$pentest/log.txt

        echo "Test Started: "$(grep "START" "./$pentest/info.txt" | cut -d "#" -f2) >> ./$pentest/log.txt
        echo "Test Finished: "$(grep "END" "./$pentest/info.txt" | cut -d "#" -f2) >> ./$pentest/log.txt
        echo "" >> ./$pentest/log.txt
        echo "NMAP Timestamps:" >> ./$pentest/log.txt
        echo "" >> ./$pentest/log.txt
        echo "    TCP Scan: "$(grep "TCP" ./$pentest/info.txt | cut -d "#" -f2) >> ./$pentest/log.txt
        echo "    UDP Scan: "$(grep "UDP" ./$pentest/info.txt | cut -d "#" -f2) >> ./$pentest/log.txt
        echo "" >> ./$pentest/log.txt
	fi
	#
	echo " [-] Parsing Targets details"
	for ip in $(cat ./$pentest/targets.txt); do
	
		if grep -q $ip "./$pentest/live-targets.txt"; then
		    ipstat="Responded to PING"
		else
		    ipstat="No ICMP Response"
		fi
		
		# Extract host provider information here
		if [ -e ./$pentest/whois.txt ]; then
		    	prov=$(grep "\b"$ip"\b" ./$pentest/whois.txt | cut -d ":" -f2)
		fi
		#
			
		echo "===================================================================================" >> ./$pentest/log.txt
		echo $ip"    ICMP: "$ipstat"    Host Provider: "$prov  >> ./$pentest/log.txt 
		echo "===================================================================================" >> ./$pentest/log.txt
			
		# If no open/closed ports break loop
		if grep -q "\b"$ip"\b" "./$pentest/services.txt"; then
		    	echo "" >> ./$pentest/log.txt
		else
		    	echo "" >> ./$pentest/log.txt
			echo "All scanned ports result FILTERD. The host might be offline." >> ./$pentest/log.txt
			echo "" >> ./$pentest/log.txt
			continue
		fi		
			
		# Nmap
		echo "" >> ./$pentest/log.txt
		echo "Open Ports:" >> ./$pentest/log.txt # No open/filtered, no tcpwrapped
		echo "" >> ./$pentest/log.txt
			
		echo "" > ./$pentest/tabber.tmp
		for openport in $(grep "\b"$ip" " ./$pentest/services.txt | grep 'open ' | cut -d ' ' -f2); do
			echo $openport >> ./$pentest/tabber.tmp
        	done
        	sed -i 's/^/\t/' ./$pentest/tabber.tmp
        	awk 'NF' ./$pentest/tabber.tmp >> ./$pentest/log.txt
		echo "" >> ./$pentest/log.txt
		echo "Closed Ports:" >> ./$pentest/log.txt # inlcude not shown: closed
		echo "" > ./$pentest/tabber.tmp
        	echo "" >> ./$pentest/log.txt
        
		for closedport in $(grep "\b"$ip" " ./$pentest/services.txt | grep 'closed' | cut -d ' ' -f2); do
		
		    echo $closedport >> ./$pentest/tabber.tmp
		    
		done
		sed -i 's/^/\t/' ./$pentest/tabber.tmp
		awk 'NF' ./$pentest/tabber.tmp >> ./$pentest/log.txt
		echo "" >> ./$pentest/log.txt
		
		# Ports Loop
		for openport in $(grep "\b"$ip" " ./$pentest/services.txt | grep 'open ' | cut -d ' ' -f2); do

		    	echo "----------------------------" >> ./$pentest/log.txt 
			echo $openport " ("$(grep "\b"$ip" " ./$pentest/services.txt | grep "\b"$openport" " | cut -d ' ' -f4)")" >> ./$pentest/log.txt 
			echo "----------------------------" >> ./$pentest/log.txt
			echo "" >> ./$pentest/log.txt
				
			local cleanport=$(echo $openport | cut -d "/" -f1)
				
			locserv() {
				
				if [ -e ./$pentest/scans/$1-$ip-$cleanport.txt ]; then
					
				    echo $2":" >> ./$pentest/log.txt 
				    echo "" >> ./$pentest/log.txt 
				    cat ./$pentest/scans/$1-$ip-$cleanport.txt > ./$pentest/tabber.tmp
				    # Add tab to each line
				    sed -i 's/^/\t/' ./$pentest/tabber.tmp
				    cat ./$pentest/tabber.tmp >> ./$pentest/log.txt
				    echo "" >> ./$pentest/log.txt 
				    
				fi
				
			}
				
			# Service List (call function above which print results in log)
			locserv ntp "NTP Information"
			locserv ssh "SSH Banner"
			locserv ftp "FTP Information"
			locserv dns "DNS Information"
			locserv smb "SMB Check"
			locserv snmp "SNMP Information"
			locserv finger "FINGER Details"
			locserv ike "IKE-VPN Check"
			# HTTP Services
			locserv ssl "SSL/TLS Configuration"
			locserv http-header "HTTP Response Header"
			locserv dom "Sub-Domains"
			locserv http-robots "Robots.txt File"
			locserv nikto "NIKTO Results"
			locserv gobuster "Web Files and Directories list"
			# ...
			locserv telnet "TELNET Check"
			locserv rpc "RPC Check"

			echo "" >> ./$pentest/log.txt
		done
	done
	
	# Remove temporary files
	rm -f ./$pentest/tabber.tmp
	
	echo " [-] Log file created."

}


report() {

	# Create a full html report
	echo -e $green"\n [+] Generating HTML Report"$normal

	echo '<!DOCTYPE html><html> <head> <meta http-equiv="Content-Type" content="text/html; charset=utf-8"> <title>Oxide - Penetration Test Report</title> </head> <style>body{background: #2f4058; font-family: sans-serif; font-size: 15px; display: flex; flex-direction: row; min-height: 100vh;}#left-panel{background: #2f4058; display: flex; flex-direction: column; align-self: flex-start; min-height: 100vh; width: 25%; min-width: 250px;}#links{flex: 1;}#right-panel{background: #1b2129; align-self: flex-end; min-height: 100vh; display: flex; flex-grow: 1;}.right-content{padding-left: 30px; color: #feffff; padding-top: 10px; width: 95%;}.right-content h1{font-weight:100;}#top-title{margin-top: 20px; color: #feffff; align-self: center; text-align: center; margin-bottom: 25px; border-bottom: 1px solid #42536a; width: 90%; padding-bottom: 20px;}#top-title h1{text-align: center; font-size: 45px; margin-bottom: 0px;font-weight:100;}#top-title p{text-align: center; color: #fff; margin-top: 0px; opacity: 0.7;}.left-item{display: flex; align-self: auto; color: #92acd3; background: #2f4058; padding-top: 10px; padding-bottom: 10px; cursor: pointer; text-decoration: none; width: 100%; padding-left: 40px;}.select, .left-item:hover{background: #243348; border-bottom: 1px solid #3b4e69;}.general{font-weight: bold; font-size: 16px;}.show{display: flex; width: 100%;}.hide{display: none;}#info{margin: 0 auto; width: 100%;}#info h1{font-weight: 100;}#footer{color: #161e27; text-align: center; margin-bottom: 30px;}#footer h3{margin-bottom: 0px;}#footer span{margin: 0px; display: block; font-size: 12px; font-weight: bold;}#footer p{margin-bottom: 5px; margin-top: 0px;}.infoline{display: block; width: 100%; padding-top: 20px; padding-bottom: 20px; margin-bottom: 5px; color: #849ebf;}.tile{display: block; width: 100%; padding-top: 20px; padding-bottom: 20px; margin-bottom: 5px; color: #f0f6ff;}.tile p{color: #849ebf; margin-top: 0px; margin-bottom: 0px;}td{padding-right: 50px;}th{text-align: left; padding-bottom: 10px; padding-right: 100px; color: #849ebf;}.target h1{margin: 0px; padding: 0px;}.target h3{color: #849ebf;}.target p{margin-bottom: 5px; padding: 0px;}hr{opacity: 0.7; border-color: #2f4058;}.ports{margin-top: 50px;}.tool{width: 100%; background: #2b384b; padding: 10px; text-align: left; text-decoration: none; border: none; cursor: pointer; font-family: inherit; color: #e5f0f5; margin-top: 4px;}.activetool, .tool:hover{background: #56749f;}.module{border: 1px solid #56749f; background: #445976; padding: 20px; display: none;}.section{margin-bottom: 30px; padding-bottom: 30px; border-bottom: 1px solid #2e3e55;}.section span{font-weight: bold; color: #161d27;}.section p{font-size: 12px; color: #d5e4fa;}</style><body><div id="left-panel"> <div id="top-title"> <h1>Oxide</h1> <p>Penetration Test Report</p></div><div id="links"> <a class="left-item select" data="info" href="#">Details</a>' > ./$pentest/$pentest-Report.html

	# Add targets to the left menu
	for ip in $(cat ./$pentest/targets.txt); do
		echo '<a class="left-item" data="'$ip'" href="#">'$ip'</a>' >> ./$pentest/$pentest-Report.html
	done
	
	echo '</div><div id="footer"><h3>Oxide</h3><p>Penetration Test Wrapper Tool</p><span>Version: 1.0.1</span> <span>Author: W315 (2019)</span></div></div><div id="right-panel"> <div id="info" name="info" class="show"><div class="right-content"><h1>Test Information</h1><hr><table class="tile"><tr><td><p><b>Test Name:</b></p></td>' >> ./$pentest/$pentest-Report.html

	# Add title
	echo '<td>'$(grep "Project" "./$pentest/info.txt" | cut -d "#" -f2)'</td>' >> ./$pentest/$pentest-Report.html

	# Add time of test
	echo '</tr></table><table class="tile"><tr><td><p>Test Started:</p></td>' >> ./$pentest/$pentest-Report.html
	echo '<td>'$(grep "START" "./$pentest/info.txt" | cut -d "#" -f2)'</td>' >> ./$pentest/$pentest-Report.html
	echo '</tr><tr><td><p>Test Finished:</p></td>' >> ./$pentest/$pentest-Report.html
	echo '<td>'$(grep "END" "./$pentest/info.txt" | cut -d "#" -f2)'</td>' >> ./$pentest/$pentest-Report.html

	# Nmap Timestamp
	echo '</tr></table><table class="tile"><tr><th>Nmap Timestamp:</th><th>Started-Finished:</th></tr><tr><td>TCP Scan: (all ports)</td>' >> ./$pentest/$pentest-Report.html
	echo '<td>'$(grep "TCP" ./$pentest/info.txt | cut -d "#" -f2)'</td>' >> ./$pentest/$pentest-Report.html
	echo '</tr><tr><td>UDP Scan: (top 200 ports)</td>' >> ./$pentest/$pentest-Report.html
	echo '<td>'$(grep "UDP" ./$pentest/info.txt | cut -d "#" -f2)'</td>' >> ./$pentest/$pentest-Report.html

	# Number of targets
	echo '</tr></table> <table class="tile"><tr><td><p>Number of Targets:</p></td>' >> ./$pentest/$pentest-Report.html
	echo '<td>'$(wc -l < ./$pentest/targets.txt)'</td>' >> ./$pentest/$pentest-Report.html

	echo '</tr><tr><td><p>Responded to ICMP:</p></td>' >> ./$pentest/$pentest-Report.html
	echo '<td>'$(wc -l < ./$pentest/live-targets.txt)'</td>' >> ./$pentest/$pentest-Report.html

	# Number of services
	echo '</tr><tr><td><p>Number of OPEN Services:</p></td>' >> ./$pentest/$pentest-Report.html
	echo '<td>'$(cat ./$pentest/services.txt | grep "open" | wc -l)'</td>' >> ./$pentest/$pentest-Report.html

	# Whois
	echo '</tr></table><hr><table class="tile"><tr><th>IP Address:</th><th>Registered Owner:</th></tr>' >> ./$pentest/$pentest-Report.html

	for ip in $(cat ./$pentest/targets.txt); do
		echo '<tr><td>'$ip'</td><td>'$(grep "\b"$ip"\b" ./$pentest/whois.txt | cut -d ":" -f2)'</td></tr>' >> ./$pentest/$pentest-Report.html
	done

	echo '</table></div></div>' >> ./$pentest/$pentest-Report.html

	# IP Details
	for ip in $(cat ./$pentest/targets.txt); do

		# Check for ICMP
		if grep -Fxq $ip ./$pentest/live-targets.txt
		then
		    icmpen="Enabled"
		else
		    icmpen="Disabled"
		fi

		echo '<div id="'$ip'" class="hide"><div class="right-content"><div class="target"><p>IP Address:</p><h1>'$ip'</h1><table class="infoline"><tr><td><b>ICMP:</b> '$icmpen'</td><td><b>Owner:</b> '$(grep "\b"$ip"\b" ./$pentest/whois.txt | cut -d ":" -f2)'</td><td><b>Firewall Misc:</b> '$(grep "\b"$ip"\b" ./$pentest/firewall-misc.txt | cut -d " " -f2,3,4)'</td><td><b>Services Available:</b> '$(grep "\b"$ip"\b" ./$pentest/services.txt | grep "open" | wc -l)'</td></tr></table><hr><h3>Services:</h3><table><tr><th>Port:</th><th>Type:</th><th>Status:</th></tr>' >> ./$pentest/$pentest-Report.html

		# Ports / Status
		IFS=$'\n'
		for line in $(grep "\b"$ip" " ./$pentest/services.txt); do

			echo '<tr><td>'$(echo $line | cut -d ' ' -f2)'</td><td>'$(echo $line | cut -d ' ' -f4)'</td><td>'$(echo $line | cut -d ' ' -f3)'</td></tr>' >> ./$pentest/$pentest-Report.html

		done

		echo '</table><div class="ports">' >> ./$pentest/$pentest-Report.html

		# Services
		for openport in $(grep "\b"$ip" " ./$pentest/services.txt | grep 'open ' | cut -d ' ' -f2); do

		    	echo '<button class="tool">'$openport' ('$(grep "\b"$ip" " ./$pentest/services.txt | grep "\b"$openport" " | cut -d ' ' -f4)')</button>' >> ./$pentest/$pentest-Report.html
			local cleanport=$(echo $openport | cut -d "/" -f1)
			echo '<div class="module">' >> ./$pentest/$pentest-Report.html
							
			locservr() {
				
				if [ -e ./$pentest/scans/$1-$ip-$cleanport.txt ]; then
					
					# Format output				    
					cat ./$pentest/scans/$1-$ip-$cleanport.txt > ./$pentest/tabber.tmp
					# sed -i 's/^/\t/' ./$pentest/tabber.tmp  <-- used to add tab
					sed -i 's/[<>]//g' ./$pentest/tabber.tmp
					sed -i 's/$/<br>/' ./$pentest/tabber.tmp

					echo '<div class="section"><span>'$2':</span><p>'$(cat ./$pentest/tabber.tmp)'</p></div>' >> ./$pentest/$pentest-Report.html
					rm ./$pentest/tabber.tmp 
 
				fi

				if [ -e './'$pentest'/screenshots/'$ip'-'$cleanport'.png' ]; then
					echo '<div class="section"><span>Screenshoot:</span><img src="screenshots/'$ip'-'$cleanport'.png"></div>' >> ./$pentest/$pentest-Report.html
				fi
				
				
			}
	
			# Service List (call function above which print results in log)
			locservr ntp "NTP Information"
			locservr ssh "SSH Banner"
			locservr ftp "FTP Information"
			locservr dns "DNS Information"
			locservr smb "SMB Check"
			locservr snmp "SNMP Information"
			locservr finger "FINGER Details"
			locservr ike "IKE-VPN Check"
			# HTTP Services
			locservr ssl "SSL/TLS Configuration"
			locservr http-header "HTTP Response Header"
			locservr dom "Sub-Domains"
			locservr http-robots "Robots.txt File"
			locservr nikto "NIKTO Results"
			locservr gobuster "Web Files and Directories list"
			# ...
			locservr telnet "TELNET Check"
			locservr rpc "RPC Check"

			echo '</div>' >> ./$pentest/$pentest-Report.html

		done
		echo '</div></div></div></div>' >> ./$pentest/$pentest-Report.html

	done

	# END

	echo '</div></body><script>var ips=document.getElementsByClassName("left-item"),cch=document.getElementsByClassName("select");for(i=0;i<ips.length;i++)ips[i].addEventListener("click",function(){cch[0].classList.remove("select"),this.classList.toggle("select")});for(var showRightContent=function(){for(var e=document.getElementById("right-panel").childNodes,t=0;t<e.length;t++)e[t].className="hide";var s=this.getAttribute("data");document.getElementById(s).className="show"},i=0;i<ips.length;i++)ips[i].addEventListener("click",showRightContent,!1);var cca=document.getElementsByClassName("tool");for(i=0;i<cca.length;i++)cca[i].addEventListener("click",function(){this.classList.toggle("activetool");var e=this.nextElementSibling;"block"===e.style.display?e.style.display="none":e.style.display="block"});</script></html>' >> ./$pentest/$pentest-Report.html

	# Remove temporary files
	rm -f ./$pentest/tabber.tmp

	echo " [-] Finished generating report ("$(stat --printf="%s" ./$pentest/$pentest-Report.html)" bytes)"
	echo " [-] Saved as: "$pentest"-Report.html"
	
}

theend() {

	echo -e $green"\n [+] DONE"$normal
	echo " [-] Time Started: "$(grep "START" ./$pentest/info.txt | cut -d "#" -f2)
	echo " [-] Time Finished: "$(grep "END" ./$pentest/info.txt | cut -d "#" -f2)
	echo

	# Cleanup
	rm ./$pentest/info.txt
	rm ./$pentest/dead-targets.txt
	rm ./$pentest/live-targets.txt
	rm ./$pentest/services.txt
	mv ./$pentest/whois.txt ./$pentest/scans/whois.txt
	mv ./$pentest/firewall-misc.txt ./$pentest/scans/firewall-misc.txt

}

# Main Functions
banner() { 

	clear
	echo -e $green
	echo -e " O X I D E"
	echo -e $normal
	
}

usage() {

	banner
	echo " v 1.1.3"
	echo " by W315 (2019) https://github.com/weissec"
	echo
	echo " Options:     Description:"
	echo " -------------------------------------------------------------"
	echo " -h           Display this help menu"
	echo " -n [name]    Create a new project with the given name"
	# echo " -r [name]    Resume an existing test"
	# echo " -c [file]    Resolve CIDR Ranges to a list of IPs (input: targets file)"
	# echo " -w [file]    Perform a whois check for targets in file (input: targets file)"
	# echo " -p [file]    Only perform a ping sweep to check live targets (input: targets file)" 
	echo " -d           Debug, run a compatibility check"
	echo
	echo " usage: ./Oxide.sh -n [name]"
	echo

}

# Install required packages
required () {
	
	echo -e $yellow" [Compatibility Issue Found] \n"$normal
	echo " This script requires the following package to run: "$1
	echo " Install the required packages? (y/n)"
	read -p " > " yesno
	echo
	if [[ $yesno == "y" ]] || [[ $yesno == 'Y' ]]; then
		apt-get install $2
	else
		echo " Aborting script.."
		exit
	fi
	echo
	echo " ------------------------------------------ \n"
	echo " Required component successfully installed."
	echo " Reloading script.."
	sleep 2s
	debug
}

# Debugger
debug() {
	banner
	echo ' # Running Debugger. Please wait.. '

	# Check for nmap
	which nmap > /dev/null 2>&1
	if [ "$?" != 0 ]; then
		required Nmap nmap
	fi
	# Check for gobuster
	which gobuster > /dev/null 2>&1
	if [ "$?" != 0 ]; then
		required Gobuster gobuster
	fi
	# Check for Nikto
	which nikto > /dev/null 2>&1
	if [ "$?" != 0 ]; then
		required Nikto nikto
	fi
	# Check for SSL Scan
	which sslscan > /dev/null 2>&1
	if [ "$?" != 0 ]; then
		required SSL-Scan sslscan
	fi
	# Check for Cutycapt
	which cutycapt > /dev/null 2>&1
	if [ "$?" != 0 ]; then
		required Cutycapt cutycapt
	fi
	# Check for ike-scan
	which ike-scan > /dev/null 2>&1
	if [ "$?" != 0 ]; then
		required IKE-Scan ike-scan
	fi
	# Check for xterm
	which xterm > /dev/null 2>&1
	if [ "$?" != 0 ]; then
		required Xterm xterm
	fi
	# Check for Sublist3r
	which sublist3r > /dev/null 2>&1
	if [ "$?" != 0 ]; then
		required Sublist3r sublist3r
	fi
	# Check if ROOT
	if [ $(id -u) != "0" ]; then
		echo -e $red" [ERROR] This script must be run with root privileges. \n"$normal
		exit
	fi
	# Check if Internet Connection active
	ping -c 1 -w 3 www.google.com > /dev/null 2>&1
	if [[ $? != '0' ]]; then
	  	echo -e $yellow" [WARNING] Possible Network Error - no connection detected. \n"$normal
	fi
	# Check if BASH
	if [[ $(ps -p $$ | grep bash | wc -l) = '0' ]]; then
		echo -e $red" [ERROR] This script must be run with BASH (sh, dash are not supported) \n"$normal
		exit
	fi
	echo -e " # Check completed: the tool is ready to run \n"
}

testrun() {

	debugger
	setpj
	echo "START#"$(date "+%H:%M %d/%m/%Y") >> "./$pentest/info.txt"
	formatter
	alive
	whoown
	nmapscan
	services
	tester
	echo "END#"$(date "+%H:%M %d/%m/%Y") >> "./$pentest/info.txt"
	logger
	report
	theend

}

# Start

unset pentest

while getopts "h:n:i:r:w:p:d" option; do
	case "${option}" in
    		n) pentest=${OPTARG}; testrun;;
	    	r) usage;;
	    	w) usage;;
	    	p) usage;;
	    	d) debug; exit;;
	    	h) usage; exit;;
	    	*) usage; exit;;
 	esac
done

if [[ $# = 0 ]]; then
	usage
	exit
fi
