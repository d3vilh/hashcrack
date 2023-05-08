#!/bin/bash
# hashcrack - Lightweight Hashcat automatisation
# v.0.3 + hash format change; + save the CRACKED logfile #v.0.2 #names added
# By Mr.Philipp 24.10.2020 
bold=$(tput bold); blue=$(tput setaf 4); normal=$(tput sgr0); black=$(tput setaf 0); red=$(tput setaf 1); green=$(tput setaf 2); yellow=$(tput setaf 3); lime_yellow=$(tput setaf 190); powder_blue=$(tput setaf 153); magenta=$(tput setaf 5); cyan=$(tput setaf 6); white=$(tput setaf 7); bright=$(tput bold); blink=$(tput blink); reverse=$(tput smso); underline=$(tput smul);

# Help information:
if [ ! -n "$1" ]; then 
	printf "\n ${reverse}${bold} (◕‿‿◕) HAshCRack v.0.3 ${normal}\n         Helps to brute ${lime_yellow}${bold}HASHES${normal} in different modes (by default mode 22000, for WPA-PBKDF2-PMKID+EAPOL used).\n
	 ${bold}${lime_yellow}TO CONVERT .pcap INTO 22000:${normal}
	 ${powder_blue}Usage:${normal} hcxpcapngtool -o \042resulted 22000 file\042 \042Source tracefile\042
	 ${powder_blue}Example:${normal} ${bold}hcxpcapngtool -o TimeCapsule.hc22000 TimeCapsule.pcap${normal}\n
	 ${bold}${lime_yellow}FOR MOBILE NUMBERS:${normal}
	 ${powder_blue}Usage:${normal} ./hashcrack.sh \042filename\042 \042Country code\042 \042Mode to use\042
	 ${powder_blue}Example:${normal} ${bold}./hashcrack.sh FriendWiFi.hccapx UA 22000${normal}\n
	   ${bold}${lime_yellow}Awailable codes:${normal}
	   ${powder_blue}UA${normal} - Ukraine Mobile MSISDNs
	   ${powder_blue}CY${normal} - Cyprus Mobile MSISDNs\n
	   ${bold}${lime_yellow}Awailable WiFi Modes:${normal}
	   ${powder_blue}22000${normal} - WPA-PBKDF2-PMKID+EAPOL
	   ${powder_blue}22001${normal} - WPA-PMK-PMKID+EAPOL

	 ${bold}${lime_yellow}FOR DATE BASED BRUTE (all dates 1772-2050y):${normal}
	 ${powder_blue}Usage:${normal} ./hashcrack.sh \042filename\042 \042DATE\042 \042Mode to use\042
	 ${powder_blue}Example:${normal} ${bold}./hashcrack.sh FriendWiFi.hccapx DATE ${normal}

	 ${bold}${lime_yellow}FOR DICTIONARY BASED BRUTE:${normal}
	 ${powder_blue}Usage:${normal} ./hashcrack.sh \042filename\042 \042Dictionary code\042 \042Mode to use\042
	 ${powder_blue}Example:${normal} ${bold}./hashcrack.sh FriendWiFi.hccapx 4800 ${normal}\n
	 ${bold}${lime_yellow}  Awailable Dictionary codes:${normal}
	 ${powder_blue}  letter${normal} - Most-Popular-Letter-Passes (47,603 lines + 30 rules(R4) = 38,558,430 matches) 1:33
	 ${powder_blue}  4800${normal} - probable-v2-wpa-top4800 (4,799 lines + 30 rules(R4) = 3,888,000 matches) 1:39
	 ${powder_blue}  204k${normal} - Top204Thousand-WPA-probable-v2 (203,806 lines + 13 rules(R3) = 9,171,270 matches) 1:39
	 ${powder_blue}  key${normal} - Keyboard-Combinations (9,604 lines + 30 rules(R4) = 7,779,240 matches) 02:40
	 ${powder_blue}  10m${normal} - 10-million-password-list-top-1000000 (999,998 lines + 13 rules(R3) = 44,999,910 matches) 3:47
	 ${powder_blue}  mil${normal} - milw0rm-dictionary (84,195 lines + 30 rules(R4) = 68,197,950 matches) 05:29
	 ${powder_blue}  DATE${normal} - dates.txt (1,019,030 uniq names + 13 rules(R3) = 45,856,350 matches) 7:15
	 ${powder_blue}  100k${normal} - 100k-most-used-passwords-NCSC (100,000 lines + 30 rules(R4) = 80,991,900 matches) 07:29
	 ${powder_blue}  rock${normal} - rockyou (14,344,391 lines +5 rules(R1) = 71,721,920 matches) 7:42
	 ${powder_blue}  NAMES${normal} - NAMES_v.0.3.txt (160,660 uniq names + 30 rules(R4) = 130,134,600 matches) 9:05
	 ${powder_blue}  phu${normal} - ph-universal-1361171. All above - rock, DATE, UA, CY (1,361,171 lines + 30 rules(R4) = 11,102,540,410 matches) 2h 41m \n
	 ${bold}${red}If Mode not passed!${normal} The default mode = 22000 will be used.
	 ${bold}${red}WITHOUT DICT CODE I WILL DO THE GALAXY BRUTE!${normal} This will take lot of time (all dicts one by one). \n\n"; 
	exit; 
fi;

# Filename in hash format 22000  # to convert pcap into 22000: hcxpcapngtool -o TimeCapsule.hc22000 TimeCapsule.pcap
hash2know=$1;

# Dictionary to run from the list below
pdictionary=$2;
if [ ! -n "$2" ]; then pdictionary=GALAXY ; fi
# Module to use with hashcat
hmodule=$3;

# Create the Logs directory if not exists
if [ ! -d logs ]; then mkdir logs 2>/dev/null ; fi

# Define the processing logfile
logfile=$(pwd)/logs/hash.$pdictionary.log

# Cleanup the latest logfile
echo "" > $logfile

# Using default module 22000 if it was not passed
if [ ! -n "$3" ]; then hmodule=22000 ; fi

# Timer in s for periodic logfile update
status_timer=180
# hashcat stsus options
hstatus="--status --status-timer=$status_timer"

# common rules
common_rule1="-r ./rules/c_att.rule"
common_rule2="-r ./rules/symbols.rule"
common_rule3="-r ./rules/symbols.rule -r ./rules/c_att.rule"
common_rule4="-r ./rules/symbols.rule -r ./rules/c_att.rule -r ./rules/numbers.rule"

# MSISDN/Mobile numbers template for Ukraine:
ua_template=(
  "3809?d?d?d?d?d?d?d?d?d"
  "38039?d?d?d?d?d?d?d"
  "38050?d?d?d?d?d?d?d"
  "38063?d?d?d?d?d?d?d"
  "38066?d?d?d?d?d?d?d"
  "38067?d?d?d?d?d?d?d"
  "38068?d?d?d?d?d?d?d"
  "09?d?d?d?d?d?d?d?d"
  "039?d?d?d?d?d?d?d"
  "050?d?d?d?d?d?d?d"
  "063?d?d?d?d?d?d?d"
  "066?d?d?d?d?d?d?d"
  "067?d?d?d?d?d?d?d"
  "068?d?d?d?d?d?d?d"
)
# MSISDN/Mobile numbers template for Cyprus:
cy_template=(
  "94?d?d?d?d?d?d"
  "95?d?d?d?d?d?d"
  "96?d?d?d?d?d?d"
  "97?d?d?d?d?d?d"
  "99?d?d?d?d?d?d"
  "35794?d?d?d?d?d?d"
  "35795?d?d?d?d?d?d"
  "35796?d?d?d?d?d?d"
  "35797?d?d?d?d?d?d"
  "35799?d?d?d?d?d?d"
)

# Report before Run
printf "\n(◕‿‿◕) Processing ${powder_blue}${bold}$hash2know${normal} with ${powder_blue}${bold}$pdictionary${normal} dictionary and ${powder_blue}${bold}$hmodule${normal} mode.\n       For progress run in other console:\n       ${bold}tail -30f $logfile${normal}\n\n       Hit ${bold}Enter${normal} here to update tailed progress file.\n\n"

# Dictionaries List
case $pdictionary in
	UA ) `for template in "${ua_template[@]}"; do hashcat $hstatus -m $hmodule -a3 $hash2know $template >> $logfile; done`;;
	CY ) `for template in "${cy_template[@]}"; do hashcat $hstatus -m $hmodule -a3 $hash2know $template >> $logfile; done`;;
#	DATE ) printf "\nThis doesnt work, my dude (°▃▃°)\n\n";; 
	key ) `hashcat $hstatus -m $hmodule $hash2know $common_rule4 ./dict/Keyboard-Combinations.txt > $logfile`;;
	4800 ) `hashcat $hstatus -m $hmodule $hash2know $common_rule4 ./dict/probable-v2-wpa-top4800.txt > $logfile`;;
	DATE ) `hashcat $hstatus -m $hmodule $hash2know $common_rule3 ./dict/dates.txt > $logfile`;;
	letter ) `hashcat $hstatus -m $hmodule $hash2know $common_rule4 ./dict/Most-Popular-Letter-Passes.txt > $logfile`;;
	mil ) `hashcat $hstatus -m $hmodule $hash2know $common_rule4 ./dict/milw0rm-dictionary.txt > $logfile`;;
	100k ) `hashcat $hstatus -m $hmodule $hash2know $common_rule4 ./dict/100k-most-used-passwords-NCSC.txt > $logfile`;;
	204k ) `hashcat $hstatus -m $hmodule $hash2know $common_rule3 ./dict/Top204Thousand-WPA-probable-v2.txt > $logfile`;; 
	10m ) `hashcat $hstatus -m $hmodule $hash2know $common_rule3 ./dict/10-million-password-list-top-1000000.txt > $logfile`;;
	rock ) `hashcat $hstatus -m $hmodule $hash2know $common_rule1 ./dict/rockyou.txt > $logfile`;;
	ph ) `hashcat $hstatus -m $hmodule $hash2know $common_rule4 ./dict/hotmail_ph.txt > $logfile`;;
	NAMES ) `hashcat $hstatus -m $hmodule $hash2know $common_rule4 ./dict/NAMES_v.0.3.txt > $logfile`;;
	phu ) `hashcat $hstatus -m $hmodule $hash2know $common_rule4 ./dict/ph-universal-1361171.txt > $logfile`;; 
	GALAXY ) `for template in "${ua_template[@]}"; do hashcat $hstatus -m $hmodule -a3 $hash2know $template > $logfile; done`;`for template in "${cy_template[@]}"; do hashcat $hstatus -m $hmodule -a3 $hash2know $template > $logfile; done`;`hashcat $hstatus -m $hmodule $hash2know ./dict/Keyboard-Combinations.txt > $logfile`;`hashcat $hstatus -m $hmodule $hash2know $common_rule4 ./dict/probable-v2-wpa-top4800.txt > $logfile`;`hashcat $hstatus -m $hmodule $hash2know $common_rule2 ./dict/dates.txt > $logfile`;`hashcat $hstatus -m $hmodule $hash2know $common_rule3 ./dict/Most-Popular-Letter-Passes.txt > $logfile`;`hashcat $hstatus -m $hmodule $hash2know $common_rule3 ./dict/milw0rm-dictionary.txt > $logfile`;`hashcat $hstatus -m $hmodule $hash2know $common_rule3 ./dict/100k-most-used-passwords-NCSC.txt > $logfile`;`hashcat $hstatus -m $hmodule $hash2know $common_rule1 ./dict/Top204Thousand-WPA-probable-v2.txt > $logfile`;`hashcat $hstatus -m $hmodule $hash2know $common_rule1 ./dict/10-million-password-list-top-1000000.txt > $logfile`;`hashcat $hstatus -m $hmodule $hash2know $common_rule1 ./dict/rockyou.txt > $logfile`;`hashcat $hstatus -m $hmodule $hash2know $common_rule4 ./dict/hotmail_ph.txt > $logfile`;`hashcat $hstatus -m $hmodule $hash2know $common_rule4 ./dict/NAMES_v.0.3.txt > $logfile`;;
esac

# Report after Run
if grep -q "found" $logfile; then
  printf "${bold}        _____ _____ _____ _____ _____ _____ ____  \n       |     | __  |  _  |     |  |  |   __|    \ \n       |   --|    -|     |   --|    -|   __|  |  |\n       |_____|__|__|__|__|_____|__|__|_____|____/ ${normal}\n"
  found=$(hashcat -m $hmodule $1 --show | tail -1 | awk -F ':' '{ print $(NF-1)":"$NF }')
  printf "       ${reverse}${bold}$found${normal}\n\n(♥‿‿♥) Cracked password saved in:\n       ${bold}./cracked/$1.$pdictionary.CRACKED.log${normal}\n\n"
  if [ ! -d cracked ]; then mkdir cracked 2>/dev/null ; fi
  hashcat -m $hmodule $1 --show > ./cracked/$1.$pdictionary.CRACKED.log
else
  notfound=$(grep Status $logfile | awk -F ': ' '{print $2}'| tail -1)
  printf "( ⚆_⚆) Completed with status: ${bold}$notfound${normal}\n       Dictionary ${bold}$pdictionary${normal} used.\n       Try once more with other dictionary!\n\n"
fi

#thats all folks!
