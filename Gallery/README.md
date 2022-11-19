# Walkthrough: Gallery

## General Enumeration

### NMAP

Before going anywhere, we need to discover what ports are open on this machine and see what services are being hosted. To do this, we conduct an `NMAP` scan as shown below.

Command:

```bash
nmap -sC -sV -A -O -T4 -oN nmap/initial $TARGET
```

Output

```bash
Host is up (0.12s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
8080/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Simple Image Gallery System
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=3/20%OT=80%CT=1%CU=33660%PV=Y%DS=4%DC=T%G=Y%TM=6237936
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=103%TI=Z%CI=Z%TS=A)SEQ(SP=FF
OS:%GCD=1%ISR=103%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O3=
OS:M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11NW6%O6=M506ST11)WIN(W1=F4B3%W2=F4
OS:B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M506NNSNW6
OS:%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=
OS:Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%
OS:RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIP
OS:CK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)
```

The port `8080` looks interesting, because there is `http-title: Simple Image Gallery System` and port `80` looks like an `Apache` web server's generic "Welcome" page. 

## Web Enumeration

Navigating to `http://$TARGET:8080`, we are redirected to `http://$TARGET/gallery/login.php`. It appears as if `8080` is, indeed, a proxy that proxys our traffic to a route on `80`. Now that we know there is an `http://$TARGET/gallery/` location, we can scan it using both `Nikto` and `Gobuster`.

### Nikto

To conduct a `Nikto` scan on `http://$TARGET/gallery`, run the following command.

Command:

```bash
nikto -h http://$TARGET/gallery/ -output nikto/gallery_scan.txt
```

Output:

```bash
- Nikto v2.1.6/2.1.5
+ Target Host: $TARGET
+ Target Port: 80
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ GET Cookie PHPSESSID created without the httponly flag
+ HEAD /gallery: Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
+ OLHMURIR Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ GET /gallery/config.php: PHP Config file may contain database IDs and passwords.
+ OSVDB-3268: GET /gallery/database/: Directory indexing found.
+ OSVDB-3093: GET /gallery/database/: Databases? Really??
```

### Gobuster

To conduct a `Gobuster` scan on the target run the following command.

Command:

```bash
gobuster dir -u http://$TARGET/gallery/ -w <wordlist_path> -o gobuster/gallery
```

Output:

```bash
/index.php            (Status: 200) [Size: 16844]
/home.php             (Status: 500) [Size: 0]
/archives             (Status: 301) [Size: 321] [--> http://10.10.193.1/gallery/archives/]
/login.php            (Status: 200) [Size: 7995]
/user                 (Status: 301) [Size: 317] [--> http://10.10.193.1/gallery/user/]
/uploads              (Status: 301) [Size: 320] [--> http://10.10.193.1/gallery/uploads/]
/assets               (Status: 301) [Size: 319] [--> http://10.10.193.1/gallery/assets/]
/report               (Status: 301) [Size: 319] [--> http://10.10.193.1/gallery/report/]
/albums               (Status: 301) [Size: 319] [--> http://10.10.193.1/gallery/albums/]
/plugins              (Status: 301) [Size: 320] [--> http://10.10.193.1/gallery/plugins/]
/database             (Status: 301) [Size: 321] [--> http://10.10.193.1/gallery/database/]
/classes              (Status: 301) [Size: 320] [--> http://10.10.193.1/gallery/classes/]
/config.php           (Status: 200) [Size: 0]
/dist                 (Status: 301) [Size: 317] [--> http://10.10.193.1/gallery/dist/]
/inc                  (Status: 301) [Size: 316] [--> http://10.10.193.1/gallery/inc/]
/build                (Status: 301) [Size: 318] [--> http://10.10.193.1/gallery/build/]
/schedules            (Status: 301) [Size: 322] [--> http://10.10.193.1/gallery/schedules/]
/create_account.php   (Status: 200) [Size: 8]
```

From the resuls of both `Gobuster` and `Nikto`, we know the site is using `PHP` to render pages. This may come in handy in the future... This still, however, does not give much of an attack surface. 

### Manual

Sometimes the best way to figure out how a website works is to play with it manually. By using either `BurpSuite` (or similar tool) or just using the developer tools builtin to your web browser and observing the traffic, you can get a better understanding of what is going on. After attempting logins using various common defaults (admin:admin, admin:password, root:toor, etc) and observing the traffic, we can see that the "Sign In" button causes a request to `Login.php?f=login`.  This may give us a better understanding of what is going on, but it is still not an opening we can attack.

Next, let's look at the source of the login page. Looking at the source can be helpful as you may find some files you would not have known existed had you not looked (ex: javascript files with potentially seinsitive information or clues on vulnerabilities). Unfortunately, nothing of real interest is present here either.

One last manual attempt is SQL injection (SQLi) on the login page. (*Note: this part does not have to be manual as tools like sqlmap can conduct it for you*). Assuming `admin` is a good username, we can attempt the basic `' or 1=1` attacks. After attempting `' or 1=1;--` and `" or 1=1;--` and their equivalents using `#` as a comment character,  maybe they are taking the hash of the password and searching for it in one go, so we can try `') or 1=1`. Using this format, we get a successful login with `') OR 1=1;#`. 

## Foothold.go

The `GenRevShell` function creates a `PHP` file that is designed to reach out to a C2 server and pull down an attacker-specified file. This was tested with an `MSFVENOM` payload and successfully opened up a connection to the attack machine. The payload used was `linux/x86/meterpreter/reverse_tcp`. The attacker, however, should be able to execute any linux binary or shell script using this automated script, because it changes the mode of the file to `executable` via the `chmod +x` command. If uploading a `python` or `sh` script, remember to put the shebang line on top (`#!/bin/python` or `#!/bin/bash`) so the script can execute without error.

