#!/usr/bin/env python3
############################################################
# This script is designed to brute force the key needed
# to execute the program pulled from the FTP server without
# error, extract the decoded message from the output, and
# decode the message for the user. 
#
# This will require files pulled down from the target after
# completing certain tasks. Two specific files are needed
# in order for this script to do its job: (1) the program
# from the FTP server, (2) a wordlist to use for the brute
# force attack.
#
# The user must also put the program in the same directory
# as this script and mark the program as executable, so it
# can run and be brute forced.
############################################################

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


def gen_words(wordlist):
    message = str()
    success = bool()

    try:
        with open(wordlist) as fptr:
            for word in fptr:
                yield word
        message = "wordlist looped through successfully"
        success = True
    except Exception as ex:
        message = str(ex)
        success = False

    return (success, message)


def port_type(portno):
    portno = int(portno)

    if (portno < 1) or (portno > 65535):
        raise argparse.ArgumentError("Port must be within range 1 - 65535.")

    return portno

def brute_program(wlgen):
    decoded = str()
    encoded = str()
    message = str()
    success = bool()

    try:
        for word in wlgen:
            word = word.replace("\n","")
            SysMsgNB(f"Attempting {word}")
            output = os.popen(f"./program {word}").read()
            if "Incorrect" not in output:
                SucMsg(f"Password Found: {word}")
                message = "password found"
                success = True
                break

        if not(success):
            raise ValueError("unable to find password")

        SysMsgNB("Searching for encoded message")
        pattern = "Decode This.*".lower()
        r = re.compile(pattern)
        matches = r.findall(output.lower())
        encoded = matches[0].split("=>")[1]

        message = "message successfully discovered"
        success = True
    except Exception as ex:
        encoded = ""
        message = str(ex)
        success = False

    return (encoded, success, message)

def decode_message(message):
    decodeDict = {
            "2": ["a","b","c"],
            "3": ["d","e","f"],
            "4": ["g","h","i"],
            "5": ["j","k","l"],
            "6": ["m","n","o"],
            "7": ["p","q","r","s"],
            "8": ["t","u","v"],
            "9": ["w","x","y","z"]
    }

    decodedLst = list()

    if isinstance(message,str):
        message = message.split(" ")
        message.remove("")

    try:
        for seq in message:
            key = seq[0]
            tap = len(seq) - 1
            decodedLst.append(decodeDict[key][tap])
        decoded = "".join(decodedLst)
        message = "message successfully decoded"
        success = True
    except Exception as ex:
        decoded = str()
        message = str(ex)
        success = False

    return (decoded, success, message)

def main():
    if platform.system().lower() == "windows":
        os.system("")
    
    parser = argparse.ArgumentParser()

    ############################################################
    # Setup required command-line arguments.
    ############################################################
    parser.add_argument("wordlist", help="worslist to use for brute force.", type=str)

    args = parser.parse_args()

    wordlist = args.wordlist

    InfoMsg(f"Wordlist: {wordlist}")

    try:
        wordgen = gen_words(wordlist)
        encoded, success, message = brute_program(wordgen)
        if not(success):
            raise ValueError(message)
        SucMsg(f"Message: {encoded}")

        decoded, success, message = decode_message(encoded)
        if not(success):
            raise ValueError(message)
        SysMsg(f"Decoded Message: {decoded}")
    except Exception as ex:
        ErrMsg(str(ex))

    return

if __name__ == "__main__":
    main()

