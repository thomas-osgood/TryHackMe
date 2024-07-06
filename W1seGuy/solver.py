import re
import string

def main():
    # all characters that can make up the key. this information was extracted
    # from the source code.
    alphabet = string.ascii_letters + string.digits
    exitcond = False
    firstfour = "THM{"
    # regular expression pattern used to determine if key has been found
    flagpat = "^THM{[a-zA-Z0-9]+}$" 
    # this is found in the source code "random.choice(..., k=5)"
    keylen = 5 
    while not(exitcond):
        try:
            # get encrypted hex value from user. this will be what is spit out by
            # the target when you connect to it.
            inp = input("Enter encrypted value: ")
            if inp.lower().strip() == "exit":
                break
            stage1 = bytes.fromhex(inp).decode("utf-8")

            # calculate the partial key based on known info (the format of the flag)
            partialkey = str()
            for i in range(0,len(firstfour)):
                partialkey += chr(ord(stage1[i]) ^ ord(firstfour[i%5]))

            # brute force the key and flag by using regular expression matching.
            # this will loop through all possible values for the 5th letter in 
            # the key, XOR the "encrypted" string and see if it has been decrypted.
            flag = str()
            testkey = str()
            searcher = re.compile(flagpat)
            for letter in alphabet:
                testkey = f"{partialkey}{letter}"

                # decrypt the string.
                testres = str()
                for i in range(0,len(stage1)):
                    testres += chr(ord(stage1[i]) ^ ord(testkey[i%keylen]))

                # test for correct decryption. if a match has been found, set the
                # key and flag values and break the loop.
                matches = searcher.findall(testres)
                if len(matches) > 0:
                    flag = matches[0]
                    key = testkey
                    break
            
            # if no key matches have been discovered, raise an error.
            if len(key) < 1:
                raise ValueError("no key found")

            # display flag and key values
            print(f"key (hex): {key.encode().hex()}")
            print(f"key (ascii): {key}")
            print(f"flag: {flag}")

            exitcond = True
        except KeyboardInterrupt:
            print("CTRL+C detected. exiting ...")
            break
        except Exception as ex:
            print(f"[-] ERR: {str(ex)}")

    return

if __name__ == "__main__":
    main()
