# W1seGuy

This solution involves leaking a partial key and brute forcing the rest of it. Because the flag format and key length used in the encryption are known, it is possible to calculate a portion of the key then brute-force the rest of it. The first four letters of the flag will always be `THM{` and the "encryption" method used is XOR. By XORing the first 4 hex bytes with `THM{`, we can leak the first four characters of the key. By looking at the source code provided, we can see the key length is 5, meaning we have 80% of the key leaked to us and only have to determine one key character. Additionally, we know the full alphabet used by the key generator (a-zA-Z0-9). Going through each possible 5th character and executing the decryption process, we can use regular expression matching to determine when we have discovered the full key. This discovery will give us the first flag and the key, which we can then enter into the prompt to get the second flag.

Key Length Leak: `res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))`
Regular Expression: `^THM{[a-zA-Z0-9]+}$`

Encryption Process:

```python
for i in range(0,len(flag)):
    xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))
```

The script to automate this process can be found [here (solver.py)](solver.py). After connecting to the server and getting the encrypted hex, copy and paste the hex into [solver.py's](solver.py) prompt and hit enter. You will be presented with the key in both (hex and ASCII) and the flag. To get flag2, enter the ASCII key into the server prompt and hit enter.
