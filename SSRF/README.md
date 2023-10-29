# SSRF

## SSRF Practical

Utilizing [practicum.py](practicum.py):

```bash
# save the IP address of the box in the TARGET
# environment variable
export TARGET=<target_ip_address_here>

# this will execute the attack using the default
# username "random".
python3 practicum.py $TARGET 80

# this will execute the attack using the user
# specified by the "--username" argument
python3 practicum.py $TARGET 80 --username surfer

# this will execute the attack using the user
# specified by the "--username" arguement and
# save the flag to "flag.txt" in the current
# working directory.
python3 practicum.py $TARGET 80 --username surfer --save
```
