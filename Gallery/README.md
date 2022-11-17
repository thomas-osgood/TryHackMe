# Gallery

## Notes

The `GenRevShell` function creates a `PHP` file that is designed to reach out to a C2 server and pull down an attacker-specified file. This was tested with an `MSFVENOM` payload and successfully opened up a connection to the attack machine. The payload used was `linux/x86/meterpreter/reverse_tcp`. The attacker, however, should be able to execute any linux binary or shell script using this automated script, because it changes the mode of the file to `executable` via the `chmod +x` command. If uploading a `python` or `sh` script, remember to put the shebang line on top (`#!/bin/python` or `#!/bin/bash`) so the script can execute without error.


## *Full Walkthrough To Come*
