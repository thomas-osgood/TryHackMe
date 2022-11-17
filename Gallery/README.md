# Gallery

## Important Note

Right now, the exploit script (`foothold.go`) does not successfully upload and execute the reverse shell. There is more work needed to get this piece of the automated process to work; however, the program *does* succeed in updating the admin password to `password`, allowing the attacker to login with credentials, rather than SQLi. 

The password is set in the `CreateMIMEData` function by adding content to the `password` part.

The `GenRevShell` function creates a `PHP` file that is designed to reach out to a C2 server and pull down an attacker-specified file, but this is not working as expected on this machine. During testing, the script was made to successfully reach out and request the specified file by changing `wget` to `curl`, but the execution of the pulled down file never occurred. For now, it is best to upload a php reverse shell script that will open a connection to the attack machine. 
