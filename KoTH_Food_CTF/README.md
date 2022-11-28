# KoTH Food CTF

## Monitor

When navigating to `$TARGET:15065` in a web browser, you are presented with an "Under Construction" message with seemingly nothing that can be done. If you enumerate this location, however, you will discover an endpoint `/monitor` that you can navigate to. 

Gobuster Command:

```bash
gobuster dir -u http://$TARGET:15065 -w <wordlist> -t 50
```

Output:

```bash
```

Upon arriving at the `/monitor` page, you are presented with an input box that will ping a given IP address.  Putting in `127.0.0.1`, we can see the output of the command is rendered in a `<div>` element. The output looks exactly like what you would expect if you ran the `ping` command in your terminal, indicating we may be able to execute arbitrary commands on the target. When we try to append command line commands to the IP address, however we get an `IP address invalid` message returned to us. It looks like this input box is sanitized or filtered in some way to prevent RCE. 

While RCE via the input may not be likely, it does not mean this page is not vulnerable. The next step is to look at the page source and the network traffic when we send a legitimate request. When looking at the page source, we find `main.js` imported. Pulling down `main.js` we find it obfuscated; we will look more at this later. Observing the network traffic, we see the request is sent to `cmd` with the body being a terminal command (`ping -c 3 <ipAddress>`). This brings us closer to confirming RCE; all we have to do now is find out the full address of the endpoint this request is being sent to.

Looking at the obfuscated JavaScript code pulled down, we find an array at the top with base64 encoded values, and oddly named functions. Base64 decoding the values in the top array, we find they are a mix of dictionary keys and other values. Scrolling down and scanning the rest of the code, we find a `POST` request to an `api/cmd` endpoint. This is what we are interested in. This `api/cmd` endpoint is where the `ping -c 3 <ipAddress>` command was being sent when we submitted the form on `/monitor`. 

To look for the `api/cmd` endpoint, we can check two likely locations: `/monitor/api/cmd` and `/api/cmd`. When we `POST` to `/monitor/api/cmd` we get a `404` status code returned. When we `POST` to `/api/cmd` we get a `200` status code returned. The endpoint is, therefore, located at `http://$TARGET/api/cmd`. 

Now that we have an endpoint to target, we can begin testing commands:

```python
import requests
target = "http://<targetip>:15065/api/cmd"
resp = requests.post(target, "whoami".encode())
```

The output of the above command reveals the username of the user hosting the site, and confirms the ability to remotely execute arbitrary code on the target machine. To make this less manual, I created [monitor_rce](monitor_rce.py). This will automatically format and execute a command given by the user and print the output to `STDOUT`.  Using eith the manual method or [monitor_rce](monitor_rce.py), it is possible to upload a reverse shell, gain a meterpreter session, etc. 

### Monitor_RCE

To successfully execute commands using [monitor_rce](monitor_rce.py), you must pass in the command as a string and give the program the target IP address and port number. An example of how to run the program is below.

Command:

```bash
./monitor_rce.py $TARGET 15065 -c "ls -la ~"
```

The above command will list all the contents of the user's home directory.