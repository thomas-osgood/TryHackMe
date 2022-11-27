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

Looking at the obfuscated JavaScript code pulled down, we find an array at the top with base64 encoded values, and oddly named functions.