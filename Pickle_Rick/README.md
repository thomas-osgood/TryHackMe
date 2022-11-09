
# Walkthrough: Pickle Rick

## Enumeration

Before an attacker can exploit a machine, they must gather intelligence about it. There are a few common methods used to gather information about a device shown below.

### NMAP

NMAP is a tool that helps discover open hosts and ports, and aids in determining what services are running on the open ports. NMAP has a host of other features as well, and I encourage you to check out NMAP's [website](https://nmap.org) for more information.

Command:

```bash
nmap -sC -sV -A -p- -oN nmap/all_ports $TARGET
```

Results:

```bash
```

### Website (Nikto)

Command:

```bash
nikto -h http://$TARGET -output nikto/niktoScan.txt
```

Results:

```bash
```

### Website (Manual)

When enumerating a website, it is always good to manually interact with the site and get an idea of what the target does. Looking at the source of the target page may leak information or give the attacker a better understanding of the system they are interacting with.

## Foothold