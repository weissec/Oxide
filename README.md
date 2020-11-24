# XNETNUM
Pentesting Bash Wrapper to enumerate external services from a list of provided hosts.

XNetNum is a "one-file", highly portable bash script that can be used to perform external vulnerability assessments.
The script works as a wrapper around popular pen-testing tools.

####List of functionalities:
- Live hosts discovery
- Targets Ownership (whois)
- Port discovery (TCP/UDP)
- Service enumeration
- Service probing
- Banner retrieval
- Sub-domains enumeration
- Search for public exploits
- HTML report output
- Text log file output

Usage:
-------------
```
chmod +x xnetnum.sh
./xnetnum.sh -h
./xnetnum.sh -n Name
```


