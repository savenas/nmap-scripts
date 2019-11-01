# nmap scripts

Check for Access control bypass in Hikvision IP Cameras


Usage

```
git clone https://github.com/savenas/nmap-scripts
cd nmap-scripts
nmap --script=http-hikvision-backdoor.nse -p 80,443 192.168.0.1/24 -Pn --open
```
