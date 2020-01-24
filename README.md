
#  BlueGate

Proof of Concept (Denial of Service + scanner) for CVE-2020-0609 and CVE-2020-0610.

  

These vulnerabilities allows an unauthenticated attacker to gain remote code execution with highest privileges via RD Gateway for RDP.

  

Please use for research and educational purpose only.

  

##  Usage
Make sure you have [pyOpenSSL](https://www.pyopenssl.org/en/stable/) installed for python3. 

    usage: BlueGate.py [-h] -M {check,dos} [-P PORT] host
    
    positional arguments:
      host                  IP address of host
    
    optional arguments:
      -h, --help            show this help message and exit
      -M {check,dos}, --mode {check,dos}
                            Mode
      -P PORT, --port PORT  UDP port of RDG, default: 3391

  

##  Vulnerability

The vulnerabilities allows an unauthenticated attacker to write forward out-of-bound in the heap, by specifying an unchecked and arbitrary index parameter `(0x00 - 0xFFFF)`. The data to write is also arbitrary with a length up to 1000 bytes at a time and a maximum of 4096 during one session.

  

If you would like to read more about the vulnerabilities, check [this](https://www.kryptoslogic.com/blog/2020/01/rdp-to-rce-when-fragmentation-goes-wrong/) or read my latest tweets on [Twitter](https://twitter.com/ollypwn) with a PoC video as well.

  

##  What is RD Gateway?

RD Gateway acts as a proxy for RDP; i.e. between some internal servers and the internet, so you don't have to expose RDP directly to the internet.

##  Why BlueGate?

  

That was just the working title, and I couldn't come up with a better one at this stage.

  

##  Todo:

- ~~Vulnerability scanner/checker~~ **DONE**

- ~~Python implementation~~ **DONE**

