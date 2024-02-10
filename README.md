# ActiveReign

> :warning: Thank you for your support. This project is no longer publicly maintained. 

<p align="center">
  <img src="https://user-images.githubusercontent.com/13889819/62736481-6f7e7880-b9fb-11e9-92d6-47b650fdb84b.png"/>
  <br>
  <img src="https://img.shields.io/badge/Python-3.7-blue.svg"/>&nbsp;
  <img src="https://img.shields.io/badge/License-GPLv3-green.svg">&nbsp;
  <a href="https://www.youtube.com/channel/UC6-HLpd0rpPXmpJIhED8qTw">
    <img src="https://img.shields.io/badge/Demo-Youtube-red.svg"/></a>&nbsp;
  <a href="https://twitter.com/intent/follow?screen_name=m8sec">
     <img src="https://img.shields.io/twitter/follow/m8sec?style=social&logo=twitter" alt="follow on Twitter"></a>
</p>

### Background
A while back I was challenged to write a discovery tool with Python3 that could automate the process of finding sensitive information on network file shares. After writing the entire tool with pysmb, and adding features such as the ability to open and scan docx an xlsx files, I slowly started adding functionality from the awesome [Impacket](https://github.com/SecureAuthCorp/impacket) library; just simple features I wanted to see in an internal penetration testing tool. The more I added, the more it looked like a Python3 rewrite of [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) created from scratch. 
 
If you are doing a direct comparison, [CME](https://github.com/byt3bl33d3r/CrackMapExec) is an amazing tool that has way more features than currently implement here. However, I added a few new features and modifications that may come in handy during an assessment.
### For more documentation checkout the project [wiki](https://github.com/m8sec/ActiveReign/wiki)

### Operational Modes
* db    - Query or insert values in to the ActiveReign database
* enum  - System enumeration & module execution
* shell - Spawn a simulated shell on the target system and perform command execution
* spray - Domain password spraying and brute force
* query - Perform LDAP queries on the domain


### Key Features
* Automatically extract domain information via LDAP and incorporate into network enumeration.
* Perform Domain password spraying using LDAP to remove users close to lockout thresholds.
* Local and remote command execution, for use on multiple starting points throughout the network.
* Simulated interactive shell on target system, with file upload and download capabilities.
* Data discovery capable of scanning xlsx and docx files.
* Various modules to add and extend capabilities.


### Acknowledgments
There were many intended and unintended contributors that made this project possible. If I am missing any, I apologize, it was in no way intentional. Feel free to contact me and we can make sure they get the credit they deserve ASAP!
* [@byt3bl33d3r](https://github.com/byt3bl33d3r) -  [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
* [@SecureAuthCorp](https://github.com/SecureAuthCorp) - [Impacket](https://github.com/SecureAuthCorp/impacket)
* [@the-useless-one](https://github.com/the-useless-one) - [pywerview](https://github.com/the-useless-one/pywerview)
* [@dirkjanm](https://github.com/dirkjanm) - [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump)

### Final Thoughts

Writing this tool and testing on a variety of networks/systems has taught me that execution method matters, and depends on the configuration of the system. If a specific module or feature does not work, determine if it is actually the program, target system, configuration, or even network placement before creating an issue.

To help this investigation process, I have created a ```test_execution``` module to run against a system with known admin privileges. This will cycle through all all execution methods and provide a status report to determine the best method to use:
```bash
$ activereign enum -u administrator -p Password123 --local-auth -M test_execution 192.168.1.1
[*] Lockout Tracker             Threshold extracted from database: 5
[*] Enum Authentication         \administrator (Password: P****) (Hash: False)
[+] DC01                        192.168.1.1     ENUM             Windows Server 2008 R2 Standard 7601 Service Pack 1    (Domain: DEMO)   (Signing: True)  (SMBv1: True) (Adm!n) 
[*] DC01                        192.168.1.1     TEST_EXECUTION   Testing execution methods                              
[*] DC01                        192.168.1.1     TEST_EXECUTION   Execution Method: WMIEXEC    Fileless: SUCCESS   Remote (Default): SUCCESS
[*] DC01                        192.168.1.1     TEST_EXECUTION   Execution Method: SMBEXEC    Fileless: SUCCESS   Remote (Default): SUCCESS
[*] DC01                        192.168.1.1     TEST_EXECUTION   Execution Method: ATEXEC     Fileless: SUCCESS   Remote (Default): SUCCESS
[*] DC01                        192.168.1.1     TEST_EXECUTION   Execution Method: WINRM      Fileless: N/A       Remote (Default): SUCCESS
```
