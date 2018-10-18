# libssh scanner

## Introduction
-----

This is a python based script to identify hosts vulnerable to CVE-2018-10933. 

The vulnerability is present on versions of libssh 0.6+ and was remediated by a patch present in libssh 0.7.6 and 0.8.4. For more details: [https://www.libssh.org/2018/10/16/libssh-0-8-4-and-0-7-6-security-and-bugfix-release/](https://www.libssh.org/2018/10/16/libssh-0-8-4-and-0-7-6-security-and-bugfix-release/)

## Help
-----

```
CVE-2018-10933 Scanner - Find vulnerable libssh services by Leap Security (@LeapSecurity)

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -t TARGET, --target TARGET
                        An ip address or new line delimited file containing
                        IPs to banner grab for the vulnerability.
  -p PORT, --port PORT  Set port of SSH service
```
