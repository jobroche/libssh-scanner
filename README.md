# libssh scanner

## Introduction

* * *

This is a python based script to identify hosts vulnerable to CVE-2018-10933. Libssh scanner has two modes: passive (banner grabbing) and aggressive (bypass auth) to validate vulnerability's existence. By default, libssh scanner uses passive mode but supply the -a argument and aggressive mode will be used which provides more accurate results.

The vulnerability is present on versions of libssh 0.6+ and was remediated by a patch present in libssh 0.7.6 and 0.8.4. For more details: <https://www.libssh.org/2018/10/16/libssh-0-8-4-and-0-7-6-security-and-bugfix-release/>

## Installation

* * *

Run `pip install -r requirements.txt` within the cloned libssh-scanner directory.

## Help

* * *

    libssh Scanner - Find vulnerable libssh services by Leap Security (@LeapSecurity)

    positional arguments:
      target                An ip address or new line delimited file containing
                            IPs to search for the vulnerability.

    optional arguments:
      -h, --help            show this help message and exit
      -v, --version         show program's version number and exit
      -p PORT, --port PORT  Set port of SSH service
      -a, --aggressive      Identify vulnerable hosts by bypassing authentication
