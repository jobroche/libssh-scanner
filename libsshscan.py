#!/usr/bin/env python2
# CVE-2018-10933 Scanner by Leap Security (@LeapSecurity) https://leapsecurity.io


from __future__ import print_function
import socket, argparse, sys, os

class colors(object):
    blue = "\033[1;34m"
    normal = "\033[0;00m"
    red = "\033[1;31m"
    yellow = "\033[1;33m"

def pstatus(ip, port, banner):
  print("{blue}[*]{white} {ipaddr}:{port} is not vulnerable to authentication bypass ({banner})".format(blue=colors.blue, white=colors.normal, ipaddr=ip, port=port, banner=banner.strip())) 

def ptimeout(ip, port):
  print("{red}[-]{white} {ipaddr}:{port} has timed out.".format(red=colors.red, white=colors.normal, ipaddr=ip, port=port))

def ppatch(ip, port, banner):
  print("{blue}[*]{white} {ipaddr}:{port} has been patched ({banner})".format(blue=colors.blue, white=colors.normal, ipaddr=ip, port=port, banner=banner.strip())) 

def pvulnerable(ip, port, banner):
  print("{yellow}[!]{white} {ipaddr}:{port} is likely VULNERABLE to authentication bypass ({banner})".format(yellow=colors.yellow, white=colors.normal, ipaddr=ip, port=port, banner=banner.strip())) 


def bannergrab(ip, port):
  try:
    s = socket.create_connection((ip, port), timeout=0.30000)
    s.settimeout(None)
    banner = s.recv(1024)
    s.close()
    return banner
  except (socket.timeout, socket.error) as e:
    return ""

parser = argparse.ArgumentParser(description='CVE-2018-10933 Scanner - Find vulnerable libssh services by Leap Security (@LeapSecurity)', version="1.0.0")
parser.add_argument('target', help="An ip address or new line delimited file containing IPs to banner grab for the vulnerability.")
parser.add_argument('-p', '--port', default=22, help="Set port of SSH service")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()
ips, results = [], []

if not args.target:
    print("You didn't provide any work for me to do.")
    sys.exit(1)

if args.target:
      print("\nStatus: Searching for Vulnerable Hosts...\n")
      if os.path.isfile(args.target): #if file add hosts
          with open (args.target) as f:
              for line in f.readlines():
                  ips.append(line.strip())
      else: #if not scan the provided IP
          ips.append(args.target.strip())


for ip in ips:
  result = ([ip, int(args.port), bannergrab(ip, int(args.port))])
  if result[2]:
    if "libssh-0.6" in result[2]: #vulnerable
      pvulnerable(result[0], result[1], result[2])
    elif "libssh-0.7" in result[2]: #chjeck if patched
      if int(result[2].split(".")[-1]) >= 6: #libssh is 0.7.6 or greater (patched)
        ppatch(result[0], result[1], result[2])
      else:
        pvulnerable(result[0], result[1], result[2])
    elif "libssh-0.8" in result[2]: #chjeck if patched
      if int(result[2].split(".")[-1]) >= 4: #libssh is 0.8.4 or greater (patched)
        ppatch(result[0], result[1], result[2])
      else:
        pvulnerable(result[0], result[1], result[2])
    else: #not vulnerable
      pstatus(result[0], result[1], result[2])
  else:
    ptimeout(result[0], result[1])


print("\nScanner Completed Successfully")
