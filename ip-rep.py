#!/usr/bin/python
import os
import re
from netaddr import all_matching_cidrs

# Data we have has non-valid ip addresses
def valid_ip(address):
    try:
        host_bytes = address.split('.')
	valid = [int(b) for b in host_bytes if 0 <= int(b) <= 255] 
        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False
 
# define a match for IP addresses
regex = re.compile('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})')

# load our exceptions
exceptions_list = []
fdexceptions = open('exceptions.txt','r')
for line in fdexceptions:
	# print "Found this exception; %s" % line.rstrip()
	exceptions_list.append(line.rstrip())
fdexceptions.close()
	
# look for IP matches log directory
matches = {}
logDir = 'logs'
for filename in os.listdir(logDir):
        fd = open(logDir + "/" + filename, "r")
        for line in fd:
                ips = regex.findall(line)
                for ip in ips:
			if valid_ip(ip):
				matches[ip] = 1
			else:
				print "Found invalid IP address " + ip
	fd.close()

# dump unique matches into a file
banlist = open('iplists.txt', 'w')
for ip in matches:
	# cheapest time to do exceptions check is after dedup
	if not all_matching_cidrs(ip, exceptions_list):
		banlist.write(ip + '\n')

banlist.close()
