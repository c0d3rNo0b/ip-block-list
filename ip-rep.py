#!/usr/bin/python
import os
import re
import socket
from netaddr import all_matching_cidrs
from netaddr import cidr_merge

# Data we have has non-valid ip addresses
def valid_ip(address):
    try:
	socket.inet_aton(address)
	return True
    except:
        return False

# define a match for IP addresses
regex = re.compile('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})')

# load our exceptions
exceptions_list = []
with open('exceptions.txt','r') as fdexceptions:
	for line in fdexceptions:
		exceptions_list.append(line.rstrip())

# remove duplication in exceptions list
exceptions_list = cidr_merge(exceptions_list)

# look for IP matches log directory
matches = {}
logDir = 'rules'
for filename in os.listdir(logDir):
        with open(logDir + "/" + filename, "r") as fd:
		for line in fd:
	                ips = regex.findall(line)
        	        for ip in ips:
				if valid_ip(ip):
					matches[ip] = 1

# dump unique matches into a file
with open('iplists.txt', 'w') as banlist:
	for ip in matches:
		# cheapest time to do exceptions check is after dedup
		if not all_matching_cidrs(ip, exceptions_list):
			banlist.write(ip + '\n')
