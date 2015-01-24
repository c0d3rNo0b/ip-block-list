#!/usr/bin/python
import os
import re
import concurrent.futures
from netaddr import all_matching_cidrs
from netaddr import cidr_merge
from itertools import izip_longest

# Data we have has non-valid ip addresses
def valid_ip(address):
    try:
        host_bytes = address.split('.')
	valid = [int(b) for b in host_bytes if 0 <= int(b) <= 255] 
        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False

# split a list up into sublists
def grouper(n, iterable, fillvalue=None):
	args = [iter(iterable)] * n
	return izip_longest(fillvalue=fillvalue, *args)

# sublist of matches worker thread
def match_worker(matchsublist, exceptions_list, banlist):
	for ip in matchsublist:
		if ip != None and not all_matching_cidrs(ip, exceptions_list):
			# thankfully this is thread safe
			banlist.write(ip + '\n')
 
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
logDir = 'logs'
for filename in os.listdir(logDir):
        with open(logDir + "/" + filename, "r") as fd:
		for line in fd:
	                ips = regex.findall(line)
        	        for ip in ips:
				if valid_ip(ip):
					matches[ip] = 1
				else:
					print "Found invalid IP address " + ip

# dump unique matches into a file                                                                                                                             
with open('iplists.txt', 'w') as banlist: 
	with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
		for sublist in grouper(100, matches):
			executor.submit(match_worker, sublist, exceptions_list, banlist)
