#!/usr/bin/python
import os
import re
import concurrent.futures
import multiprocessing
import socket
from netaddr import all_matching_cidrs
from netaddr import cidr_merge

# all worker threads need to read this
exceptions_list = []

# Data we have has non-valid ip addresses
def valid_ip(address):
    try:
	socket.inet_aton(address)
	return True
    except:
        return False

# workers do the cidr matching concurrently
def match_worker(ip):
	if not all_matching_cidrs(ip, exceptions_list):
		return ip

def main():
	# define a match for IP addresses
	regex = re.compile('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})')

	# load our exceptions
	global exceptions_list
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
		with concurrent.futures.ProcessPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
			for ip in executor.map(match_worker, matches):
				if ip:
					banlist.write(ip + '\n')

if __name__ == '__main__':
    main()
