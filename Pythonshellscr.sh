#!/bin/bash
#This shell script will install python, all dependancies, including source files, and automation for 
#the Reputation Lists Python script Version .5(Alpha)
# 
echo Installing Python and dependancies.
apt-get install python -y
echo Installing python package netaddr
apt-get install python-netaddr
echo Installing python-concurrent.futures
apt-get install python-concurrent.futures -y
echo Installing Python setup.py 
python setup.py install
# This section builds the file structure
echo Creating Files Dependancies
echo Creating blank iplists.txt
touch iplists.txt
chmod 777 iplists.txt
echo Downloading Chinese IP blocks for exclusion lists. 
wget -O exceptionsraw.txt http://www.okean.com/chinacidr.txt
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\/[0-9]\{1,\}' exceptionsraw.txt >> exceptions.txt
echo exceptionsraw.txt cleaned and moved to exceptions.txt. exceptionsraw.txt will be deleted!
rm exceptionsraw.txt
chmod 777 exceptions.txt
echo Making rules directory
mkdir rules
chmod 777 -R rules
echo Downloading rules files to rules directory
wget -e robots=off -r -nH --cut-dirs=2 --reject "index.html*" --no-parent -P /rules http://rules.emergingthreats.net/blockrules/
chmod 777 -R rules
#run the reputation list python script to generate the block list. 
python reputationlists-v5.py
echo script complete! Please check iplists.txt for your block list. 
exit