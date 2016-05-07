#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:        penex
# Version:     1.0
# Purpose:     Regex some useful patterns while pentesting
#
# Author:      Ender Akbas @endr_akbas
#
# Created:     12.02.2016
#-------------------------------------------------------------------------------

import re,sys,os

#HTTP/HTTPS/FTP
reg_url = re.compile(u"^(?:(?:https?|ftp)://)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:/\S*)?$", re.MULTILINE)

#IP 192.168.1.1
reg_ip = r'(?i)(?<!\-|\.)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?){1})(?!\.|\/|\-)'

#CIDR 192.168.1.1/24
reg_cidr = re.compile(ur'(?i)^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?){1}\/(3[0-2]|1[0-9]?|2[0-9]?|0?))$', re.MULTILINE)

#IP RANGE 192.168.1.1-192.168.1.255
reg_range = r'(?i)((((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))-(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))'

#MAC Address aa:bb:CC:a9:f5 or aa-bb-cc-dd-ee-ff
reg_mac = re.compile(ur'^(([0-9a-fA-F]{1,2}[:-])([0-9a-fA-F]{1,2}[:-])([0-9a-fA-F]{1,2}[:-])([0-9a-fA-F]{1,2}[:-])([0-9a-fA-F]{1,2}[:-])([0-9a-fA-F]{1,2}))$', re.MULTILINE)

#MD5 098f6bcd4621d373cade4e832627b4f6
reg_md5 = r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])'

#SHA1 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
reg_sha1 = r'(?i)(?<![a-z0-9])[a-f0-9]{40}(?![a-z0-9])'

#LM:NTLM aad3b435b51404eeaad3b435b51404ee:36076e8d2685e14ed71d7efdf8aeb85b
reg_lm_ntlm = r'(?i)((?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9]):(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9]))'

#Email aaa@bbb.com
reg_email = r'[\w_+-.]+@[\w]+\.[\w.]+'

#Usage check
if len(sys.argv) < 2:
    sys.stderr.write('Usage: regex.py file.txt\n')
    sys.exit(1)

#File check
if os.path.exists(sys.argv[1]):
	f = open(sys.argv[1],'r')
	liste = f.read()

#Arrays
mac = re.findall(reg_mac,liste)
ip = re.findall(reg_ip,liste)
cidr = re.findall(reg_cidr,liste)
ranges = re.findall(reg_range,liste)

sha1 = re.findall(reg_sha1,liste)
md5 = re.findall(reg_md5,liste)
lm_ntlm = re.findall(reg_lm_ntlm,liste)

url = re.findall(reg_url,liste)
email = re.findall(reg_email,liste)

dic = {"IP List:":ip,"IP Ranges:":ranges,"CIDR:":cidr,"MD5/NTLM:":md5,"SHA1:":sha1,"LM:NTLM:":lm_ntlm,"MAC:":mac,"E-mails:":email,"URLs:":url}

for keys in dic:
	if dic.get(keys):
		if (keys == "IP List:" or keys == "IP Ranges:" or keys == "CIDR:" or keys == "MAC:"):
			print keys
			for x in dic.get(keys):
				print x[0]
			print
		else:
			print keys
			for x in dic.get(keys):
				print str(x)
			print

