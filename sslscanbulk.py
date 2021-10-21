#!/usr/bin/python
import os
import sys

if len(sys.argv) != 2: 
    print "(+) Please indicate a file with targets (each one as an individual line). Usage %s <file>" % sys.argv[0]  
    print "(+) eg: %s file" % sys.argv[0]  
    sys.exit(1) 

file = sys.argv[1]
target = ""

#Read every target as a line and run sslscan on it
with open(file) as fp:
   target = fp.readline()
   while target:
       cmd = "sslscan "+target.strip()
       returned_value = os.system(cmd) 
       target = fp.readline()