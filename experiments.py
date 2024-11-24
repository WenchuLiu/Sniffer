import subprocess
import numpy as np
import netifaces as nif
import psutil
from scapy.all import *

def run_command(command):
    netshcmd = subprocess.Popen(command,stdout=subprocess.PIPE)
    [output, errors] =  netshcmd.communicate()
    output = output.decode('UTF-8')
    if errors:
        print("WARNING: ", errors)
    else:
        print("SUCCESS ", output)
        return output

def mac_for_ip(ip):
    'Returns a list of MACs for interfaces that have given IP, returns None if not found'
    for i in nif.interfaces():
        addrs = nif.ifaddresses(i)
        try:
            if_mac = addrs[nif.AF_LINK][0]['addr']
            if_ip = addrs[nif.AF_INET][0]['addr']
        except : #ignore ifaces that dont have MAC or IP
            if_mac = if_ip = None
        if if_ip == ip:
            return if_mac
    return "mafeeeeesh"


#d = psutil.net_if_stats()
d2 = psutil.net_if_addrs()
print(d2)
#print("d",d)
#print("////////////////////////////////////////////////////////////////////////////")
#print("d2", d2)

chosen_mac = None
for i in d2.keys():
    #print("------------------------")
    #print(i)
    #print("---------------------")
    # select NIFs whose "isup" attribute equals TRUE and save as list of tuples [(name,macaddress),...]
    if "Loopback" not in i and d2[i][0].address == "64-5A-04-B4-6A-1C":
        print(i,d2[i][0].address)
        chosen_mac = d2[i][0].address.lower().replace("-", ":")
        print("chosen_mac",chosen_mac)

def exampleFunction(p):
    print("src", p[IP].src,mac_for_ip(p[IP].src))
    print("dst",p[IP].dst,mac_for_ip(p[IP].dst))
    if chosen_mac in [mac_for_ip(p[IP].src),mac_for_ip(p[IP].dst)] :
        print("yaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay")
        p.show()
    else:
        print("la2aa")





print(mac_for_ip('192.168.1.3'))
sniff(prn=exampleFunction)
