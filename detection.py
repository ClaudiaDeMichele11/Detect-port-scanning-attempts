import os
import logging
from scapy.all import *


ip = "10.0.2.15"

result = os.popen('ls /sys/class/net').read()
interf = result.split("\n")
interf = interf[:-1]
print("le interfacce sono: ", ' '.join(map(str, interf)))
print("Quale interfaccia scegli?")

interfaccia = str(input())

if interfaccia in interf:
    capture = sniff(iface=interfaccia, count=20) 
    print(type(capture))
    print(capture.summary())
    for p in capture:
        wrpcap("log.pcap", [p], append=True)
else:
    logging.error("L'interfaccia inserita non esiste")


pkts = rdpcap('log.pcap')
ports = [80, 25]
filtered = (pkt for pkt in pkts if
    TCP in pkt and
    (pkt[TCP].sport in ports or pkt[TCP].dport in ports))
wrpcap('filtered.pcap', filtered)


requests_d = {}

filtered_cap = PcapReader('filtered.pcap')
for packet in filtered_cap:
    if packet[TCP].flags=='S':
        if packet[IP].src not in requests_d:
            requests_d[packet[IP].src]={}
        if packet[TCP].dport not in requests_d:
            requests_d[packet[IP].src][packet[TCP].dport] = {'SYN':1, 'RSTACK':0, 'RST':0}
        else:
            requests_d[packet[IP].src][packet[TCP].dport]['SYN']+=1 
       
    if packet[TCP].flags=='RA':
        if packet[IP].src == ip:
            requests_d[packet[IP].dst][packet[TCP].sport]['RSTACK']+=1
        else:
            requests_d[packet[IP].src][packet[TCP].dport]['RSTACK']+=1
    if packet[TCP].flags=='R':
        requests_d[packet[IP].src][packet[TCP].dport]['RST']+=1

print(requests_d)
count = 0
for ip in requests_d:
    for port in requests_d[ip]:
        if requests_d[ip][port]['RSTACK'] == requests_d[ip][port]['SYN'] or requests_d[ip][port]['SYN'] == requests_d[ip][port]['RST']:
            count +=1

for ip in requests_d:
    if count == len(requests_d[ip]):
        print(f"{ip} ha scansionato tutte le porte")
    elif count > 0:
        print(f"{ip} ha scansionato qualche porta")
    else:
        print(f"Nessuna scansione e\' stata fatta da {ip} ha")


