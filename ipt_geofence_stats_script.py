import sys
import math
from scapy.all import *

def ip_tuple(pkt):   # used to sort pkt on IP addresses
   if IP in pkt:
      return pkt[IP].src,pkt[IP].dst
   return '',''   #should never enter this. Must call clean_pcap first

# calculates the avg time between packets departure and arrival
# avg(x_echo.time - x.time)
def method1(pcapone,pcaptwo):
   delta_rtt_sum = 0.0
   n = 0
   i = 0
   pcapone = sorted(pcapone, key=ip_tuple)   # sort pcap on IP addresses
   # X and X_echo are now one after the other in the list,
   # UNLESS there are eterogeneous packets in between
   # we'll increment i by 2, if everything goes OK
   pcaptwo = sorted(pcaptwo, key=ip_tuple)   # sort pcap on IP addresses
   # X and X_echo are now one after the other in the list,
   # UNLESS there are eterogeneous packets in between
   # we'll increment i by 2, if everything goes OK
   max=-1
   min=100000000
   while i < len(pcapone)-1:
      pkt = pcapone[i]
      pkt2 = pcaptwo[i]
      if IP not in pkt: # odd packet, might be ARP or DNS stuff
         print("Skipping packet: ", pkt.summary())
         i += 1   # increment by 1!!!
         continue
      if IP not in pkt2: # odd packet, might be ARP or DNS stuff
         print("Skipping packet: ", pkt2.summary())
         i += 1   # increment by 1!!!
         continue
      pkt_echo = pcapone[i + 1]  # get echo pkt
      pkt2_echo = pcaptwo[i + 1]  # get echo pkt2

      if (IP not in pkt_echo or pkt[IP].src != pkt_echo[IP].src or pkt[IP].dst != pkt_echo[IP].dst ):
         # there is no echo pkt for some reason
         print("Something went wrong! Skipping packet echo: ", pkt_echo.summary())
         i+=1  # increment by 1!!!
         continue
      if (IP not in pkt2_echo or pkt2[IP].src != pkt2_echo[IP].src or pkt2[IP].dst != pkt2_echo[IP].dst ):
         # there is no echo pkt for some reason
         print("Something went wrong! Skipping packet echo: ", pkt2_echo.summary())
         i+=1  # increment by 1!!!
         continue

      # base case, everything ok, now calc RTT
      rtt_pkt= pkt_echo.time - pkt.time
      rtt2_pkt= pkt2_echo.time - pkt2.time

      delta_rtt=rtt_pkt-rtt2_pkt
    
      if (delta_rtt>=0):
        if(max<delta_rtt):
            max=delta_rtt
        if(min>delta_rtt):
            min=delta_rtt
        delta_rtt_sum+= delta_rtt
        n += 1   # increment to calculate avg later
      i += 2
   delta_rtt_sum=delta_rtt_sum-max-min
   return n-2 , delta_rtt_sum/(n-2)

def variance(avg_delta_rtt,pcapone,pcaptwo):
   sum = 0.0
   n = 0
   i = 0
   max=-1
   min=100000000
   pcapone = sorted(pcapone, key=ip_tuple)   # sort pcap on IP addresses
   # X and X_echo are now one after the other in the list,
   # UNLESS there are eterogeneous packets in between
   # we'll increment i by 2, if everything goes OK
   pcaptwo = sorted(pcaptwo, key=ip_tuple)   # sort pcap on IP addresses
   # X and X_echo are now one after the other in the list,
   # UNLESS there are eterogeneous packets in between   
   # we'll increment i by 2, if everything goes OK
   while i < len(pcapone)-1:
      pkt = pcapone[i]
      pkt2 = pcaptwo[i]
      if IP not in pkt: # odd packet, might be ARP or DNS stuff
         print("Skipping packet: ", pkt.summary())
         i += 1   # increment by 1!!!
         continue
      if IP not in pkt2: # odd packet, might be ARP or DNS stuff
         print("Skipping packet: ", pkt2.summary())
         i += 1   # increment by 1!!!
         continue
      pkt_echo = pcapone[i + 1]  # get echo pkt
      pkt2_echo = pcaptwo[i + 1]  # get echo pkt2

      if (IP not in pkt_echo or pkt[IP].src != pkt_echo[IP].src or pkt[IP].dst != pkt_echo[IP].dst ):
         # there is no echo pkt for some reason
         print("Something went wrong! Skipping packet echo: ", pkt_echo.summary())
         i+=1  # increment by 1!!!
         continue
      if (IP not in pkt2_echo or pkt2[IP].src != pkt2_echo[IP].src or pkt2[IP].dst != pkt2_echo[IP].dst ):
         # there is no echo pkt for some reason
         print("Something went wrong! Skipping packet echo: ", pkt2_echo.summary())
         i+=1  # increment by 1!!!
         continue

      # base case, everything ok, now calc RTT
      rtt_pkt= pkt_echo.time - pkt.time
      rtt2_pkt= pkt2_echo.time - pkt2.time
      delta_rtt=rtt_pkt-rtt2_pkt
      if (delta_rtt>=0):
        if(max<delta_rtt):
            max=delta_rtt
        if(min>delta_rtt):
            min=delta_rtt
        sum+=math.pow(avg_delta_rtt-(delta_rtt),2)
        n += 1   # increment to calculate avg later
      i += 2
   sum= sum-math.pow(avg_delta_rtt-max,2)-math.pow(avg_delta_rtt-min,2)
   return sum/(n-1-2)

   # path should be absolute
def read_pcap(path):
   print(path, " Reading...")
   ret = rdpcap(path)
   sys.stdout.write("\033[F") # flush and clean last written line
   sys.stdout.write("\033[K")
   print(path[path.rfind("/",0,path.rfind("/"))+1:], " DONE")
   ret.listname = path[path.rfind("/",0,path.rfind("/"))+1:]   # make pcap name readable
   return ret

pcaponepath=sys.argv[1]
pcaptwopath=sys.argv[2]

pcapone=read_pcap(pcaponepath)
pcaptwo=read_pcap(pcaptwopath)
n, avg_Te=method1(pcapone,pcaptwo)
print('n samples:',n)
print('avg_Te:',avg_Te)
variance=variance(avg_Te,pcapone,pcaptwo)
print('variance:',variance)
stddev= math.sqrt(variance)
print('std dev:', math.sqrt(variance))  
print('95%','confidence interval','[',avg_Te-(1.96* (stddev/math.sqrt(n))),',', avg_Te+(1.96* (stddev/math.sqrt(n))),']')