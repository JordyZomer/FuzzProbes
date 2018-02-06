import argparse
from scapy.all import *
import hexdump

parser = argparse.ArgumentParser(description='Wireless probe fuzzer - Author: Jordy Zomer - Set your interface to monitor mode')
parser.add_argument('-i', '--interface', help='Network Interface', required=True)
parser.add_argument('-t', '--target', help='Target SSID', required=True)
parser.add_argument('-o', '--output', help='Output file name', default="stdout")
args = parser.parse_args()

logfile = args.output
interface = args.interface
target = args.target

for i in range(1,256):
  buffer_overflow = ["00" *i, "FF" *i]
  exploits = [buffer_overflow]

for x in exploits[:]:
  tofuzz = [
    "Dot11Elt(ID=x,info='00')", 
    "Dot11Elt(ID='SSID', len=9,info=x)", 
    "Dot11Elt(ID='RATES', info=x)", 
    "Dot11Elt(ID='EXT RATES',info=x)", 
    "Dot11Elt(ID='DS PARAM', info=x)", 
    "Dot11Elt(ID='COUNTRY', info=x)", 
    "Dot11Elt(ID='REQUEST',info=x)", 
    "Dot11Elt(ID='CHALLENGE TEXT',info=x)", 
    "Dot11Elt(ID='POWER CONSTRAINT',info=x)", 
    "Dot11Elt(ID='POWER CAPAB',info=x)", 
    "Dot11Elt(ID='CHANNELS',info=x)", 
    "Dot11Elt(ID='ERP INFO',info=x)", 
    "Dot11Elt(ID='ERP NONERP PRESENT',info=x)", 
    "Dot11Elt(ID='CHANNELS CHANNEL BAND',info=x)", 
    "Dot11Elt(ID='ERP BARKER LONG',info=x)", 
    "Dot11Elt(ID='RSN',info=x)", 
    "Dot11Elt(ID='VENDOR',info=x)", 
    "Dot11Elt(ID='COUNTRY TRIPLET',info=x)", 
    "Dot11Elt(ID='COUNTRY BAND TRIPLET',info=x)", 
    "Dot11Elt(ID='COUNTRY EXT TRIPLET',Info=x)"]
for x in tofuzz[:]:
  resp = hexdump(sendp(
    RadioTap()/
    Dot11(type=0,subtype=0100,addr2=target)/
    Dot11ProbeReq()/x))
