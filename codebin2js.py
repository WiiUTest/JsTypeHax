import struct
import os


j = 0;

payload = ""
try:
    f = open("wiiuhaxx_loader.bin", "rb")
    while True:
        B = struct.unpack(">B", f.read(1))[0];
        payload += "0x%02x, " % (B)
        j+=1
except:
    payload += "\n"

for i in range(j&0x03):
    payload += "0x00, "
payload += "\n"

payload += "0x00, 0x80, 0x00, 0x00,\n"
j+=4

try:
    f = open("code550.bin", "rb")
    while True:
        B = struct.unpack(">B", f.read(1))[0];
        payload += "0x%02x, " % (B)
        j+=1
except:
    payload += ""
    
for i in range(j&0x03):
    payload += "0x00,"
payload += "\n"

#nop
nop = "";
for i in range(j, 0x8000, 4):
    nop += "0x60, 0x00, 0x00, 0x00, "
nop += "\n"

print "["
print nop
print payload
print "]"