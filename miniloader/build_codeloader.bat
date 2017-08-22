#Assemble the codeloader and extract the code section to codeloader.bin
powerpc-eabi-as -mregnames codeloader.s -o codeloader.o
powerpc-eabi-ld -Ttext 0x80000000 codeloader.o
powerpc-eabi-objcopy -O binary codeloader.o codeloader.bin
