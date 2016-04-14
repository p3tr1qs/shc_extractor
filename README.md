# shc_extrac.py

This utility is for helping the learning process of shellcoding.

##What does this code?

- Extract opCodes from objdump;
- Write Code in C for linux;
- Execute shellcode;

##How use

For learnig shellcodind I use the follow article, this is a great tutorial about shellcode. 
[Shellcoding for Linux and Windows Tutorial](http://www.vividmachines.com/shellcode/shellcode.html#linex2) 

###Step 1 - Write your code in Assembly
``` asm
;hello.asm
[SECTION .text]
global _start
_start:
jmp short ender
starter:
        xor eax, eax    ;clean up the registers
        xor ebx, ebx
        xor edx, edx
        xor ecx, ecx

        mov al, 4       ;syscall write
        mov bl, 1       ;stdout is 1
        pop ecx         ;get the address of the string from the stack
        mov dl, 14       ;length of the string
        int 0x80

        xor eax, eax
        mov al, 1       ;exit the shellcode
        xor ebx,ebx
        int 0x80

ender:
        call starter	;put the address of the string on the stack
        db 'H1 1 Sp3ak 4sm'
```

###Step 2: Compile

p3tr1qs@sh3llC0d3:~$ nasm -f elf hello.asm
p3tr1qs@sh3llC0d3:~$ ld -m elf_i386 -o hello hello.o
p3tr1qs@sh3llC0d3:~$ objdump -d hello

hello: formato do arquivo elf32-i386


Desmontagem da seção .text:

08048060 <_start>:
 8048060:	eb 19                	jmp    804807b <ender>

08048062 <starter>:
 8048062:	31 c0                	xor    %eax,%eax
 8048064:	31 db                	xor    %ebx,%ebx
 8048066:	31 d2                	xor    %edx,%edx
 8048068:	31 c9                	xor    %ecx,%ecx
 804806a:	b0 04                	mov    $0x4,%al
 804806c:	b3 01                	mov    $0x1,%bl
 804806e:	59                   	pop    %ecx
 804806f:	b2 05                	mov    $0x5,%dl
 8048071:	cd 80                	int    $0x80
 8048073:	31 c0                	xor    %eax,%eax
 8048075:	b0 01                	mov    $0x1,%al
 8048077:	31 db                	xor    %ebx,%ebx
 8048079:	cd 80                	int    $0x80

0804807b <ender>:
 804807b:	e8 e2 ff ff ff       	call   8048062 <starter>
 8048080:	48                   	dec    %eax
 8048081:	31 20                	xor    %esp,(%eax)
 8048083:	31 20                	xor    %esp,(%eax)
 8048085:	53                   	push   %ebx
 8048086:	70 33                	jo     80480bb <ender+0x40>
 8048088:	61                   	popa   
 8048089:	6b 20 34             	imul   $0x34,(%eax),%esp
 804808c:	73 6d                	jae    80480fb <ender+0x80>

###Step 3: Generate dump file

p3tr1qs@sh3llC0d3:~$ objdump -d hello > hello.dmp

###Step 4: Extract OpCodes, Generate C File and Execute

p3tr1qs@sh3llC0d3:~$ python3 sh_extrac.py -b hello.dmp -c hello.c  -e

