
* [ltrace](http://man7.org/linux/man-pages/man1/ltrace.1.html) and [strace](https://strace.io)

	Repport library, system calls and signals.

* [gdb](https://en.wikipedia.org/wiki/GNU_Debugger)

	Most used debugger, can be impoved with [GEF](https://hugsy.github.io/gef/) or [PEDA](https://github.com/longld/peda).

Install GEF on top of gdb:
```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

* [Ghidra](https://ghidra-sre.org/)

	Decompiler for binary files, usefull for static analysis.

Automaticaly create a ghidra project from a binary file:
```bash
ghidra.py <file>
```

* [Hopper](https://www.hopperapp.com)

	Disassembler.

* [Binary Ninja](https://binary.ninja)

	Good for multithreaded analysis.


* [IDA](https://www.hex-rays.com/products/ida/support/download.shtml)

	Proprietary reverse engineering software, known to have the best disassembler. The free version can only disassemble 64-bit binaries.

* [radare2](https://github.com/radareorg/radare2)

	Binary analysis, disassembler, debugger.


* Compiling & running ASM code:

	You can convert ASM functions from assembly and run them as C functions like the following:

	`asm4.S`
	```asm
	.intel_syntax noprefix
	.global asm4
	asm4:
		push   ebp
		mov    ebp,esp
		push   ebx
		sub    esp,0x10
		mov    DWORD PTR [ebp-0x10],0x27d
		mov    DWORD PTR [ebp-0xc],0x0
		jmp    label2
	label1:
		add    DWORD PTR [ebp-0xc],0x1
	label2:
		mov    edx,DWORD PTR [ebp-0xc]
		mov    eax,DWORD PTR [ebp+0x8]
		add    eax,edx
		movzx  eax,BYTE PTR [eax]
		test   al,al
		jne    label1
		mov    DWORD PTR [ebp-0x8],0x1
		jmp    label3
	label4:
		mov    edx,DWORD PTR [ebp-0x8]
		mov    eax,DWORD PTR [ebp+0x8]
		add    eax,edx
		movzx  eax,BYTE PTR [eax]
		movsx  edx,al
		mov    eax,DWORD PTR [ebp-0x8]
		lea    ecx,[eax-0x1]
		mov    eax,DWORD PTR [ebp+0x8]
		add    eax,ecx
		movzx  eax,BYTE PTR [eax]
		movsx  eax,al
		sub    edx,eax
		mov    eax,edx
		mov    edx,eax
		mov    eax,DWORD PTR [ebp-0x10]
		lea    ebx,[edx+eax*1]
		mov    eax,DWORD PTR [ebp-0x8]
		lea    edx,[eax+0x1]
		mov    eax,DWORD PTR [ebp+0x8]
		add    eax,edx
		movzx  eax,BYTE PTR [eax]
		movsx  edx,al
		mov    ecx,DWORD PTR [ebp-0x8]
		mov    eax,DWORD PTR [ebp+0x8]
		add    eax,ecx
		movzx  eax,BYTE PTR [eax]
		movsx  eax,al
		sub    edx,eax
		mov    eax,edx
		add    eax,ebx
		mov    DWORD PTR [ebp-0x10],eax
		add    DWORD PTR [ebp-0x8],0x1
	label3:
		mov    eax,DWORD PTR [ebp-0xc]
		sub    eax,0x1
		cmp    DWORD PTR [ebp-0x8],eax
		jl     label4
		mov    eax,DWORD PTR [ebp-0x10]
		add    esp,0x10
		pop    ebx
		pop    ebp
		ret
	```

	`asm4.c`
	```c
	#include<stdio.h>
	extern int asm4(char* s);

	int main(){
	    char *str = "picoCTF_d899a";
	    printf("%X", asm4(str));
	    return 0;
	}
	```
	`bash`
	```bash
	$ gcc -m32 -o a asm4.c asm4.S
	$ ./a
	```

* Punchcards

	[Punch card emulator](http://tyleregeto.com/article/punch-card-emulator)


* GameBoy ROMS

	Packages to run GameBoy ROMS: `visualboyadvance` or `retroarch`
