%rax	System call			%rdi			%rsi		%rdx				%r10

101		sys_ptrace			long request	long pid	unsigned long addr	unsigned long data

sys_ptrace(0,0,1)

 mov     rax, 65h
.text:000000000040075C mov     rcx, 0
.text:0000000000400763 mov     rdx, 1                          ; addr
.text:000000000040076A mov     rsi, 0                          ; pid
.text:0000000000400771 mov     rdi, 0                          ; request


#int mprotect(const void *start, size_t len, int prot);  
.text:0000000000400818 sar     rax, 0Ch
.text:000000000040081C shl     rax, 0Ch
.text:0000000000400820 mov     rdi, rax
.text:0000000000400823 mov     rdx, 7
.text:000000000040082A mov     rax, 0Ah
.text:0000000000400831 mov     rsi, 1000h
.text:0000000000400838 syscall                                 ; LINUX - sys_mprotect

#define	PROT_NONE	 0x00	/* No access.  */
#define	PROT_READ	 0x04	/* Pages can be read.  */
#define	PROT_WRITE	 0x02	/* Pages can be written.  */
#define	PROT_EXEC	 0x01	/* Pages can be executed.  */


sys_mprotect(0x1000,0x400000,7)

.text:000000000040083D mov     rdx, 6
.text:0000000000400844 push    rax
.text:0000000000400845 lea     rax, szCh
.text:000000000040084D mov     rsi, rax
.text:0000000000400850 pop     rax
.text:0000000000400851 mov     rdi, rax
.text:0000000000400854 syscall                                 ; LINUX -

sys_read(0,0x601080,6)

0x401000
-------------------------------------------------------------------game--------------------
sys_ptrace(0,0,1)
sys_mprotect(0x400000,0x1000,7)
sys_read(0,0x601080,6)





.text:0000000000400869                 db 30h
.text:000000000040086A                 db 0D3h
.text:000000000040086B                 db 88h
.text:000000000040086C                 db  1Ch
.text:000000000040086D                 db    8
.text:000000000040086E                 db 8Ah
.text:000000000040086F                 db  74h ; t
.text:0000000000400870                 db    8
.text:0000000000400871                 db 0FFh
.text:0000000000400872                 db 48h
.text:0000000000400873                 db 0FFh
.text:0000000000400874                 db 0C1h
.text:0000000000400875                 db 80h
.text:0000000000400876                 db 0FEh
.text:0000000000400877                 db 0FBh
.text:0000000000400878                 db 74h
.text:0000000000400879                 db 0ECh
.text:000000000040087A                 db 80h
.text:000000000040087B                 db 0FBh
.text:000000000040087C                 db  90h
.text:000000000040087D                 db 75h
.text:000000000040087E                 db 0E7h

.text:000000000040087F                 db 2Dh
.text:0000000000400880                 db 0E8h
.text:0000000000400881                 db  61h ; a
.text:0000000000400882                 db  6Dh ; m
.text:0000000000400883                 db  2Dh ; -
.text:0000000000400884                 db 48h
.text:0000000000400885                 db 0E5h
.text:0000000000400886                 db  65h ; e
.text:0000000000400887                 db  65h ; e

0x2D,0xE8,0x61,0x6D,0x2D,0x48,0xE5,0x65