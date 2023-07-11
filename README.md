# DECPwn
Practicing different Linux kernel exploitation techniques with my DECnet vulnerability and null page mapping enabled.
___
## Scenarios
- **Everything disabled**: `qemu-system-x86_64 -append "nosmap nosmep nopti nokaslr"`

  Code execution is redirected to the `output` function in userland, which invokes `commit_creds(prepare_kernel_cred(0))`.

- **Syscall Hooking**

  Swap the *mkdir* system call handler address inside the *sys_call_table* with a function resembling the one in Scenario 1.

- **SMEP and KPTI enabled**: `qemu-system-x86_64 -append "nosmap nokaslr"`

  Code execution is redirected to a stack pivot that sets _$rsp_ to a ROP chain in the null page. 

- **Usermode Helper**

  The `core_pattern` sysctl is overwritten to specify a command to run with elevated privileges when dumping core.

  The program is then interrupted with the SIGABRT signal to trigger the usermode script.

## Build
```bash
apt install libdnet
gcc -o lpe lpe.c -ldnet
gcc -o lpe-core_pattern lpe-core_pattern.c -ldnet
gcc -o lpe-nosmep lpe-nosmep.c -ldnet -no-pie
gcc -o lpe-syscall lpe-syscall.c -ldnet -no-pie
```
## Run
Configure DECnet as root:
```bash
sysctl -w vm.mmap_min_addr="0" # 0x1000
echo -n "1.10" > /proc/sys/net/decnet/node_address
```
Run the exploit as unprivileged user:
```
$ ./lpe
[*] Saved state
[*] Triggering NPD
[*] Returned to userland
[*] UID: 0, got root!
#
```
