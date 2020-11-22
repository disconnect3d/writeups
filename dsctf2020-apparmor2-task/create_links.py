import os

# run `mkdir rootfs` before
for i in range(256):
    if i % 16 == 0:
        print('Progress:', i/256.0)
    for j in range(256):
        a = '%02x' % i
        b = '%02x' % j
        os.system('ln -s D rootfs/flag-{}{}'.format(a,b))
