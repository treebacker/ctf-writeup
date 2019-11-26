#!/bin/bash
./qemu-system-x86_64 -initrd ./rootfs.cpio -kernel ./vmlinuz-4.8.0-52-generic -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -enable-kvm -monitor /dev/null -m 64M --nographic -device VDD,id=vda -device VDD,id=vdb
