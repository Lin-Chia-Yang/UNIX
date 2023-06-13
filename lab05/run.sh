#!/bin/sh
cd hellomod
make
cp kshram.ko ../dist/rootfs/kshram.ko
cp hello ../dist/rootfs/hello
cd ../dist/rootfs
find . | cpio -H newc -o | bzip2 > ../rootfs.cpio.bz2;
cd ../..
