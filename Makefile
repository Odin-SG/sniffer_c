all: server sniffer.c tables dump dhcp
	gcc -g3 sniffer.c -o sniffer_x86 dump.o tables.o dhcpdiscover.o

dump: dump.c
	gcc -g3 -c dump.c

tables: tables.c
	gcc -g3 -c tables.c

dhcp:	dhcpdiscover.c
	gcc -g3 -c dhcpdiscover.c
#________________________________
server: server.c
	gcc -g3 server.c -o server
#sniffer: sniffer.c
#	mips-linux-gnu-gcc-10 -static -static-libgcc -pipe -mno-branch-likely -mips32r2 -mtune=24kc -march=24kc sniffer.c -o sniffer
#
#
# BEFORE MAKE IT READ https://openwrt.org/docs/guide-developer/toolchain/crosscompile
#
# PATH=$PATH:/home/[youhomedir]/workspace/openwrt/openwrt/staging_dir/toolchain-mips_24kc_gcc-8.4.0_musl/bin/
# export PATH
# STAGING_DIR=/home/[youhomedir]/workspace/openwrt/openwrt/staging_dir/toolchain-mips_24kc_gcc-8.4.0_musl/
# export STAGING_DIR
# mips-openwrt-linux-gcc -c tables.c
# mips-openwrt-linux-gcc -c dump.c
# mips-openwrt-linux-gcc -c dhcpdiscover.c
# mips-openwrt-linux-gcc sniffer.c -o sniffer dump.o tables.o dhcpdiscover.o
