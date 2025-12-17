[English](README.md) | [中文](README_zh.md)

## Introduction
BVM is a Bhyve virtual machine management tool based on FreeBSD. It provides a simple and easy-to-use command line interface that allows users to conveniently create, configure and manage virtual machines. BVM supports multiple mainstream operating systems and offers flexible network and storage configuration, making it a powerful virtualization management tool.

## Features
1. Support for multiple mainstream operating systems, including:
   - BSD systems like FreeBSD, OpenBSD, NetBSD
   - Linux distributions like Debian, Ubuntu, OpenSuse, CentOS, Kali
   - Windows systems like Windows 10, Windows 11
2. Flexible storage configuration:
   - Support for adding multiple virtual disks to each VM
   - Support for dynamic disk addition and removal
   - Multiple storage interfaces: AHCI, VirtIO-BLK, NVMe
   - ZFS storage support with snapshot and data protection features
3. Powerful networking capabilities:
   - Support for configuring multiple network cards per VM
   - Bridge, NAT, and Switch networking modes
   - Port forwarding support in NAT mode
   - Built-in DHCP server with dynamic IP display in `bvm --ll`
4. Multiple boot methods:
   - Support for traditional GRUB boot
   - Support for modern UEFI boot (including UEFI Variables persistence)
5. VNC and Display:
   - Configurable VNC bind address, port, resolution
   - VNC password protection
   - VNC wait option for boot synchronization
   - HDA audio device support
6. Advanced features:
   - TPM 2.0 support (Trusted Platform Module) for Windows 11
   - VirtIO-9P shared folders (share host directories with VMs)
   - CPU topology control (sockets, cores, threads)
   - VM encryption protection
   - Autoboot configuration with boot order
   - Snapshot and rollback support
   - Complete command line management interface

## Installation
```
  # pkg update
  # pkg install bvm
```
### -- or --
```
  # portsnap fetch update
  # cd /usr/ports/sysutils/bvm/
  # make install clean
```

## Basic Setup
Before running, you need to edit /usr/local/etc/bvm/bvm.conf file to set the virtual machine storage directory
```
vmdir=/your/vm/dir/
```

## Usage
```
Usage:  bvm <options> [args...]
Options:
        --abinfo        Display information about auto-boot VMs
        --addisk        Add a new disk to VM
        --addnat        Add NAT
        --addswitch     Add Switch
        --autoboot      Auto-boot VMs
        --clone         Clone VM
        --config        Configure VM
        --create        Create new VM
        --deldisk       Delete a disk
        --delnat        Delete NAT
        --delswitch     Delete Switch
        --swinfo        Output Switch info
        --decrypt       Decrypt VM
        --encrypt       Encrypt VM
        --login         Log in to VM
        --ls            List VMs and status
        --ll            List VMs and status in long format
        --netstat       Show VM network status
        --natinfo       Output NAT info
        --lock          Lock VM
        --lockall       Lock all VMs
        --os            Output OS list
        --poweroff      Force power off
        --reload-nat    Reload NAT redirect port
        --remove        Destroy VM(s)
        --rename        Rename VM
        --restart       Restart VM
        --reboot        Restart VM (alias for --restart)
        --rollback      Roll back to snapshot point
        --setnat        Set NAT IP address
        --setsw         Set Switch IP address
        --setpr         Set port redirection list
        --showpr        Show port redirection list
        --showdev       Show device
        --showdevall    Show all devices in class mode
        --showdevuse    Show all devices in simple mode
        --showdhcp      Show all DHCP clients
        --showsnap      Show snapshot list of VM
        --showsnapall   Show snapshot list of all VMs
        --showstats     Show VM stats
        --snapshot      Generate snapshot for VM
        --start         Start VM
        --stop          Stop VM
        --unlock        Unlock VM
        --unlockall     Unlock all VMs
        --unsetsw       Unset Switch IP address
        --vminfo        Output VM info
```

## Q&A

### Question 1: How to create a virtual machine?
```
Answer: You can create a new virtual machine in three ways:

    1. Use the command 'bvm --create vmname' to create

    2. Use an existing VM configuration as template:

        bvm --create newname from template-vmname

        - template-vmname: Name of existing VM (template)
        - newname: Name of new VM
    This command will copy the template VM's configuration to the new VM for customization.

    Standard templates available:
        - freebsd (FreeBSD standard configuration)
        - linux   (Linux standard configuration)
        - windows (Windows standard configuration)

    You can also use any existing VM name as a template.

    Optional parameters for template creation:
        -s          Set boot type to grub
        -U=N        Set CPU count (e.g. -U=4)
        -m=SIZE     Set memory size (e.g. -m=512m, -m=2g)
        -d=SIZE     Set first disk size (e.g. -d=10g, -d=1t)
        -n=MODE     Set network mode (bridge or nat)
        -i=NIC      Set bind NIC (e.g. -i=em0)

    Example:
        bvm --create myvm from linux -s -U=4 -m=512m -d=10g -n=bridge -i=em0

    3. Clone an existing VM:

        bvm --clone oldname newname

        - oldname: Name of existing VM
        - newname: Name of new VM
    This command will make a complete copy of a VM.
```
### Question 2: How to modify VM configuration?
```
Answer: The VM must be powered off, then use command 'bvm --config vmname' to modify settings
Some configuration parameters explained:

    Parameter          Description
    ---------          -----------
    cpus               Number of CPUs used by VM (the total vCPU count)
    ram                Memory allocated to VM (e.g. 512M or 1G)
    ios path           Installation image directory (auto-listed for selection)
    boot from          Boot options (cd0:CD boot/hd0:Hard disk boot)
    boot type          Boot method (grub: Standard, uefi: UEFI, uefi_csm: UEFI CSM/Legacy BIOS)
    TPM (UEFI)         Enable TPM 2.0 support (requires UEFI, needed for Windows 11)
    shared folder      Share host directories with the VM (VirtIO-9P)
    VNC                Enable/disable VNC display
    VNC bind           VNC server bind address (default: 0.0.0.0)
    VNC port           VNC server port number
    VNC width/height   VNC display resolution
    VNC password       Optional password for VNC connection
    VNC wait           Wait for VNC connection before boot
    audio              Enable HDA audio device
    auto boot          Auto-start configuration (see bvm --autoboot)
    hostbridge         CPU architecture (intel:hostbridge/AMD:amd_hostbridge)
    disk config        Disk configuration (can add/remove disks, set storage interface: ahci-hd/virtio-blk/nvme)
    network config     Network configuration (Bridge/NAT/Switch modes)
```
### Question 3: How to view VM configuration information?
```
Answer: Use 'bvm --vminfo vmname' to view detailed VM information, including VM name, OS, IP address, network mode, disk info, etc.

Example output:
---------------------------
Welcome to Bhyve Vm Manager
---------------------------
name           : debian
os type        : Debian
ram            : 512m
cpus           : 1
disk interface : ahci-hd
disk numbers   : 1
|-ZFS support  : off
|-disk(0) size : 5g
cd status      : on
|-iso path     : /root/iso/debian-9.3.0-amd64-netinst.iso
boot from      : cd0
hostbridge     : hostbridge
boot type      : grub
auto boot      : yes
|-index        : 2
|-time         : 15 sec.
nic interface  : e1000
nic numbers    : 1
nic_0
|-network mode : NAT
|-wan          : em0
|-gateway      : nat2 [GW 192.168.1.1/24]
|-redirect     : disable
|-bridge       : bridge1
|-tap          : vmnet1
|-ip           : 192.168.1.10/24
status         : off
lock           : no
crypt          : no
```
### Question 4: How to start a VM?
```
Answer: Use command 'bvm --start vmname' to start, use 'bvm --restart vmname' or 'bvm --reboot vmname' to restart. For VMs using GRUB boot mode, use 'bvm --login vmname' to log in. For UEFI boot mode, 'bvm --login' can be attempted, but console login support depends on the guest OS configuration; if it fails, please use VNC or SSH.
```

### Question 5: What is VM auto-start and how to use it?
```
Answer: VM auto-start means automatically starting VMs when the system boots. For example: with two VMs, vm1 and vm2, where vm1 is a database server and vm2 is a web server that depends on vm1's database service, vm1 must start before vm2. In vm1 and vm2's configurations, there are options like:

vm1's config:
    [8]. auto boot     : yes
    [9]. boot index    : 1
    [a]. boot time     : 60
  
vm2's config:
    [8]. auto boot     : yes
    [9]. boot index    : 2
    [a]. boot time     : 15

Where [8] indicates auto-start, [9] indicates start order, [a] indicates start delay.
This means vm2 will start 60 seconds after vm1, and if there's a vm3, its start time depends on vm2's boot time value.

To properly use this option, add to startup script:
  sysrc bvmd_enable=yes

When system boots, it will automatically start all VMs set for auto-start in order, or you can manually start with:
  bvm --autoboot

You can also check auto-start VM settings anytime:
  bvm --abinfo
  
  Example output:
  ---------------------------------
  idx   vm          time(sec)
  ---------------------------------
  1     freebsd     18
  2     debian      15
```
### Question 6: How to shut down a VM?
```
Answer: There are two ways:

    1. Normal shutdown: 
      bvm --stop vmname

    2. Force shutdown (use when VM cannot shut down normally): 
      bvm --poweroff vmname 
```
### Question 7: How to view VM list?
```
Answer: There are two formats - long and short:

    - Short list: 
      bvm --ls

    - Long list: 
      bvm --ll
    Both show VM name, status, OS, IP address etc.
    
    You can also use parameters to get specific information:

    - Online list: 
      bvm --ls online

    - By status: 
      bvm --ls bystatus

    - By OS: 
      bvm --ls byos
      
    - By IP: 
      bvm --ls byip
```
### Question 8: How to lock VMs?
```
Answer: Sometimes you need to prevent accidental VM deletion by using the lock feature. When locked, VMs cannot be deleted until unlocked.

   bvm --lock vmname
   bvm --unlock vmname
   bvm --lockall
   bvm --unlockall
```

### Question 9: VM encryption and decryption operations
```
Answer: For security, some VMs need encryption when powered off to prevent unauthorized use of VM files. Encrypted VMs cannot start until decrypted. Note that encryption and decryption require the same password; if the password is lost, it cannot be decrypted. Starting from bvm 1.3.4, due to the modified encryption algorithm, old encrypted VMs cannot be decrypted; you need to decrypt them with an old version first, then encrypt them with a new version. 

VM encryption/decryption is done with these commands:

   bvm --encrypt vmname
   bvm --decrypt vmname
```
### Question 10: How to check VM network status?
```
Answer: Use ‘bvm --netstat’ command to view online VM network status, including network mode, IP address, gateway, port forwarding, bridge, TAP etc.

Example output:
NAME          NIC  MODE    IP              GATEWAY               PORTS        BRIDGE   TAP
ob            0    NAT     dhcp            172.16.1.1/24 (nat0)  -            bridge0  vmnet0
c             0    NAT     dhcp            172.16.1.1/24 (nat0)  -            bridge0  vmnet1
freebsd-14    0    NAT     172.16.1.10/24  172.16.1.1/24 (nat0)  tcp 22:2224  bridge0  vmnet3
```

### Question 11: How to view network device information?
```
Answer: You can use these commands to view network device information:

  bvm --showdev
  bvm --showdevall
  bvm --showdevuse

Example output:
default-bridge 
  |-em0
  |-c          (nic1)
  |-test       (nic1)
nat0 [172.16.1.1/24]
  |-ob         (nic0)
  |-c          (nic0)
  |-c11        (nic0)
  |-c12        (nic0)
  |-centos     (nic0)
  |-test       (nic0)
  |-freebsd-14 (nic0)
nat1 [10.10.30.1/24]
  |-null
nat2 [192.168.1.1/24]
  |-c2         (nic0)
  |-debian     (nic0)
switch0 [10.0.1.0/24]
  |-null
switch1 [10.0.2.0/24]
  |-null
switch2 [10.0.3.0/24]
  |-null
switch3 
  |-null
switch4 
  |-null
switch5 
  |-null
switch6 
  |-null
switch7 
  |-null

The default-bridge is the default VM-host bridge; nat0-nat2 are 3 reserved NAT interfaces for host communication; switch0-switch7 are 8 reserved VM communication interfaces, which are also bridges but differ from the default bridge as they're mainly for internal networking and usually don't include host physical NICs.
```
### Question 12: What network modes does bvm have?
```
Answer: bvm provides bridge and NAT modes, with 3 reserved NAT interfaces for host communication and 8 switch interfaces for host communication. Administrators can set NAT network IP addresses as needed, switches usually don't need configuration except in special cases.

NAT configuration is in /usr/local/etc/bvm/nat.conf, defined as:

nat0=172.16.1.1/24
nat1=10.10.30.1/24
nat2=192.168.1.1/24

Switch configuration is in /usr/local/etc/bvm/switch.conf, defined as:

switch0=10.0.1.0/24
switch1=10.0.2.0/24
switch2=10.0.3.0/24
switch3=
switch4=
switch5=
switch6=
switch7=

bvm provides commands to manage NAT and switch interfaces:

Query commands:

  bvm --natinfo
  bvm --swinfo

Setting commands:

  bvm --setnat
  bvm --setsw
  bvm --unsetsw

Add commands:

  bvm --addnat
  bvm --addswitch

Delete commands:

  bvm --delnat
  bvm --delswitch
```

### Question 13: What is port forwarding?
```
Answer: Port forwarding maps internal VM ports to host ports, enabling VM-host communication. bvm allows setting port forwarding during VM creation and configuration. Additionally, bvm supports dynamic port forwarding to add/remove rules without stopping VMs, using commands:

  bvm --setpr
  bvm --showpr

For example, to set port forwarding for a VM with IP 192.168.1.10:

  bvm --setpr 192.168.1.10

You can view port forwarding rules anytime:

  bvm --showpr

Example output:
PROTO   VM IP:PORT            HOST PORT   VM NAME
tcp     172.16.1.10:22        2224        freebsd-14
tcp     172.16.1.10:80        8080        freebsd-14
```
### Question 14: How to view DHCP client information?
```
Answer: Use ’bvm --showdhcp‘ command to view online VM DHCP client information, including VM name, MAC address, IP address, lease time etc.

Example output:
ip              mac                     bind_time                               status
--              ---                     ---------                               ------
172.16.1.100    00:a0:98:ad:89:74       03/26 09:30:37 - 03/26 19:30:37         ASSOCIATED
192.168.1.100   00:a0:98:dc:ff:5b       03/26 09:34:26 - 03/27 09:34:26         ASSOCIATED

```
### Question 15: How to configure DHCP?
```
Answer: The DHCP configuration file is located at /usr/local/etc/bvm/dhcp.conf, where you can modify the nat0-nat2 parameters as needed.

Static IP addresses should be written in the following format:

  nat0_static_ip_01="172.16.1.2 00:00:00:00:00:00"
  nat0_static_ip_02="172.16.1.3 00:00:00:00:00:00"

Dynamic IP range should be written in the following format:

  nat0_dynamic_ip="172.16.1.100 172.16.1.254"

Other sections can be filled in according to the default configuration.
```
### Question 16: How to view VM CPU, memory, network traffic information?
```
Answer: Use 'bvm --showstats vmname' command to view VM CPU, memory, network traffic information.

Example output:
[ Infrastructure Metrics ]
CPU Usage      : 0.00% (Allocated: 1 Cores)
Memory Usage   : 0.97% (Allocated: 2g, Active: 19.89 MB)
Disk I/O & Cap :
  - disk0      : Cap: 5g, Used: 1.82 GB (/var/vm/fb/disk.img)
Network Traffic:
  - vmnet0     : RX: 726 B / TX: 4.43 KB (Drops: 0)

[ Advanced VM Stats ]
VM Exits       : 1437238 (Rate: ~45784/sec)
  - IO Access  : 202732
  - Emulation  : 685290
  - Interrupts : 45059 (NMI: 0)

[ Availability & Services ]
PID            : 6044
Host Load Avg  : 1.44, 1.43, 1.36
Status         : Online
Uptime         : 52:34 (Process)
Boot Time      : 31s (CPU Runtime)
VNC Service    : Disabled
```

### Question 17: How to use file sharing (Shared Folder)?
```
Answer: Shared folders allow you to share host directories with virtual machines. Enable 'shared folder' in the VM configuration, set the share name and host path.

Configuration options:
    shared folder      Enable/disable file sharing (on/off)
    share name         Name used in guest to identify the share
    share path         Host directory path to share
    share ro           Read-only mode (on/off)

Mount in Linux guest:
    mkdir -p /mnt/hostshare
    mount -t 9p -o trans=virtio hostshare /mnt/hostshare

Note: VirtIO-9P is well supported in Linux guests. FreeBSD 14 guests lack the virtio_p9fs module; FreeBSD 15+ has full support.
```
