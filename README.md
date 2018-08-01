Introduction
------------
The BVM is a Bhyve virtual machine management tool based on FreeBSD that allows you to easily manage virtual machines.

Features
--------
1. The supported operating systems are: FreeBSD OpenBSD NetBSD Debian OpenSuse Ubuntu Windows10 etc.
2. Supports multiple network cards and multiple hard disks.
3. There are two kinds of network modes: Bridged and NAT
4. Support grub and uefi boot
5. Support for ZFS

How to compile
--------------
  # cd src
  # make
  # cp bvm bvmb /usr/local/bin/
  # mkdir /usr/local/etc/bvm/
  # cd ..
  # cp conf/*.conf /usr/local/etc/bvm/
  # cp conf/bvmd /usr/local/etc/rc.d/

Generate the installation package
---------------------------------
  # cd pkg
  # ./create

Installation
------------
# pkg add bvm.txz

  bvm.txz is replaced with the installation package you generated
  For example, pkg add http://bigdragon.chinafreebsd.cn/bvm/bvm-1.1.2_1.txz

How to run
----------
Before running, you need to edit the bvm.conf file to set the virtual machine storage directory
vmdir=/your/vm/dir/

How to use
----------
Usage:  bvm <options> [args...]
Options:
        --abinfo        Output autoboot vms info
        --addisk        Add an new disk
        --autoboot      Auto booting vms
        --clone         Vm cloning
        --config        Configure for vm
        --create        Create new vm
        --deldisk       Delete a disk
        --login         Login to vm
        --ls            List vm and status
        --ll            List vm and status in long format
        --os            Output os lists
        --poweroff      Force poweroff
        --lock          Lock vm
        --lockall       Lock all vms
        --remove        Destroy vm
        --rename        Rename vm
        --restart       Restart vm
        --rollback      Roll back to the snapshot point
        --setnat        Setting NAT's IP-addr
        --setsw         Setting Switch's IP-addr
        --showdev       Show device
        --showdevall    Show all devices in class mode
        --showdevuse    Show all devices in simple mode
        --showsnap      Show snapshots list of the vm
        --showsnapall   Show snapshots list of the all vm
        --snapshot      Generating snapshots for vm
        --start         Start vm
        --stop          Stop vm
        --unlock        Unlock vm
        --unlockall     Unlock all vms
        --unsetsw       Unset Switch's IP-addr
        --vminfo        Output vm info

Example:
        bvm --start vmname
        bvm --clone oldname newname
        bvm --ls
