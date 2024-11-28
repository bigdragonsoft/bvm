## Introduction
The BVM is a Bhyve virtual machine management tool based on FreeBSD that allows you to easily manage virtual machines.

## Features
1. The supported operating systems are: FreeBSD OpenBSD NetBSD Debian OpenSuse Ubuntu Windows10 etc.
2. Supports multiple network cards and multiple hard disks.
3. There are two kinds of network modes: Bridged and NAT
4. Support grub and uefi boot
5. Support for ZFS

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
Before running, you need to edit the bvm.conf file to set the virtual machine storage directory
```
vmdir=/your/vm/dir/
```

## Usage
```
Usage:  bvm <options> [args...]
Options:
        --abinfo        Output autoboot vms info
        --addisk        Add an new disk
        --autoboot      Auto booting vms
        --clone         Vm cloning
        --config        Configure for vm
        --create        Create new vm
        --deldisk       Delete a disk
        --decrypt       Decrypt vm
        --encrypt       Encrypt vm
        --login         Login to vm
        --ls            List vm and status
        --ll            List vm and status in long format
        --lock          Lock vm
        --lockall       Lock all vms
        --os            Output os lists
        --poweroff      Force poweroff
        --reload-nat    Reload NAT redirect-port
        --remove        Destroy vm
        --rename        Rename vm
        --restart       Restart vm
        --rollback      Roll back to the snapshot point
        --setnat        Setting NAT's IP-addr
        --setsw         Setting Switch's IP-addr
        --setpr         Setting the port redirection list
        --showpr        Show port redirection list
        --showdev       Show device
        --showdevall    Show all devices in class mode
        --showdevuse    Show all devices in simple mode
        --showdhcp      Show all DHCP clients
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
        bvm --ll online
```

