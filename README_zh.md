[English](README.md) | [中文](README_zh.md)

## 简介
BVM 是一个基于 FreeBSD 的 Bhyve 虚拟机管理工具。它提供了简单易用的命令行界面，让用户可以方便地创建、配置和管理虚拟机。BVM 支持多种主流操作系统，并提供灵活的网络和存储配置，是一个功能强大的虚拟化管理工具。

## 功能特性
1. 支持多种主流操作系统，包括：
   - BSD 系统如 FreeBSD、OpenBSD、NetBSD
   - Linux 发行版如 Debian、Ubuntu、OpenSuse、CentOS、Kali
   - Windows 系统如 Windows 10、Windows 11
2. 灵活的存储配置：
   - 支持为每个虚拟机添加多个虚拟磁盘
   - 支持动态添加和删除磁盘
   - 多种存储接口：AHCI、VirtIO-BLK、NVMe
   - 支持 ZFS 存储，具有快照和数据保护功能
   - 多光驱支持（最多 4 个 CD，用于驱动安装等场景）
3. 强大的网络功能：
   - 支持为每个虚拟机配置多个网卡
   - 支持桥接、NAT 和 Switch 网络模式
   - NAT 模式下支持端口转发
   - 内置 DHCP 服务器，`bvm --ll` 可显示动态 IP
4. 多种引导方式：
   - 支持传统的 GRUB 引导
   - 支持现代的 UEFI 引导（包含 UEFI 变量持久化支持）
5. VNC 和显示：
   - 可配置 VNC 绑定地址、端口、分辨率
   - VNC 密码保护
   - VNC wait 选项用于启动同步
   - HDA 音频设备支持
6. 高级功能：
   - 支持 TPM 2.0 (可信平台模块)，用于 Windows 11
   - VirtIO-9P 共享文件夹（与虚拟机共享宿主机目录）
   - CPU 拓扑控制（sockets、cores、threads）
   - 虚拟机加密保护
   - 自动启动配置（支持启动顺序）
   - 快照和回滚支持
   - 完整的命令行管理界面

## 安装
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

## 基本配置
在运行之前，需要编辑 /usr/local/etc/bvm/bvm.conf 文件，设置虚拟机存储目录
```
vmdir=/your/vm/dir/
```

## 使用方法
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

## 常见问题

### 问题 1: 如何创建虚拟机？
```
答: 您可以通过以下三种方式创建虚拟机：

    1. 使用命令 'bvm --create vmname' 创建

    2. 使用现有虚拟机配置作为模板：

        bvm --create newname from template-vmname

        - template-vmname: 现有虚拟机名称（模板）
        - newname: 新虚拟机名称
    该命令将复制模板虚拟机的配置到新虚拟机中进行定制。

    可用标准模板：
        - freebsd (FreeBSD 标准配置)
        - linux   (Linux 标准配置)
        - windows (Windows 标准配置)

    您也可以使用任何现有的虚拟机名称作为模板。

    模板创建的可选参数：
        -s          设置启动类型为 grub
        -U=N        设置 CPU 数量（例如 -U=4）
        -m=SIZE     设置内存大小（例如 -m=512m、-m=2g）
        -d=SIZE     设置第一块磁盘大小（例如 -d=10g、-d=1t）
        -n=MODE     设置网络模式（bridge 或 nat）
        -i=NIC      设置绑定网卡（例如 -i=em0）

    示例：
        bvm --create myvm from linux -s -U=4 -m=512m -d=10g -n=bridge -i=em0

    3. 克隆现有虚拟机：

        bvm --clone oldname newname

        - oldname: 现有虚拟机名称
        - newname: 新虚拟机名称
    该命令将创建一个虚拟机的完整副本。
```
### 问题 2: 如何修改虚拟机配置？
```
答: 虚拟机必须关闭，然后使用命令 'bvm --config vmname' 修改设置
以下是一些配置参数解释：

    参数                描述
    ---------          -----------
    cpus               VM使用的CPU数量（总虚拟核心数）
    ram                VM分配的内存（例如512M或1G）
    CD                 启用/禁用光驱 (on/off)
    cd numbers         光驱数量 (1-4)
    cd(N) iso          第 N 个光驱的 ISO 路径（输入 '-' 可清空 cd1-cd3）
    ios path           ISO镜像目录（自动列出供选择）
    boot from          启动选项 (cd0:CD启动/hd0:硬盘启动)
    boot type          启动方式 (grub: 标准引导, uefi: UEFI引导, uefi_csm: UEFI CSM/兼容传统BIOS)
    TPM (UEFI)         启用TPM 2.0支持（需要UEFI，Windows 11必需）
    shared folder      共享文件夹（与虚拟机共享宿主机目录）
    VNC                启用/禁用VNC显示
    VNC bind           VNC服务器绑定地址（默认0.0.0.0）
    VNC port           VNC服务器端口号
    VNC width/height   VNC显示分辨率
    VNC password       VNC连接密码（可选）
    VNC wait           启动前等待VNC连接
    audio              启用HDA音频设备
    auto boot          自启动配置（见bvm --autoboot）
    hostbridge         CPU架构 (intel:hostbridge/AMD:amd_hostbridge)
    disk config        磁盘配置（可添加/删除磁盘，设置存储接口：ahci-hd/virtio-blk/nvme）
    network config     网络配置（Bridge/NAT/Switch模式）
```
### 问题 3: 如何查看虚拟机配置信息？
```
答: 使用 'bvm --vminfo vmname' 查看虚拟机详细信息，包括虚拟机名称、操作系统、IP地址、网络模式、磁盘信息等。

示例输出：
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
### 问题 4: 如何启动虚拟机？
```
答: 使用命令 'bvm --start vmname' 启动，使用 'bvm --restart vmname' 或 'bvm --reboot vmname' 重启。对于使用GRUB启动模式的虚拟机，使用 'bvm --login vmname' 登录。对于UEFI启动模式，也可以尝试使用 'bvm --login' 登录，但控制台支持取决于客户机操作系统配置；如果失败，请使用VNC或SSH。
```

### 问题 5: 什么是虚拟机自动启动，如何使用？
```
答: 虚拟机自动启动意味着在系统启动时自动启动虚拟机。例如：有两个虚拟机，vm1和vm2，其中vm1是一个数据库服务器，vm2是一个依赖于vm1数据库服务的Web服务器，因此vm1必须在vm2之前启动。在vm1和vm2的配置中，有如下选项：

vm1的配置：
    [8]. auto boot     : yes
    [9]. boot index    : 1
    [a]. boot time     : 60
  
vm2的配置：
    [8]. auto boot     : yes
    [9]. boot index    : 2
    [a]. boot time     : 15

其中[8]表示自动启动，[9]表示启动顺序，[a]表示启动延迟。
这意味着vm2将在vm1启动60秒后启动，如果有一个vm3，它的启动时间取决于vm2的启动时间值。

要正确使用此选项，请将以下内容添加到启动脚本中：
  sysrc bvmd_enable=yes

当系统启动时，将自动启动所有设置为自动启动的虚拟机，或者可以使用以下命令手动启动：
  bvm --autoboot

你也可以随时检查自动启动虚拟机的设置情况：
  bvm --abinfo
  
  示例输出：
  ---------------------------------
  idx   vm          time(sec)
  ---------------------------------
  1     freebsd     18
  2     debian      15
```
### 问题 6: 如何关闭虚拟机？
```
答: 有两种方法：

    1. 正常关闭：
      bvm --stop vmname

    2. 强制关闭（当虚拟机无法正常关闭时使用）：
      bvm --poweroff vmname 
```
### 问题 7: 如何查看虚拟机列表？
```
答: 有两种格式：长格式和短格式：

    - 短格式：
      bvm --ls

    - 长格式：
      bvm --ll
    两者都显示虚拟机名称、状态、操作系统、IP地址等。
    
    你也可以使用参数来获取特定信息：

    - 在线列表：
      bvm --ls online

    - 按状态输出：
      bvm --ls bystatus

    - 按操作系统输出：
      bvm --ls byos
      
    - 按IP地址输出：
      bvm --ls byip
```
### 问题 8: 如何锁定虚拟机？
```
答: 有时你需要防止意外删除虚拟机，可以使用锁定功能。锁定后，虚拟机无法删除，直到解锁。

   bvm --lock vmname
   bvm --unlock vmname
   bvm --lockall
   bvm --unlockall
```

### 问题 9: 虚拟机加密和解密操作
```
答: 出于安全考虑，有些虚拟机在关闭时需要加密以防止未经授权使用虚拟机文件。加密的虚拟机无法启动，直到解密。需要注意的是，加密和解密操作需要使用相同的密码，密码一旦丢失将无法解密。bvm 1.3.4 版本之后，由于修改的加密算法，旧的加密虚拟机将无法解密，需要先用老版本解密，然后使用新版本加密。

虚拟机加密和解密操作使用以下命令：

   bvm --encrypt vmname
   bvm --decrypt vmname
```
### 问题 10: 如何查看虚拟机网络状态？
```
答: 使用 'bvm --netstat' 命令查看在线虚拟机网络状态，包括网络模式、IP地址、网关、端口转发、桥接、TAP等。

示例输出：
NAME          NIC  MODE    IP              GATEWAY               PORTS        BRIDGE   TAP
ob            0    NAT     dhcp            172.16.1.1/24 (nat0)  -            bridge0  vmnet0
c             0    NAT     dhcp            172.16.1.1/24 (nat0)  -            bridge0  vmnet1
freebsd-14    0    NAT     172.16.1.10/24  172.16.1.1/24 (nat0)  tcp 22:2224  bridge0  vmnet3
```

### 问题 11: 如何查看网络设备信息？
```
答: 可以使用以下命令查看网络设备信息：

  bvm --showdev
  bvm --showdevall
  bvm --showdevuse

示例输出：
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

default-bridge 是默认的虚拟机-主机桥接；nat0-nat2 是 3 个用于主机通信的保留 NAT 接口；switch0-switch7 是 8 个用于主机通信的保留虚拟机通信接口，它们也是桥接，但与默认桥接不同，主要用于内部网络，通常不包括主机的物理 NIC。
```
### 问题 12: bvm 支持哪些网络模式？
```
答: bvm 提供桥接和 NAT 模式，其中 3 个保留的 NAT 接口用于主机通信，8 个交换接口用于主机通信。管理员可以按需设置 NAT 网络 IP 地址，交换机通常不需要配置，除非在特殊情况下。

NAT 配置在 /usr/local/etc/bvm/nat.conf 中定义，如下所示：

nat0=172.16.1.1/24
nat1=10.10.30.1/24
nat2=192.168.1.1/24

交换机配置在 /usr/local/etc/bvm/switch.conf 中定义，如下所示：

switch0=10.0.1.0/24
switch1=10.0.2.0/24
switch2=10.0.3.0/24
switch3=
switch4=
switch5=
switch6=
switch7=

bvm 提供管理 NAT 和交换接口的命令：

查询命令：

  bvm --natinfo
  bvm --swinfo

设置命令：

  bvm --setnat
  bvm --setsw
  bvm --unsetsw

添加命令：

  bvm --addnat
  bvm --addswitch

删除命令：

  bvm --delnat
  bvm --delswitch
```

### 问题 13: 什么是端口转发？
```
答: 端口转发将内部虚拟机端口映射到主机端口，以实现虚拟机-主机通信。bvm 允许在虚拟机创建和配置期间设置端口转发。此外，bvm 支持动态端口转发，可以在不停止虚拟机的情况下添加/删除规则，使用以下命令：

  bvm --setpr
  bvm --showpr

例如，设置 IP 为 192.168.1.10 的虚拟机的端口转发：

  bvm --setpr 192.168.1.10

你可以随时查看端口转发规则：

  bvm --showpr

示例输出：
PROTO   VM IP:PORT            HOST PORT   VM NAME
tcp     172.16.1.10:22        2224        freebsd-14
tcp     172.16.1.10:80        8080        freebsd-14
```
### 问题 14: 如何查看 DHCP 客户端信息？
```
答: 使用 'bvm --showdhcp' 命令查看在线虚拟机 DHCP 客户端信息，包括虚拟机名称、MAC地址、IP地址、租期等。

示例输出：
ip              mac                     bind_time                               status
--              ---                     ---------                               ------
172.16.1.100    00:a0:98:ad:89:74       03/26 09:30:37 - 03/26 19:30:37         ASSOCIATED
192.168.1.100   00:a0:98:dc:ff:5b       03/26 09:34:26 - 03/27 09:34:26         ASSOCIATED

```
### 问题 15: 如何配置 DHCP？
```
答: DHCP 配置文件位于 /usr/local/etc/bvm/dhcp.conf，可以修改 nat0-nat2 参数，如下所示：

静态 IP 地址应写成以下格式：

  nat0_static_ip_01="172.16.1.2 00:00:00:00:00:00"
  nat0_static_ip_02="172.16.1.3 00:00:00:00:00:00"

动态 IP 范围应写成以下格式：

  nat0_dynamic_ip="172.16.1.100 172.16.1.254"

其他部分可以根据默认配置填写。
```
### 问题 16: 如何查看虚拟机CPU、内存、网络流量等信息 ？
```
答: 使用 'bvm --showstats vmname' 命令查看虚拟机CPU、内存、网络流量等信息。

示例输出：
[ Infrastructure Metrics ]
CPU Usage      : 0.00% (Allocated: 1 Cores)
Memory Usage   : 0.97% (Allocated: 2g, Active: 19.89 MB)
Disk I/O & Cap :
  - disk0      : Cap: 5g, Used: 1.82 GB(/var/vm/fb/disk.img)
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

### 问题 17: 如何使用共享文件夹？
```
答: 共享文件夹允许您与虚拟机共享宿主机目录。在虚拟机配置中启用 'shared folder'，设置共享名称和宿主机路径。

配置选项：
    shared folder      启用/禁用共享文件夹 (on/off)
    share name         虚拟机中用于识别共享的名称
    share path         要共享的宿主机目录路径
    share ro           只读模式 (on/off)

在 Linux 虚拟机中挂载：
    mkdir -p /mnt/hostshare
    mount -t 9p -o trans=virtio hostshare /mnt/hostshare

注意：VirtIO-9P 在 Linux 虚拟机中支持良好。FreeBSD 14 虚拟机缺少 virtio_p9fs 模块；FreeBSD 15+ 完整支持。
```
