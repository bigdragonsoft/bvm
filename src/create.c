/*-----------------------------------------------------------------------------
   BVM Copyright (c) 2018-2025, Qiang Guo (bigdragonsoft@gmail.com)
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   * Redistributions of source code must retain the above copyright notice, this
     list of conditions and the following disclaimer.

   * Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 *---------------------------------------------------------------------------*/

/*
 * ============= 颜色代码 =============
 * 字背景颜色:40~49	字颜色:30~39
 * 40:黑		30:黑
 * 41:深红		31:红
 * 42:绿		32:绿
 * 43:黄色		33:黄
 * 44:蓝色		34:蓝色
 * 45:紫色		35:紫色
 * 46:天蓝色		36:天蓝色
 * 47:白色		37:白色
 *
 * ========= ANSI控制码的说明 =========
 * \33[0m 		关闭所有属性
 * \33[1m 		设置高亮度
 * \33[2m 		设置一半高亮度
 * \33[4m 		下划线
 * \33[5m 		闪烁
 * \33[7m 		反显
 * \33[8m 		消隐
 * \33[22m 		设置一般密度
 * \33[24m		关闭下划线
 * \33[25m		关闭闪烁
 * \33[27m		关闭反显
 * \33[30m -- \33[37m 	设置前景色
 * \33[40m -- \33[47m 	设置背景色
 * \33[nA 		光标上移n行
 * \33[nB 		光标下移n行
 * \33[nC 		光标右移n行
 * \33[nD 		光标左移n行
 * \33[y;xH		设置光标位置
 * \33[2J 		清屏
 * \33[K 		清除从光标到行尾的内容
 * \33[s 		保存光标位置
 * \33[u 		恢复光标位置
 * \33[?25l 		隐藏光标
 * \33[?25h 		显示光标
 *
 * 同类的多种设置项可以组合在一起，中间用分号（;）隔开。如下：
 *  "\033[20;1H\033[1;4;32mHello,world\033[0m"
 */

#include "create.h"
#include "cdisk.h"
#include "cnet.h"
#include "vnet.h"
#include "zfs.h"

//#define BVM_DEBUG

vm_stru new_vm;
create_stru tbl[MM_MAX] = {0};
create_stru *sel[MM_MAX] = {0};
char *options = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/*
 * 创建菜单
 * create menu
 */
void create_init()
{
	/*-----table--desc------------value-----------------------------func--------------------arg-----edit----submenu*/
	add_item(tbl, "name",	      (char*)&new_vm.name,		enter_vm_name, 		0,	0,	0);
	add_item(tbl, "os",	      (char*)&new_vm.ostype, 		enter_vm_ostype,    	0,	0,	0);
	add_item(tbl, "version",      (char*)&new_vm.version, 		enter_vm_version,    	0,	1,	0);
	add_item(tbl, "cpus", 	      (char*)&new_vm.cpus, 		enter_vm_cpus,    	0,	1,	0);
	add_item(tbl, "ram", 	      (char*)&new_vm.ram,      		enter_vm_ram,        	0,	1,	0);
	
	add_item(tbl, "CD",	      (char*)&new_vm.cdstatus,      	enter_vm_cdstatus, 	0,	1,	0);
	add_item(tbl, "iso path",     (char*)&new_vm.iso,      		enter_vm_iso, 		0,	1,	0);
	add_item(tbl, "boot from",    (char*)&new_vm.bootfrom, 		enter_vm_bootfrom, 	0,	1,	0);
	add_item(tbl, "boot type",    (char*)&new_vm.boot_type, 		enter_vm_boot_type, 	0,	0,	0);
	add_item(tbl, "TPM (UEFI)",   (char*)&new_vm.tpmstatus, 	enter_vm_tpmstatus,	0,	1,	0);

	add_item(tbl, "shared folder", (char*)&new_vm.share_status, 	enter_vm_sharestatus,	0,	1,	0);
	add_item(tbl, "share name",   (char*)&new_vm.share_name, 	enter_vm_sharename,	0,	1,	0);
	add_item(tbl, "share path",   (char*)&new_vm.share_path, 	enter_vm_sharepath,	0,	1,	0);
	add_item(tbl, "share ro",     (char*)&new_vm.share_ro, 		enter_vm_sharero,	0,	1,	0);

	add_item(tbl, "VNC", 	      (char*)&new_vm.vncstatus,  	enter_vm_vncstatus,	0,	1,	0);
	add_item(tbl, "VNC bind",     (char*)&new_vm.vncbind,		enter_vm_vncbind,	0,	1,	0);
	add_item(tbl, "VNC port",     (char*)&new_vm.vncport,  		enter_vm_vncport,	0,	1,	0);
	add_item(tbl, "VNC width",    (char*)&new_vm.vncwidth, 		enter_vm_vncwidth, 	0,	1,	0);
	add_item(tbl, "VNC height",   (char*)&new_vm.vncheight,		enter_vm_vncheight, 	0,	1,	0);
	add_item(tbl, "VNC password", (char*)&new_vm.vncpassword,	enter_vm_vncpassword,	0,	1,	0);
	add_item(tbl, "VNC wait",     (char*)&new_vm.vncwait,		enter_vm_vncwait,	0,	1,	0);
	add_item(tbl, "audio", 	      (char*)&new_vm.audiostatus,  	enter_vm_audiostatus,	0,	1,	0);
	add_item(tbl, "hostbridge",   (char*)&new_vm.hostbridge, 	enter_vm_hostbridge,	0,	1,	0);
	add_item(tbl, "auto boot",    (char*)&new_vm.autoboot, 		enter_vm_autoboot,	0,	1,	0);
	add_item(tbl, "boot index",   (char*)&new_vm.bootindex, 	enter_vm_bootindex,	0,	1,	0);
	add_item(tbl, "boot time",    (char*)&new_vm.bootdelay, 	enter_vm_bootdelay,	0,	1,	0);

	add_item(tbl, "disk config",  NULL,				enter_vm_disk_config,	0,	1,	1);
	add_item(tbl, "network config", NULL,				enter_vm_network_config,0,	1,	1);
	//add_item(tbl, "driver config", NULL,				enter_vm_driver_config,	0,	1,	1);

	add_item(tbl, "cancel",		NULL,				exit_the_menu,		0,	1,	1);

}

// 设置固定的配置项
void set_const_config()
{
	sprintf(new_vm.profile,   "vm-%s", new_vm.ostype);
	sprintf(new_vm.disk,      "%s%s%s", vmdir, new_vm.name, "/disk.img");
	sprintf(new_vm.devicemap, "%s%s%s", vmdir, new_vm.name, "/device.map");
	//strcpy(new_vm.vncstatus,  "on");
	//strcpy(new_vm.vncwidth,	  "1024");
	//strcpy(new_vm.vncheight,  "768");
	strcpy(new_vm.status, 	  "off");
	strcpy(new_vm.lock,	  "0");

	if (strcmp(new_vm.ostype, "OpenBSD") != 0)
		strcpy(new_vm.version, "");
	for (int n=0; n<atoi(new_vm.nics); n++) {
		//strcpy(new_vm.nic[n].ip, "dhcp");
		if (strcmp(new_vm.nic[n].netmode, "NAT") != 0)
			strcpy(new_vm.nic[n].nat, "");
	}
}

// 设置驱动配置的默认值
void set_default_driver_config()
{
	if (strlen(new_vm.network_interface) == 0) 
		strcpy(new_vm.network_interface, "e1000");
	if (strlen(new_vm.storage_interface) == 0)
		strcpy(new_vm.storage_interface, "ahci-hd");
}

// 添加菜单项
void add_item(create_stru *table, char *desc, char *value, void (*func)(), int arg, int edit, int submenu)
{
	int n = 0;
	while (table[n].func) ++n;
	strcpy(table[n].desc, desc);
	table[n].value 	 = value;
	table[n].func 	 = func;
	table[n].arg 	 = arg;
	table[n].edit 	 = edit;
	table[n].submenu = submenu;
}


// 欢迎画面
void welcome()
{
	printf("---------------------------\n");
	printf("Welcome to \033[1mB\033[0mhyve \033[1mV\033[0mm \033[1mM\033[0manager\n");
	printf("---------------------------\n");
}

// 返回上级菜单
void goback_mainmenu(int not_use)
{
}


// 创建vm配置信息
void enter_vm(char *vm_name)
{
	int n = 0; //n=0是从name开始
	if (vm_name) {
		strcpy(new_vm.name, vm_name);
		n = 1; 
	}
	while (tbl[n].func) {
		if (tbl[n].submenu == 0)
			tbl[n].func(tbl[n].arg); 
		n++;
	}

	edit_vm(NULL);
}

// 编辑vm配置信息
void edit_vm(char *vm_name)
{
	char *msg = "Enter an number to edit or 'ok' to complet: ";
	show_all_enter();

	//非新建vm则只允许从版本号(min=2)开始编辑
	int min = 0, max = 0;
	if (vm_name != NULL) min = 2;

	char answer[8];
	while (1) {
	
		while (sel[max]) ++max;
		--max;
	
		printf("%s", msg);
		fgets(answer, sizeof(answer), stdin);
		answer[strlen(answer)-1] = '\0';

		for (int i=0; i<strlen(answer); i++)
			answer[i] = tolower(answer[i]);
		
		if (strcmp(answer, "ok") == 0) {
			if (check_enter_valid() == -1)
				continue;
			break;
		}

		//int n = strtoint(answer);
		int n = check_options(min, max, answer);

		if (n < min || n > max) { printf("\033[1A\033[K"); continue; }

		//排除不可编辑的选项
		if (vm_name != NULL) {
			if (!is_edit_item(tbl, sel, n)) { printf("\033[1A\033[K"); continue; }
		}

		//if (sel[n]) sel[n]();
		if (sel[n]) sel[n]->func(sel[n]->arg);
		show_all_enter();
	}

	set_const_config();
}

// 检测输入项的有效性
// 返回 -1 输入有误
// 返回 0  输入正确
int check_enter_valid()
{
	if (strcmp(new_vm.ostype, "OpenBSD") == 0)
		if (strlen(new_vm.version) == 0) {
			warn("version is invalid\n");
			return -1;
		}
	if (strcmp(new_vm.autoboot, "yes") == 0) {
		if (strlen(new_vm.bootindex) == 0) {
		       	warn("booting sequence index is invalid\n");
			return -1;
		}
		if (strlen(new_vm.bootdelay) == 0) {
			warn("booting estimate dealy time is invalid\n");
			return -1;
		}		
	}
	if (strcmp(new_vm.cdstatus, "on") == 0)
	       if (strlen(new_vm.iso) == 0) {
		       warn("iso path invalid\n");
		       return -1;
	       }

	if (strcmp(new_vm.share_status, "on") == 0) {
		if (strlen(new_vm.share_name) == 0) {
			warn("share name invalid\n");
			return -1;
		}
		if (strlen(new_vm.share_path) == 0) {
			warn("share path invalid\n");
			return -1;
		}
		if (strlen(new_vm.share_ro) == 0) {
			warn("share ro invalid\n");
			return -1;
		}
	}
	
	if (support_uefi(new_vm.ostype) && strcmp(new_vm.boot_type, "grub") != 0) {
		if (strlen(new_vm.vncstatus) == 0) {
			warn("VNC status invalid\n");
			return -1;
		}
		if (strlen(new_vm.vncport) == 0) {
			warn("VNC port invalid\n");
			return -1;
		}

		if (strlen(new_vm.vncwidth) == 0) {
			warn("VNC display width invalid\n");
			return -1;
		}
		if (strlen(new_vm.vncheight) == 0) {
			warn("VNC display height invalid\n");
			return -1;
		}
	}
	if (check_vm_disks(&new_vm) == -1) {
		warn("disk config invalid\n");
		return -1;
	}

	if (atoi(new_vm.nics) == 0) {
		warn("network config invalid\n");
		return -1;
	}

	// 用于模板创建的检测
	// 1. NAT模式下，未指定网卡则默认选择第一个网卡
	if (strcmp(new_vm.nic[0].netmode, "NAT") == 0 && strlen(new_vm.nic[0].bind) == 0) {
		get_nic_list(CABLE_AND_WIRELESS);
		strcpy(new_vm.nic[0].bind, nic_list[0]);
	}

	// 2. 检测 CPU 数量是否大于主机
	long host_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (atoi(new_vm.cpus) > host_cpus) {
		warn("The number of CPUs cannot be greater than the host (%ld)\n", host_cpus);
		return -1;
	}

	return 0;
	
}

// 字符串转化成整数
int strtoint(char *str)
{
	if (strlen(str) == 0) return -1;

	int n = 0;
	for (int i=0; i<strlen(str); i++) {
		if (str[i] >= '0' && str[i] <= '9')
			n = n * 10 + str[i] - '0';
		else {
			n = -1;
			break;
		}
	}
	return n;
}

// 判断是否为编辑项
//int is_edit_item(create_stru *tbl, void (*select[])(), int item)
int is_edit_item(create_stru *tbl, create_stru *select[], int item)
{
	int n = item;
	int x = 0;
	while (tbl[x].func) {
		if (tbl[x].func == select[n]->func)
			return tbl[x].edit;
		x++;
	}
	return -1;
}

// 判断是否为非输出项
int is_non_show_item(int item)
{
	int n = item;
	return
	((tbl[n].func == enter_vm_version && strcmp(new_vm.ostype, "OpenBSD") != 0) ||
	(tbl[n].func == enter_vm_iso && strcmp(new_vm.cdstatus, "off") == 0) ||
	 (tbl[n].func == enter_vm_boot_type && !support_uefi(new_vm.ostype)) ||
	 (tbl[n].func == enter_vm_tpmstatus && 
		(!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0)) ||
	 (tbl[n].func == enter_vm_sharename && strcmp(new_vm.share_status, "off") == 0) ||
	 (tbl[n].func == enter_vm_sharepath && strcmp(new_vm.share_status, "off") == 0) ||
	 (tbl[n].func == enter_vm_sharero && strcmp(new_vm.share_status, "off") == 0) ||
	 (tbl[n].func == enter_vm_vncstatus && 
		(!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0)) ||
	 (tbl[n].func == enter_vm_vncbind && 
		(!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0 || strcmp(new_vm.vncstatus, "off") == 0)) ||
	 (tbl[n].func == enter_vm_vncpassword && 
		(!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0 || strcmp(new_vm.vncstatus, "off") == 0)) ||
	 (tbl[n].func == enter_vm_vncwait && 
		(!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0 || strcmp(new_vm.vncstatus, "off") == 0)) ||
	 (tbl[n].func == enter_vm_vncport && 
		(!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0 || strcmp(new_vm.vncstatus, "off") == 0)) ||
	 (tbl[n].func == enter_vm_vncwidth && 
		(!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0 || strcmp(new_vm.vncstatus, "off") == 0)) ||
	 (tbl[n].func == enter_vm_vncheight && 
		(!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0 || strcmp(new_vm.vncstatus, "off") == 0)) ||
	 (tbl[n].func == enter_vm_bootindex && strcmp(new_vm.autoboot, "yes") != 0) ||
	 (tbl[n].func == enter_vm_bootdelay && strcmp(new_vm.autoboot, "yes") != 0));

}

// 显示所有的输入信息
void show_all_enter()
{
	static int first = 1;
	if (first) 
		first = 0;
	else 
		printf("---------------------------\n");

	int n = 0;
	int index = 0;
	while (tbl[n].func) {
		if (is_non_show_item(n));
		else {
			//sel[index] = tbl[n].func;
			sel[index] = &tbl[n];
			printf("[%c]. %-14s", options[index], tbl[n].desc);
			//printf("[%2d]. %-14s", index, tbl[n].desc);
			if (tbl[n].value)
				printf(": %s", tbl[n].value);
			printf("\n");
			++index;
		}
		++n;
	}
	sel[index] = NULL;
	printf("\n");
}

// vm_name 
// 虚拟机名称输入处理
void enter_vm_name(int not_use)
{
	char *msg = "Enter new vm name: ";
	
	vm_init();
	while (1) {
		printf("%s", msg);
		fgets(new_vm.name, sizeof(new_vm.name), stdin);
		new_vm.name[strlen(new_vm.name)-1] = '\0';
		if (check_spell(new_vm.name) == RET_SUCCESS) {
			vm_node *p;
			if ((p = find_vm_list(new_vm.name)) != NULL) {
				warn("%s already exist\n", new_vm.name);
			}
			else
				break;
		}
		else {
			warn("vm name invalid\n");
		}
	}
	vm_end();

}

// vm_ostype 
// 操作系统类型输入处理
void enter_vm_ostype(int not_use)
{
	char *msg = "Enter os type: ";
	char *os[OS_NUM] = {0};

	int i = 0;
	while (strlen(bvm_os[i].type) > 0) {
		os[i] = bvm_os[i].type;
		i++;
	}
	os[i] = NULL;
	enter_options(msg, os, NULL, (char*)&new_vm.ostype);
}

// vm_version
// 操作系统版本输入处理
void enter_vm_version(int not_use)
{
	if (strcmp(new_vm.ostype, "OpenBSD") != 0) return;

	char *msg = "Enter vm version: ";
	char *ver[] = { 
		"6.0",
		"6.1",
		"6.2",
		"6.3",
		"6.4",
		"other",
		NULL,
	};

	enter_options(msg, ver, NULL, (char*)&new_vm.version);
	if (strcmp(new_vm.version, (char*)ver[5]) == 0)
		enter_version("Enter other version: ", (char*)&new_vm.version);
}

// vm_zfs
// 使用zfs输入处理
void enter_vm_zfs(int not_use)
{
	if (!support_zfs()) {
		strcpy(new_vm.zfs, "none");
		return;
	}

	char *msg = "Enter ZFS support: ";
	char *opt[] = {
		"on",
		"off",
		NULL,
	};

	enter_options(msg, opt, NULL, (char*)&new_vm.zfs);
}

// vm_zpool
// 存储池输入处理
void enter_vm_zpool(int not_use)
{
	if (strcmp(new_vm.zfs, "on") != 0) return;

	char *msg = "Enter zpool: ";
	char *opts[ZPOOL_LISTSIZE] = {0};

	get_zpool_list();
	int n = 0;
	while (strlen(zpool_list[n]) > 0) {
		opts[n] = (char*)&zpool_list[n];
		++n;
	}

	enter_options(msg, opts, NULL, (char*)&new_vm.zpool);

}

// vm_disks
// 磁盘数量输入处理
void enter_vm_disks(int not_use)
{
	while (1) {
		char *msg = "Enter vm number of disks: ";
		enter_numbers(msg, NULL, (char*)&new_vm.disks);
		if (atoi(new_vm.disks) >= 1 && atoi(new_vm.disks) <= DISK_NUM) 
			break;
		else 
			warn("input invalid\n");
	}
}

// vm_vdisk
// 磁盘容量输入处理
void enter_vm_vdisk_size(int disk_ord)
{
	if (atoi(new_vm.disks) < disk_ord + 1) return;
	static int flag = 1;
	char msg[BUFFERSIZE];
	char hint[32];
	if (flag) {
		strcpy(hint, "(e.g. 5g): ");
		flag = 0;
	}
	else
		strcpy(hint, ": ");
	sprintf(msg, "Enter vm disk(%d) size %s", disk_ord, hint);
	enter_numbers(msg, "mMgGtT",  (char*)&new_vm.vdisk[disk_ord].size);
}

// vm_ram
// 内存容量输入处理
void enter_vm_ram(int not_use)
{
	char *msg = "Enter vm RAM (e.g. 512m): ";
	enter_numbers(msg, "mMgG", (char*)&new_vm.ram);
}

// vm_cpus
// CPU数量输入处理
void enter_vm_cpus(int not_use)
{
	char *msg = "Enter vm CPUs: ";
	char old_cpus[8];
	strcpy(old_cpus, new_vm.cpus); // 保存旧的 CPU 数量

	long host_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	while(1) {
		enter_numbers(msg, NULL, (char*)&new_vm.cpus);
		if (atoi(new_vm.cpus) > host_cpus)
			warn("The number of CPUs cannot be greater than the host (%ld)\n", host_cpus);
		else
			break;
	}

	// 检查 CPU 数量是否发生变化
	if (strcmp(old_cpus, new_vm.cpus) != 0) {
		// 如果数量变了，重置为默认推荐拓扑
		strcpy(new_vm.sockets, "1");
		strcpy(new_vm.cores, new_vm.cpus);
		strcpy(new_vm.threads, "1");
	} 
	// 如果没变，保留原有的 sockets/cores/threads 配置（从 load_vm_info 读取的）
	// 但为了防止旧配置为空（例如旧版本升级上来），还是要做个兜底检查
	else if (strlen(new_vm.sockets) == 0 || strlen(new_vm.cores) == 0 || strlen(new_vm.threads) == 0) {
		strcpy(new_vm.sockets, "1");
		strcpy(new_vm.cores, new_vm.cpus);
		strcpy(new_vm.threads, "1");
	}

	// 询问是否需要高级配置
	char advanced[16];
	printf("Advanced CPU topology? (Enter to skip or 'y' to enable): ");
	fgets(advanced, sizeof(advanced), stdin);
	advanced[strlen(advanced)-1] = '\0';
	
	// 转换为小写
	for (int i = 0; i < strlen(advanced); i++)
		advanced[i] = tolower(advanced[i]);
	
	
	if (strcmp(advanced, "y") == 0 || strcmp(advanced, "yes") == 0) {
		// 高级模式：让用户自定义 sockets, cores, threads
		int total_cpus = atoi(new_vm.cpus);
		
		printf("\n--- CPU Topology Configuration ---\n");
		printf("Recommended (Best Practice):\n");
		printf("  Sockets: 1, Cores: %d, Threads: 1\n", total_cpus);
		printf("  (Reason: Maximum OS compatibility, especially for Windows)\n\n");
		
		// 显示当前配置（如果与推荐值不同）
		int current_calc = atoi(new_vm.sockets) * atoi(new_vm.cores) * atoi(new_vm.threads);
		if (strcmp(new_vm.sockets, "1") != 0 || 
		    strcmp(new_vm.cores, new_vm.cpus) != 0 || 
		    strcmp(new_vm.threads, "1") != 0) {
			printf("Current Saved Configuration:\n");
			printf("  Sockets: %s, Cores: %s, Threads: %s\n", 
				new_vm.sockets, new_vm.cores, new_vm.threads);
			printf("  Total CPUs: %s × %s × %s = %d\n\n", 
				new_vm.sockets, new_vm.cores, new_vm.threads, current_calc);
		} else {
			printf("Current Configuration: Using recommended defaults\n\n");
		}
		
		char input[16];
		char prompt[64];
		
		while (1) {
			// Sockets
			sprintf(prompt, "Enter sockets (default: %s): ", new_vm.sockets);
			printf("%s", prompt);
			fgets(input, sizeof(input), stdin);
			input[strlen(input)-1] = '\0';
			if (strlen(input) > 0) strcpy(new_vm.sockets, input);
			
			// Cores
			sprintf(prompt, "Enter cores per socket (default: %s): ", new_vm.cores);
			printf("%s", prompt);
			fgets(input, sizeof(input), stdin);
			input[strlen(input)-1] = '\0';
			if (strlen(input) > 0) strcpy(new_vm.cores, input);
			
			// Threads
			sprintf(prompt, "Enter threads per core (default: %s): ", new_vm.threads);
			printf("%s", prompt);
			fgets(input, sizeof(input), stdin);
			input[strlen(input)-1] = '\0';
			if (strlen(input) > 0) strcpy(new_vm.threads, input);
			
			// 验证：sockets * cores * threads == cpus
			int calc_cpus = atoi(new_vm.sockets) * atoi(new_vm.cores) * atoi(new_vm.threads);
			if (calc_cpus == total_cpus) {
				break;
			} else {
				warn("Invalid topology: %s × %s × %s = %d, but CPUs = %d\n",
					new_vm.sockets, new_vm.cores, new_vm.threads, calc_cpus, total_cpus);
				// 重置为默认值
				strcpy(new_vm.sockets, "1");
				strcpy(new_vm.cores, new_vm.cpus);
				strcpy(new_vm.threads, "1");
			}
		}
	}
}

// vm_bootfrom
// 启动方式输入处理
void enter_vm_bootfrom(int not_use)
{
	char *msg = "Enter boot from: ";
	char *cd_hd_opts[] = {
		"cd0",
		"hd0",
		NULL,
	};

	char *hd_opts[] = {
		"hd0",
		NULL,
	};

	char **opts;
	if (strcmp(new_vm.cdstatus, "off") == 0)
		opts = hd_opts;
	else
		opts = cd_hd_opts;
	enter_options(msg, opts, NULL, (char*)&new_vm.bootfrom);

	// 自动调整 VNC wait 选项
	// 如果是 UEFI 启动且从光盘启动，通常需要安装，开启 wait 以便连接 VNC
	// 否则关闭 wait
	if (strcmp(new_vm.boot_type, "grub") != 0) {
		if (strcmp(new_vm.bootfrom, "cd0") == 0)
			strcpy(new_vm.vncwait, "on");
		else
			strcpy(new_vm.vncwait, "off");
	}
}

// vm_boot_type
// boot type启动模式输入处理
void enter_vm_boot_type(int not_use)
{
	if (!support_uefi(new_vm.ostype)) {
		strcpy(new_vm.boot_type, "grub");
		return;
	}

	char *msg = "Enter boot type: ";
	
	// 检查 UEFI CSM 固件文件是否存在
	int has_csm = (access("/usr/local/share/uefi-firmware/BHYVE_UEFI_CSM.fd", F_OK) == 0);
	
	char *opts_grub_and_uefi[] = {
		"grub",
		"uefi",
		has_csm ? "uefi_csm" : NULL,
		NULL,
	};

	char *opts_only_uefi[] = {
		"uefi",
		has_csm ? "uefi_csm" : NULL,
		NULL,
	};
	
	char **opts;
	if (support_grub(new_vm.ostype) == 0)
		opts = opts_only_uefi;
	else
		opts = opts_grub_and_uefi;

	// 提示用户推荐使用 UEFI 启动模式
	printf("\033[33m[Tips] UEFI boot is recommended for better stability.\033[0m\n");

	enter_options(msg, opts, NULL, (char*)&new_vm.boot_type);

	// 自动调整 VNC wait 选项
	if (strcmp(new_vm.boot_type, "grub") != 0) {
		if (strcmp(new_vm.bootfrom, "cd0") == 0)
			strcpy(new_vm.vncwait, "on");
		else
			strcpy(new_vm.vncwait, "off");
	}
}

// vm_vncstatus
// vnc状态输入处理
void enter_vm_vncstatus(int not_use)
{
	if (!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0) return;
	char *msg = "Enter vnc: ";
	char *opts[] = {
		"on",
		"off",
		NULL,
	};

	enter_options(msg, opts, NULL, (char*)&new_vm.vncstatus);
}

// vm_audiostatus
// 音频状态输入处理
void enter_vm_audiostatus(int not_use)
{
	if (!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0) return;
	char *msg = "Enter audio: ";
	char *opts[] = {
		"on",
		"off",
		NULL,
	};

	enter_options(msg, opts, NULL, (char*)&new_vm.audiostatus);
}

// vm_vncpassword
// VNC密码输入处理
void enter_vm_vncpassword(int not_use)
{
	if (!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0 || strcmp(new_vm.vncstatus, "off") == 0) return;
	char *msg = "Enter VNC password (leave empty for no password): ";
	printf("%s", msg);
	bvm_gets(new_vm.vncpassword, sizeof(new_vm.vncpassword), BVM_ECHO);
}

// vm_vncwait
// VNC wait选项输入处理
void enter_vm_vncwait(int not_use)
{
	if (!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0 || strcmp(new_vm.vncstatus, "off") == 0) return;
	char *msg = "Enter VNC wait: ";
	char *opts[] = {
		"on",
		"off",
		NULL,
	};

	enter_options(msg, opts, NULL, (char*)&new_vm.vncwait);
}

// vm_vncbind
// VNC绑定地址输入处理
void enter_vm_vncbind(int not_use)
{
	if (!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0 || strcmp(new_vm.vncstatus, "off") == 0) return;
	char *msg = "Enter VNC bind address (default 0.0.0.0): ";
	while (1) {
		printf("%s", msg);
		bvm_gets(new_vm.vncbind, sizeof(new_vm.vncbind), BVM_ECHO);
		if (strlen(new_vm.vncbind) == 0) {
			strcpy(new_vm.vncbind, "0.0.0.0");
			break;
		}
		// 验证IP地址格式（使用inet_pton）
		struct in_addr addr;
		if (inet_pton(AF_INET, new_vm.vncbind, &addr) > 0) {
			break;
		}
		error("Invalid IP address format\n");
		printf("\033[1A\033[K"); // 清除上一行
	}
}

// vm_vncport
// vnc端口输入处理
void enter_vm_vncport(int not_use)
{
	if (!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0 || strcmp(new_vm.vncstatus, "off") == 0) return;
	char *msg = "Enter VNC port: ";
	enter_numbers(msg, NULL, (char*)&new_vm.vncport);
}

// vm_vncwidth
// vnc屏幕宽度输入处理
void enter_vm_vncwidth(int not_use)
{
	if (!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0 || strcmp(new_vm.vncstatus, "off") == 0) return;
	char *msg = "Enter VNC display width: ";
	enter_numbers(msg, NULL, (char*)&new_vm.vncwidth);
}

// vm_vncheight
// vnc屏幕高度输入处理
void enter_vm_vncheight(int not_use)
{
	if (!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0 || strcmp(new_vm.vncstatus, "off") == 0) return;
	char *msg = "Enter VNC display height: ";
	enter_numbers(msg, NULL, (char*)&new_vm.vncheight);
}

// vm_nics
// 网卡数量输入处理
void enter_vm_nics(int not_use)
{
	while (1) {
		char *msg = "Enter vm number of nics: ";
		enter_numbers(msg, NULL, (char*)&new_vm.nics);
		if (atoi(new_vm.nics) >= 1 && atoi(new_vm.nics) <= NIC_NUM) 
			break;
		else 
			warn("input invalid\n");
	}

}

// vm_hostbridge
// 桥接方式输入处理
void enter_vm_hostbridge(int not_use)
{
	char *msg = "Enter hostbridge: ";
	char *opts[] = {
		"hostbridge",
		"amd_hostbridge",
		NULL,
	};

	enter_options(msg, opts, NULL, (char*)&new_vm.hostbridge);
}

// vm_autoboot
// 自动启动输入处理
void enter_vm_autoboot(int not_use)
{
	char *msg = "Enter auto booting: ";
	char *opts[] = {
		"no",
		"yes",
		NULL,
	};

	enter_options(msg, opts, NULL, (char*)&new_vm.autoboot);
}

// vm_bootindex
// 启动顺序输入处理
void enter_vm_bootindex(int not_use)
{
	if (strcmp(new_vm.autoboot, "no") == 0) return;

	while (1) {
		char *msg = "Enter booting sequence index (1~1000): ";
		enter_numbers(msg, NULL, (char*)&new_vm.bootindex);
		if (atoi(new_vm.bootindex) >0 && atoi(new_vm.bootindex) <= 1000)
			break;
		else
			warn("input invalid\n");
	}
}

// vm_bootdealy
// 启动延迟输入处理
void enter_vm_bootdelay(int not_use)
{
	if (strcmp(new_vm.autoboot, "no") == 0) return;

	while (1) {
		char *msg = "Enter booting estimate time (1~1000 secs.): ";
		enter_numbers(msg, NULL, (char*)&new_vm.bootdelay);
		if (atoi(new_vm.bootdelay) > 0 && atoi(new_vm.bootdelay) <= 1000)
			break;
		else
			warn("input invalid\n");
	}
}

// vm_tpmstatus
// TPM状态输入处理
void enter_vm_tpmstatus(int not_use)
{
	// TPM需要UEFI模式
	if (!support_uefi(new_vm.ostype) || strcmp(new_vm.boot_type, "grub") == 0) {
		strcpy(new_vm.tpmstatus, "off");
		return;
	}
	
	char *msg = "Enter TPM status: ";
	char *opts[] = {
		"on",
		"off",
		NULL,
	};
	
	enter_options(msg, opts, NULL, (char*)&new_vm.tpmstatus);
	
	// 如果启用TPM，自动设置版本为2.0
	if (strcmp(new_vm.tpmstatus, "on") == 0) {
		strcpy(new_vm.tpmversion, "2.0");
	}
}

// vm_sharestatus
// VirtIO-9P共享状态输入处理
void enter_vm_sharestatus(int not_use)
{
	char *msg = "Enable shared folder: ";
	char *opts[] = {
		"on",
		"off",
		NULL,
	};
	
	enter_options(msg, opts, NULL, (char*)&new_vm.share_status);
	
	// 如果启用共享，设置默认值
	if (strcmp(new_vm.share_status, "on") == 0) {
		if (strlen(new_vm.share_name) == 0)
			strcpy(new_vm.share_name, "hostshare");
		if (strlen(new_vm.share_ro) == 0)
			strcpy(new_vm.share_ro, "off");
	}
}

// vm_sharename
// VirtIO-9P共享名称输入处理
void enter_vm_sharename(int not_use)
{
	if (strcmp(new_vm.share_status, "on") != 0) return;
	
	char *msg = "Enter share name (used in guest): ";
	
	while (1) {
		printf("%s", msg);
		bvm_gets(new_vm.share_name, sizeof(new_vm.share_name), BVM_ECHO);
		
		if (strlen(new_vm.share_name) == 0) {
			strcpy(new_vm.share_name, "hostshare");
			break;
		}
		
		// 验证共享名称只包含字母数字和下划线
		int valid = 1;
		for (int i = 0; i < strlen(new_vm.share_name); i++) {
			char c = new_vm.share_name[i];
			if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
			      (c >= '0' && c <= '9') || c == '_')) {
				valid = 0;
				break;
			}
		}
		
		if (valid)
			break;
		else
			warn("share name can only contain letters, numbers, and underscores\n");
	}
}

// vm_sharepath
// VirtIO-9P共享目录路径输入处理
void enter_vm_sharepath(int not_use)
{
	if (strcmp(new_vm.share_status, "on") != 0) return;
	
	char *msg = "Enter host directory to share: ";
	
	while (1) {
		printf("%s", msg);
		bvm_gets(new_vm.share_path, sizeof(new_vm.share_path), BVM_ECHO);
		
		if (strlen(new_vm.share_path) == 0) {
			warn("path cannot be empty\n");
			continue;
		}
		
		// 验证路径必须是绝对路径
		if (new_vm.share_path[0] != '/') {
			warn("path must be an absolute path (start with /)\n");
			continue;
		}
		
		// 验证路径存在
		struct stat st;
		if (stat(new_vm.share_path, &st) != 0) {
			warn("path does not exist\n");
			continue;
		}
		
		// 验证路径是目录
		if (!S_ISDIR(st.st_mode)) {
			warn("path must be a directory\n");
			continue;
		}
		
		break;
	}
}

// vm_sharero
// VirtIO-9P只读模式输入处理
void enter_vm_sharero(int not_use)
{
	if (strcmp(new_vm.share_status, "on") != 0) return;
	
	char *msg = "Enter share read-only mode: ";
	char *opts[] = {
		"on",
		"off",
		NULL,
	};
	
	enter_options(msg, opts, NULL, (char*)&new_vm.share_ro);
}

// 磁盘配置
void enter_vm_disk_config(int not_use)
{
	disk_config_init();
	create_disk_config();
}

// 网络配置
void enter_vm_network_config(int not_use)
{
	network_config_init();
	create_network_config();
}

// 驱动配置
/*
void enter_vm_driver_config(int not_use)
{
	set_default_driver_config();

	driver_config_init();
	create_driver_config();
}
*/

// 退出菜单系统
void exit_the_menu(int not_use)
{
	err_exit();
}

// vm_netmode
// 网络模式输入处理
void enter_vm_netmode(char *msg, char *value)
{
	char *opts[] = {
		"Bridged",
		"NAT",
		NULL,
	};

	enter_options(msg, opts, NULL, value);
	
}

// vm_rpstatus
// 是否开启端口转发输入处理
void enter_vm_rpstatus(char *netmode, char *value)
{
	if (strcmp(netmode, "NAT") != 0) return;

	char *msg = "Enter port redirection status: ";
	char *opts[] = {
		"disable",
		"enable",
		NULL,
	};

	enter_options(msg, opts, NULL, value);
}

// vm_rplist
// 端口映射列表输入处理
void enter_vm_rplist(char *netmode, char *value)
{
	if (strcmp(netmode, "NAT") != 0) return;

	char *msg = "Format: vm-port:host-port, vm-port:host-port,...\nEnter redirect port list (e.g. 22:2224,tcp 80:8080,udp 53:53...): ";

	printf("%s", msg);
	fgets(value, PORT_LIST_LEN, stdin);
	value[strlen(value) - 1] = '\0';
}


// 设置端口转发列表
// 用于在虚拟机运行中动态设置端口转发
int set_portlist(char *ip)
{
	char vm_name[32];
	int nic_index;
	find_vm_stru vm;
	vm.vm_name = vm_name;
	vm.nic_index = &nic_index;

	if (find_vm_by_ip(ip, &vm, NULL) == RET_FAILURE) {
		error("the IP address does not exist or is an error\n");
		return RET_FAILURE;
	}

	load_vm_info(vm_name, &new_vm);

	if (strcmp(new_vm.nic[nic_index].rpstatus, "enable") != 0) {
		error("port redirection for this IP is disabled\n");
		return RET_FAILURE;
	}

	//开始设置端口转发列表
	printf("current port redirection list: ");
	warn("%s\n", new_vm.nic[nic_index].rplist);

	enter_vm_rplist_proc(nic_index);
	save_vm_info(vm_name, &new_vm);
	success("ok!\n");

	return 0;
}


// 检测端口映射列表输入的有效性
// 返回 -1：错误
// 返回  0：列表为空 
int check_portlist(char *portlist, int nic_idx)
{
	//初始化端口映射表
	for (int i=0; i<PORT_NUM; i++) {
		new_vm.nic[nic_idx].ports[i].vm_port   = -1;
		new_vm.nic[nic_idx].ports[i].host_port = -1;
		strcpy(new_vm.nic[nic_idx].ports[i].proto, "tcp");
	}

	//删除掉列表两侧的空格
	trim(portlist);
	if (strlen(portlist) == 0) return 0;

	//对于列表中包含非法字符的均视为错误
	for (int i=0; i<strlen(portlist)-1; i++)
		if (!isdigit(portlist[i]) && portlist[i] != ':' && portlist[i] != ',' && !isblank(portlist[i])
			&& portlist[i] != 't' && portlist[i] != 'c' && portlist[i] != 'p'
			&& portlist[i] != 'u' && portlist[i] != 'd')
			return -1;

	//分割
	char proto[PROTO_LEN];
	int lport, hport;
	int m = 0, n = 0;
	int count = 0;
	
	while (strlen(portlist) > (m + n)) {

		portlist += n;
		trim(portlist);

		//获取协议
		#ifdef BVM_DEBUG 
		error("%s\n", portlist);
		#endif
		if (get_proto(proto, portlist) == -1) 
			return -1;
		else {
			trim(portlist);
			if (strlen(portlist) == 0) return 0;
		}

		//获取本地端口号
		m = split_portlist(&lport, portlist, ':');
		portlist += m;

		//获取宿主机端口号
		n = split_portlist(&hport, portlist, ',');
		#ifdef BVM_DEBUG
		warn("proto=%s\n", proto);
		warn("len=%d, port=%d\n", m, lport);
		warn("len=%d, port=%d\n", n, hport);
		#endif
		if (m != -1 && n != -1) {
			new_vm.nic[nic_idx].ports[count].vm_port   = lport;
			new_vm.nic[nic_idx].ports[count].host_port = hport;
			strcpy(new_vm.nic[nic_idx].ports[count].proto, proto);

			scan_redirect_port_stru check;
			int ret = 1;
			check.vm_name = new_vm.name;
			check.port = &new_vm.nic[nic_idx].ports[count];
			check.ret = &ret;

			vm_show_ports(SP_VALID, &check);
			if (ret == RET_FAILURE) {
				error("port %d has been occupied by other vm\n", check.port->host_port);
				return -1;
			}
			else
				++count;
		}
		else 
			break;
	}

	//保存端口转发的数量
	new_vm.nic[nic_idx].rpnum = count;

	#ifdef BVM_DEBUG
	warn("count=%d\n", count);
	#endif

	//将结果重新写入rplist
	strcpy(new_vm.nic[nic_idx].rplist, "");
	for (int i=0; i<count; i++) {
		char str[PORT_LIST_LEN] = {0};
		sprintf(str, "%s %d:%d,", 	new_vm.nic[nic_idx].ports[i].proto,
						new_vm.nic[nic_idx].ports[i].vm_port,
						new_vm.nic[nic_idx].ports[i].host_port);
		strcat(new_vm.nic[nic_idx].rplist, str);
	}
	new_vm.nic[nic_idx].rplist[strlen(new_vm.nic[nic_idx].rplist) - 1] = '\0';
	
	#ifdef BVM_DEBUG
	warn("rplist=%s\n", new_vm.nic[nic_idx].rplist);
	#endif
	
	//返回获取到的映射数量
	return count;
}

// 获得端口映射表的协议文字
// 参数
//    proto	: 分离出的协议
//    protlist	: 端口映射表
// 返回值
//    获取失败，返回 -1
//    否则，返回指针移动的距离
int get_proto(char *proto, char *portlist)
{
	int n = 0;
	char str[PROTO_LEN];

	// 映射表长度过短
	if (strlen(portlist) < 3) return -1;

	// 映射表为数字开头默认为 tcp 协议
	if (isdigit(portlist[n])) {
		strcpy(proto, "tcp");
		return 0;
	}

	// 对映射表前3个字符进行对比
	char *p = portlist;
	for (n=0; n<3; n++)
		str[n] = portlist[n];
	str[n] = '\0';
	if (strcmp(strtolower(str), "tcp") == 0) {
		strcpy(proto, "tcp");
		p += 3;
	}
	else if (strcmp(strtolower(str), "udp") == 0) {
		strcpy(proto, "udp");
		p += 3;
	}
	else
		return -1;

	strcpy(portlist, p);
	return strlen(str);
}


// 拆分端口映射列表
// 参数 
//    port 	: 拆分后得到的端口号
//    portlist 	: 端口映射列表
//    sep	: 分隔符
// 返回值
//    列表不合法，拆分失败，返回 -1
//    否则，返回指针移动的距离
int split_portlist(int *port, char *portlist, char sep)
{
	#ifdef BVM_DEBUG
	warn("portlist=%s, sep=%c\n", portlist, sep);
	#endif

	*port = 0;
	char ch;
	int flag = 0;
	int n = 0;	//指针移动的距离
	while ((ch = portlist[n++])) {
		if (ch == sep) {
			#ifdef BVM_DEBUG
			warn("port=%d\n", *port);
			#endif
			return n;
		}
		if (ch == ' ' || ch == '\t') {
			if (*port == 0) 
				continue;
			else
				flag = 1;
		}
		else {
			if (isdigit(ch) && flag == 0)
				*port = *port * 10 + ch - '0';
			else
				break;
				
		}
	}
	if (sep == ':') {
		#ifdef BVM_DEBUG
		warn("error\n");
		#endif
		return -1;
	}
	else {
		#ifdef BVM_DEBUG
		warn("port=%d\n", *port);
		#endif
		return n;
	}
}

// vm_bind
// 绑定网卡输入处理
void enter_vm_bind(char *netmode, char *rpstatus, char *value)
{
	enum {
		BIND_NOTHING = -1,	//什么也不做
		BIND_BRIDGED = 0,	//桥接绑定
		BIND_NAT_REDIRECT,	//端口重定向绑定
	};

	int type = CABLE_AND_WIRELESS;
	int flag = BIND_NOTHING;
	if (strcmp(netmode, "Bridged") == 0) { 
		flag = BIND_BRIDGED;
		type = CABLE;
	}
	else if (strcmp(netmode, "NAT") == 0) 
		flag = BIND_NAT_REDIRECT;
	//if (strcmp(netmode, "NAT") == 0 && strcmp(rpstatus, "enable") == 0) flag = BIND_NAT_REDIRECT;

	if (flag == BIND_NOTHING) return;

	char *msg = "Select the binding device: ";
	char *opts[VNET_LISTSIZE] = {0};
	char *desc[VNET_LISTSIZE] = {0};

	get_nic_list(type);
	load_switch_list();

	int idx = 0;
	int n = 0;
	while (strlen(nic_list[n]) > 0) {
		opts[idx] = (char*)&nic_list[n];
		desc[idx] = (char*)&nic_list[n];
		++idx;
		++n;
	}

	//保存一下物理网卡的数量
	int pn = n;

	//当做桥接绑定时需要添加虚拟交换机列表
	n = 0;
	int g_idx = idx;
	if (flag == BIND_BRIDGED)
		while (switch_list[n]) {
			desc[idx] = (char*)malloc(BUFFERSIZE * sizeof(char));
			memset(desc[idx], 0, BUFFERSIZE * sizeof(char));
			strcpy(desc[idx], switch_list[n]->name);
			strncat(desc[idx], "  ", 2);
			strncat(desc[idx], switch_list[n]->ip, sizeof(switch_list[n]->ip));

			opts[idx] = (char*)&switch_list[n]->name;
			++idx;
			++n;
	}

	//当做端口重定向并只有一块物理网卡时
	//直接填写绑定的网卡名称，无需进行选择录入
	if (flag == BIND_NAT_REDIRECT && pn == 1)
		strcpy(value, nic_list[0]);
	else
		enter_options(msg, opts, desc, value);

	//释放空间
	while (idx >= g_idx) {
		if (desc[idx]) free(desc[idx]);
		--idx;
	}

	free_vnet_list(NAT);
}

/*
// vm_bind
// 绑定网卡输入处理
void enter_vm_bind(char *netmode, char *value)
{
	if (strcmp(netmode, "Bridged") != 0) return;

	char *msg = "Select the binding device: ";
	char *opts[VNET_LISTSIZE] = {0};
	char *desc[VNET_LISTSIZE] = {0};

	get_nic_list();
	load_switch_list();

	int idx = 0;
	int n = 0;
	while (strlen(nic_list[n]) > 0) {
		opts[idx] = (char*)&nic_list[n];
		desc[idx] = (char*)&nic_list[n];
		++idx;
		++n;
	}

	n = 0;
	int g_idx = idx;
	while (switch_list[n]) {
		desc[idx] = (char*)malloc(BUFFERSIZE * sizeof(char));
		memset(desc[idx], 0, BUFFERSIZE * sizeof(char));
		strcpy(desc[idx], switch_list[n]->name);
		strncat(desc[idx], "  ", 2);
		strncat(desc[idx], switch_list[n]->ip, sizeof(switch_list[n]->ip));

		opts[idx] = (char*)&switch_list[n]->name;
		++idx;
		++n;
	}

	enter_options(msg, opts, desc, value);

	while (idx >= g_idx) {
		if (desc[idx]) free(desc[idx]);
		--idx;
	}

	free_vnet_list(NAT);
}*/

// vm_nat
// NAT网络输入处理
void enter_vm_nat(char *netmode, char *value)
{
	if (strcmp(netmode, "NAT") != 0) return;

	char *msg = "Enter gateway: ";
	char *nat_opts[VNET_LISTSIZE] = {0};
	char *nat_desc[VNET_LISTSIZE] = {0};

	load_nat_list();

	int n = 0;
	while (nat_list[n]) {
		
		nat_desc[n] = (char*)malloc(BUFFERSIZE * sizeof(char));
		memset(nat_desc[n], 0, BUFFERSIZE * sizeof(char));
		strcpy(nat_desc[n], nat_list[n]->name);
		strncat(nat_desc[n], "  ", 2);
		strncat(nat_desc[n], nat_list[n]->ip, sizeof(nat_list[n]->ip));

		nat_opts[n] = (char*)&nat_list[n]->name;
		++n;
	}

	enter_options(msg, nat_opts, nat_desc, value);

	while (n >= 0) {
		if (nat_desc[n]) free(nat_desc[n]);
		--n;
	}

	free_vnet_list(NAT);
}

// vm_ip
// IP地址输入处理
void enter_vm_ip(char *value)
{
	char *msg = "Enter IP-Address: ";
	char *opts[] = {
		"none",
		"dhcp",
		"static",
		NULL
	};

	enter_options(msg, opts, NULL, value);

	if (strcmp(value, opts[2]) == 0) 
		enter_static_ipv4(value);	
}

// 输入IPv4
void enter_static_ipv4(char *value)
{
	char *msg = "static ip: ";
	char ip[32] = {0};
	while (1) {
		printf("%s", msg);
		fgets(ip, sizeof(ip), stdin);
		ip[strlen(ip) - 1] = '\0';
		if (check_ip(ip)) 
			break;
		else
			warn("invalid IPv4 address\n");
	}
	strcpy(value, ip);
}

// 从nat/switch设备中选择
void enter_vm_device(char *value)
{
	char *msg = "Select device: ";
	char *opts[VNET_LISTSIZE] = {0};
	char *desc[VNET_LISTSIZE] = {0};

	load_nat_list();
	load_switch_list();

	int idx = 0;
	int n = 0;

	{
		desc[n] = (char*)malloc(BUFFERSIZE * sizeof(char));
		memset(desc[n], 0, BUFFERSIZE * sizeof(char));
		strcpy(desc[n], VNET_DEFAULT_BRIDGE);
		opts[n] = desc[n];
		++idx;
		++n;
	}

	n = 0;
	while (nat_list[n]) {
		
		desc[idx] = (char*)malloc(BUFFERSIZE * sizeof(char));
		memset(desc[idx], 0, BUFFERSIZE * sizeof(char));
		strcpy(desc[idx], nat_list[n]->name);
		strncat(desc[idx], "\t", 1);
		strncat(desc[idx], nat_list[n]->ip, sizeof(nat_list[n]->ip));

		opts[idx] = (char*)&nat_list[n]->name;
		++idx;
		++n;
	}

	n = 0;
	int g_idx = idx;
	while (switch_list[n]) {
		desc[idx] = (char*)malloc(BUFFERSIZE * sizeof(char));
		memset(desc[idx], 0, BUFFERSIZE * sizeof(char));
		strcpy(desc[idx], switch_list[n]->name);
		strncat(desc[idx], "\t", 1);
		strncat(desc[idx], switch_list[n]->ip, sizeof(switch_list[n]->ip));

		opts[idx] = (char*)&switch_list[n]->name;
		++idx;
		++n;
	}

	enter_options(msg, opts, desc, value);

	while (idx >= g_idx) {
		if (desc[idx]) free(desc[idx]);
		--idx;
	}

	free_vnet_list(NAT);

}

// 网络模式输入前端接口
void enter_vm_netmode_proc(int nic_idx)
{
	if (atoi(new_vm.nics) < (nic_idx + 1)) return;
	char msg[BUFFERSIZE];
	sprintf(msg, "Enter nic-%d network mode: ", nic_idx);

	//变量old也是为了下面的清理做铺垫
	char old[32];
	strcpy(old, new_vm.nic[nic_idx].netmode);

	enter_vm_netmode(msg, (char*)&new_vm.nic[nic_idx].netmode);

	//当改变网络模式后需要将绑定的网卡清理一下
	//例如：当模式为Bridged-switch
	//      如果变更为NAT而switch会依旧保留
	//      就会形成NAT-switch的局面
	if (strcmp(new_vm.nic[nic_idx].netmode, old) != 0)
		strcpy(new_vm.nic[nic_idx].bind, "");
}

// 是否开启端口转发前端接口
void enter_vm_rpstatus_proc(int nic_idx)
{
	enter_vm_rpstatus(new_vm.nic[nic_idx].netmode, (char*)&new_vm.nic[nic_idx].rpstatus);

	//确保端口转发状态为enable时ip地址的有效性
	//ip地址为 none/dhcp 时，将ip地址一栏清空
	//bind也随之一起清空
	if (strcmp(new_vm.nic[nic_idx].rpstatus, "enable") == 0)
		if (!check_ip(new_vm.nic[nic_idx].ip)) {
			strcpy(new_vm.nic[nic_idx].ip, "");
			//strcpy(new_vm.nic[nic_idx].bind, "");
		}
}

// 端口转发列表输入前端接口
void enter_vm_rplist_proc(int nic_idx)
{
	if (strcmp(new_vm.nic[nic_idx].rpstatus, "enable") != 0) return;
	while (1) {
		enter_vm_rplist(new_vm.nic[nic_idx].netmode, (char*)&new_vm.nic[nic_idx].rplist);
		if (check_portlist((char*)&new_vm.nic[nic_idx].rplist, nic_idx) > 0)
			break;
		else
			warn("invalid redirect-port list\n");
	}
}

// 网卡绑定输入前端接口
void enter_vm_bind_proc(int nic_idx)
{
	if (atoi(new_vm.nics) < (nic_idx + 1)) return;
	//enter_vm_bind(new_vm.nic[nic_idx].netmode, (char*)&new_vm.nic[nic_idx].bind);
	enter_vm_bind(new_vm.nic[nic_idx].netmode, new_vm.nic[nic_idx].rpstatus, (char*)&new_vm.nic[nic_idx].bind);
}

// NAT输入前端接口
void enter_vm_nat_proc(int nic_idx)
{
	enter_vm_nat(new_vm.nic[nic_idx].netmode, (char*)&new_vm.nic[nic_idx].nat);
}

// 网卡IP地址输入处理
void enter_vm_ip_proc(int nic_idx)
{
	if (atoi(new_vm.nics) < (nic_idx + 1)) return;

	if (strcmp(new_vm.nic[nic_idx].rpstatus, "enable") != 0)
		enter_vm_ip((char*)&new_vm.nic[nic_idx].ip);
	else
		enter_static_ipv4((char*)&new_vm.nic[nic_idx].ip);

	if (check_ip(new_vm.nic[nic_idx].ip)) {
		while (1) {
			char ip[32];
			strcpy(ip, new_vm.nic[nic_idx].ip);
			get_ip(ip);
	
			if (find_vm_by_ip(ip, NULL, &new_vm) == RET_SUCCESS) { //found same IP
				warn("found same ip\n");
				enter_static_ipv4((char*)&new_vm.nic[nic_idx].ip);
			}
			else { //No found same IP
				//warn("no found same ip\n");
				break;
			}
		}
	}
}

// vm_cdstatus
// cd状态输入处理
void enter_vm_cdstatus(int not_use)
{
	char *msg = "Enter cd status: ";
	char *opts[] = {
		"on",
		"off",
		NULL,
	};

	enter_options(msg, opts, NULL, (char*)&new_vm.cdstatus);
	if (strcmp(new_vm.cdstatus, "off") == 0)
		strcpy(new_vm.bootfrom, "hd0");
}


// vm_iso
// ISO文件输入处理
void enter_vm_iso(int not_use)
{
	if (strcmp(new_vm.cdstatus, "on") != 0) return;

	char *msg = "Enter iso path for CD-ROM: ";
	char *dir_opts[BUFFERSIZE] = {0};
	char *dir_desc[BUFFERSIZE] = {0};

	int n;
	while (1) {
		printf("%s", msg);
		fgets(new_vm.iso, sizeof(new_vm.iso), stdin);
		new_vm.iso[strlen(new_vm.iso)-1] = '\0';

		n = get_filelist(new_vm.iso, dir_opts, dir_desc);
		if (n < 0)
			warn("input invalid\n");
		if (n == 0)
			warn("no iso files\n");
		if (n > 0) {
			break;
		}
	}

	enter_options("Enter a iso file: ", dir_opts, dir_desc, (char*)&new_vm.iso);

	while (n >= 0) {
		if (dir_opts[n]) free(dir_opts[n]);
		if (dir_desc[n]) free(dir_desc[n]);
		--n;
	}
}

// vm_network_interface
// 输入网络接口驱动
void enter_vm_network_interface(int not_use)
{
	char *msg = "Enter network interface: ";
	char *opt[] = {
		"e1000",
		"virtio-net",
		NULL,
	};

	char *desc[] = {
		"Intel e82545 network interface [e1000]",
		"Virtio network interface [virtio-net]",
		NULL,
	};

	char *opt_uefi[] = {
		"virtio-net",
		NULL,
	};

	char *desc_uefi[] = {
		"Virtio network interface [virtio-net]",
		NULL,
	};

	char **opts, **descs;
	if (strcmp(new_vm.boot_type, "uefi") == 0) {
		opts = opt_uefi;
		descs = desc_uefi;
	} 
	else {
		opts = opt;
		descs = desc;
	}

	enter_options(msg, opts, descs, (char*)&new_vm.network_interface);

}

// vm_storage_interface
// 输入存储接口驱动
void enter_vm_storage_interface(int not_use)
{
	char *msg = "Enter storage interface: ";
	char *opt[] = {
		"ahci-hd",
		"virtio-blk",
		"nvme",
		//"virtio-scsi",
		NULL,
	};

	char *desc[] = {
		"SATA hard-drive [ahci-hd]",
		"Virtio block storage interface [virtio-blk]",
		"NVM Express (NVMe) controller [nvme]",
		//"Virtio SCSI interface [virtio-scsi]",
		NULL,
	};

	enter_options(msg, opt, desc, (char*)&new_vm.storage_interface);

}

// 获得目录中文件列表
// 返回值：目录中文件个数（不包含 . 和 ..）
//         错误返回-1
int get_filelist(char *dir, char **opt, char **opt_desc)
{
	DIR *dp;
	struct dirent *dirp;

	if ((dp = opendir(dir)) == NULL) {
		error("can't open %s\n", dir);
		return -1;
	}

	int n = 0;
	while ((dirp = readdir(dp)) != NULL) {
		//目录不处理
		if (dirp->d_type == DT_DIR)
			continue;

		//非ISO文件不处理
		char tmp[5];
		if (strcmp(strtolower(rightstr(tmp, dirp->d_name, 4)), ".iso") != 0)
			continue;
		
		//opt设置
		opt[n] = (char*)malloc(BUFFERSIZE*sizeof(char));
		memset(opt[n], 0, BUFFERSIZE * sizeof(char));
		sprintf(opt[n], "%s/%s", dir, dirp->d_name);
		str_replace(opt[n], "//", "/");

		//opt_desc设置
		opt_desc[n] = (char*)malloc(BUFFERSIZE*sizeof(char));
		memset(opt_desc[n], 0, BUFFERSIZE * sizeof(char));
		strncpy(opt_desc[n], dirp->d_name, strlen(dirp->d_name));

		++n;
	}

	closedir(dp);

	return n;
}

// 用于操作系统版本号的输入处理
//   msg： 输入提示 
// value： 作用的数据
void enter_version(char *msg, char *value)
{
	while (1) {
		printf("%s", msg);
		fgets(value, sizeof(value), stdin);
		value[strlen(value)-1] = '\0';

		if (check_version(value) == RET_SUCCESS) {
			break;
		}
		else
			warn("input invalid\n");
	}
	if (strchr(value, '.') == NULL) strcat(value, ".0");
}

// 检测版本号输入的有效性
// 错误返回 RET_FAILURE
int check_version(char *value)
{
	if (value == NULL) return RET_FAILURE;
	if (strlen(value) == 0) return RET_FAILURE;

	char str[16];
	strcpy(str, value);

	int n = 0;
	char *p = str;
	char ch = *p;
	int point = 0;
	while (ch) {
		if (ch >= '0' && ch <= '9') {
			n = n * 10 + ch - '0';
			ch = *++p;
		}
		else if (ch == '.') {
			++point;
			ch = *++p;
		}
		else
			return RET_FAILURE;
	}

	if (point > 1)
		return RET_FAILURE;
	else
		return RET_SUCCESS;
}

// 在原有字符串的基础上编辑输入
// 参数echo：
// 	BVM_NOECHO 不回显
// 	BVM_ECHO   回显
// 	其他字符   回显此字符
int bvm_gets(char *s, int len, char echo)
{
	const int key_esc = 27;
	const int key_back = 8;
	const int key_del = 127;
	const int key_return = 10;
	/*左箭头 27 91 68 [D
	  右箭头 27 91 67 [C
	  上箭头 27 91 65 [A
	  下箭头 27 91 66 [B
	*/

	static struct termios oldt, newt;
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~ICANON;
	newt.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);

	int ch;
	int i = 0;
	int j;

	i = strlen(s);
	printf("%s", s);
	while (1) {

		ch = getchar();
		if (ch == key_return) { printf("\n"); break;} //Enter
		//if (!isdigit(ch) && !isalpha(ch) && ch != key_back && ch != key_del && ch != key_esc) continue;
		
		switch (ch) {
		case key_esc: //ESC
			j = i;
			if (echo != BVM_NOECHO)
				while (j-- > 0) printf("\b \b");
			i = 0;
			s[i] = 0;
			break;
		case key_back: //BACKSPACE
		case key_del: //DEL
			if (i > 0) {
				s[--i] = 0;
				if (echo != BVM_NOECHO)
					printf("\b \b");
			}
			break;
		default:
			if (i < len - 1) {
				s[i++] = ch;
				s[i] = 0;
				if (echo == BVM_NOECHO)
					break;
				if (echo == BVM_ECHO)
					putchar(ch);
				else
					putchar(echo);
			}
			break;
		}

	}

	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	
	return strlen(s);
}

// 用于数字的输入处理
//   msg： 输入提示 
//  unit： 单位
// value： 作用的数据
void enter_numbers(char *msg, char *unit, char *value)
{
	char str[BUFFERSIZE] = {0};
	// 如果已有默认值，在提示信息中显示
	if (strlen(value) > 0)
		printf("%s [default: %s] ", msg, value);
	else
		printf("%s", msg);

	while (1) {
		//printf("%s", msg);
		if (fgets(str, sizeof(str), stdin) == NULL) continue;
		str[strlen(str)-1] = '\0';

		// 如果输入为空，且有默认值，则使用默认值
		if (strlen(str) == 0 && strlen(value) > 0) {
			break;
		}

		if (check_numbers(str, unit) == RET_SUCCESS) {
			strcpy(value, str);
			break;
		}
		else {
			warn("input invalid\n");
			// 再次提示
			if (strlen(value) > 0)
				printf("%s [default: %s]", msg, value);
			else
				printf("%s", msg);
		}
	}
	strtolower(value);
}

// 检测数字输入的有效性
// 错误返回 RET_FAILURE
int check_numbers(char *value, char *unit)
{
	if (value == NULL) return RET_FAILURE;
	if (strlen(value) == 0) return RET_FAILURE;

	char str[16];
	strcpy(str, value);

	if (unit) {
		if (strchr(unit, lastch(str)))
			str[strlen(str)-1] = '\0';
		else
			return RET_FAILURE;
	}

	int n = 0;
	char *p = str;
	char ch = *p;
	while (ch) {
		if (ch >= '0' && ch <= '9') {
			n = n * 10 + ch - '0';
			ch = *++p;
		}
		else
			return RET_FAILURE;
	}

	int m = 1;
	for (int i=0; i<strlen(str)-1; i++, m*=10);
	if (n > 0 && n >= m)
		return RET_SUCCESS;
	else
		return RET_FAILURE;
}

// 用于数字选项列表的输入处理
//      msg： 输入提示
//      opt： 选择的表列
// opt_desc： 选择表列描述文字
//    value： 作用的数据
void enter_options(char *msg, char **opt, char **opt_desc, char *value)
{

	int min, max;
	min = 0;
	while (opt[min]) min++;
	max = --min;
	min = 0;

	printf("%s\n", msg);
	
	// 查找当前value对应的索引作为默认项
	int default_idx = -1;
	if (strlen(value) > 0) {
		for (int i = 0; i <= max; i++) {
			if (strcmp(opt[i], value) == 0) {
				default_idx = i;
				break;
			}
		}
	}

	while (1) {
		
		int n = 0;
		while (opt[n]) {
			if (opt_desc)
				//printf("[%2d]. %s\n", n, opt_desc[n]);
				printf("[%c]. %s\n", options[n], opt_desc[n]);
			else
				//printf("[%2d]. %s\n", n, opt[n]);
				printf("[%c]. %s\n", options[n], opt[n]);
			++n;
		}

		//printf("%s", msg);
		if (default_idx >= 0)
			printf("%s [default: %c]: ", msg, options[default_idx]);
		else
			printf("%s: ", msg);

		char str[32];
		fgets(str, sizeof(str), stdin);
		str[strlen(str) - 1] = '\0';

		// 处理直接回车的情况
		if (strlen(str) == 0) {
			if (default_idx >= 0) {
				strcpy(value, opt[default_idx]);
				break;
			} else {
				//warn("input invalid\n"); // 只有在没有默认值时才警告，或者也可以选择忽略
				continue;
			}
		}

		int idx;
		if ((idx = check_options(min, max, str)) >= 0) {
			strcpy(value, opt[idx]);	
			break;
		}
		else
			warn("input invalid\n");
	}
}


// 检测序号输入的有效性
// 成功返回选择的序号
// 错误返回 -1

int  check_options(int min, int max, char *value)
{
	if (min < 0) return -1;
	if (value == NULL) return -1;
	if (strlen(value) != 1) return -1;

	char ch = *value;
	for (int n=min; n<=max; n++)
		if (ch == options[n]) return n;
	return -1;
}

/*
int  check_options(int min, int max, char *value)
{
	if (min < 0) return -1;
	if (value == NULL) return -1;
	if (strlen(value) == 0) return -1;

	int n = 0;
	char ch = *value;
	while (ch) {
		if (ch >= '0' && ch <= '9') {
			n = n * 10 + ch - '0';
			ch = *++value;
		}
		else
			return -1;
	}

	if (n >= min && n <= max)
		return n;
	else 
		return -1;
}
*/
