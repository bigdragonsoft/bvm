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
	add_item(tbl, "uefi", 	      (char*)&new_vm.uefi,     		enter_vm_uefi, 		0,	0,	0);
	add_item(tbl, "VNC", 	      (char*)&new_vm.vncstatus,  	enter_vm_vncstatus,	0,	1,	0);
	add_item(tbl, "VNC port",     (char*)&new_vm.vncport,  		enter_vm_vncport,	0,	1,	0);
	add_item(tbl, "VNC width",    (char*)&new_vm.vncwidth, 		enter_vm_vncwidth, 	0,	1,	0);
	add_item(tbl, "VNC height",   (char*)&new_vm.vncheight,		enter_vm_vncheight, 	0,	1,	0);
	add_item(tbl, "hostbridge",   (char*)&new_vm.hostbridge, 	enter_vm_hostbridge,	0,	1,	0);
	add_item(tbl, "auto boot",    (char*)&new_vm.autoboot, 		enter_vm_autoboot,	0,	1,	0);
	add_item(tbl, "boot index",   (char*)&new_vm.bootindex, 	enter_vm_bootindex,	0,	1,	0);
	add_item(tbl, "boot time",    (char*)&new_vm.bootdelay, 	enter_vm_bootdelay,	0,	1,	0);

	add_item(tbl, "disk config",  NULL,				enter_vm_disk_config,	0,	1,	1);
	add_item(tbl, "network config", NULL,				enter_vm_network_config,0,	1,	1);

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
		//*new_vm.version = NULL;
		strcpy(new_vm.version, "");
	for (int n=0; n<atoi(new_vm.nics); n++) {
		//strcpy(new_vm.nic[n].ip, "dhcp");
		if (strcmp(new_vm.nic[n].netmode, "NAT") != 0)
			//*new_vm.nic[n].nat = NULL;
			strcpy(new_vm.nic[n].nat, "");
	}
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
			warn("version invalid\n");
			return -1;
		}
	if (strcmp(new_vm.autoboot, "yes") == 0) {
		if (strlen(new_vm.bootindex) == 0) {
		       	warn("booting sequence index invalid\n");
			return -1;
		}
		if (strlen(new_vm.bootdelay) == 0) {
			warn("booting estimate dealy time invalid\n");
			return -1;
		}		
	}
	if (strcmp(new_vm.cdstatus, "on") == 0)
	       if (strlen(new_vm.iso) == 0) {
		       warn("iso path invalid\n");
		       return -1;
	       }

	if (support_uefi(new_vm.ostype) && strcmp(new_vm.uefi, "none") != 0) {
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
	 (tbl[n].func == enter_vm_uefi && !support_uefi(new_vm.ostype)) ||
	 (tbl[n].func == enter_vm_vncstatus && 
		(!support_uefi(new_vm.ostype) || strcmp(new_vm.uefi, "none") == 0)) ||
	 (tbl[n].func == enter_vm_vncport && 
		(!support_uefi(new_vm.ostype) || strcmp(new_vm.uefi, "none") == 0 || strcmp(new_vm.vncstatus, "off") == 0)) ||
	 (tbl[n].func == enter_vm_vncwidth && 
		(!support_uefi(new_vm.ostype) || strcmp(new_vm.uefi, "none") == 0 || strcmp(new_vm.vncstatus, "off") == 0)) ||
	 (tbl[n].func == enter_vm_vncheight && 
		(!support_uefi(new_vm.ostype) || strcmp(new_vm.uefi, "none") == 0 || strcmp(new_vm.vncstatus, "off") == 0)) ||
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
		"other",
		NULL,
	};

	enter_options(msg, ver, NULL, (char*)&new_vm.version);
	if (strcmp(new_vm.version, (char*)ver[4]) == 0)
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
	enter_numbers(msg, NULL, (char*)&new_vm.cpus);
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
}

// vm_uefi
// uefi启动模式输入处理
void enter_vm_uefi(int not_use)
{
	if (!support_uefi(new_vm.ostype)) {
		strcpy(new_vm.uefi, "none");
		return;
	}

	char *msg = "Enter efi: ";
	char *opts_grub_and_uefi[] = {
		"none",
		"uefi",
		"uefi_csm",
		NULL,
	};

	char *opts_only_uefi[] = {
		"uefi",
		"uefi_csm",
		NULL,
	};
	
	char **opts;
	if (support_grub(new_vm.ostype) == 0)
		opts = opts_only_uefi;
	else
		opts = opts_grub_and_uefi;
	enter_options(msg, opts, NULL, (char*)&new_vm.uefi);
}

// vm_vncstatus
// vnc状态输入处理
void enter_vm_vncstatus(int not_use)
{
	if (!support_uefi(new_vm.ostype) || strcmp(new_vm.uefi, "none") == 0) return;
	char *msg = "Enter vnc: ";
	char *opts[] = {
		"on",
		"off",
		NULL,
	};

	enter_options(msg, opts, NULL, (char*)&new_vm.vncstatus);
}

// vm_vncport
// vnc端口输入处理
void enter_vm_vncport(int not_use)
{
	if (!support_uefi(new_vm.ostype) || strcmp(new_vm.uefi, "none") == 0 || strcmp(new_vm.vncstatus, "off") == 0) return;
	char *msg = "Enter VNC port: ";
	enter_numbers(msg, NULL, (char*)&new_vm.vncport);
}

// vm_vncwidth
// vnc屏幕宽度输入处理
void enter_vm_vncwidth(int not_use)
{
	if (!support_uefi(new_vm.ostype) || strcmp(new_vm.uefi, "none") == 0 || strcmp(new_vm.vncstatus, "off") == 0) return;
	char *msg = "Enter VNC display width: ";
	enter_numbers(msg, NULL, (char*)&new_vm.vncwidth);
}

// vm_vncheight
// vnc屏幕高度输入处理
void enter_vm_vncheight(int not_use)
{
	if (!support_uefi(new_vm.ostype) || strcmp(new_vm.uefi, "none") == 0 || strcmp(new_vm.vncstatus, "off") == 0) return;
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

// vm_nat
// NAT网络输入处理
void enter_vm_nat(char *netmode, char *value)
{
	if (strcmp(netmode, "NAT") != 0) return;

	char *msg = "Enter NAT: ";
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
	enter_vm_netmode(msg, (char*)&new_vm.nic[nic_idx].netmode);
}

// 网卡绑定输入前端接口
void enter_vm_bind_proc(int nic_idx)
{
	enter_vm_bind(new_vm.nic[nic_idx].netmode, (char*)&new_vm.nic[nic_idx].bind);
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
	enter_vm_ip((char*)&new_vm.nic[nic_idx].ip);
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

	enter_options(msg, dir_opts, dir_desc, (char*)&new_vm.iso);

	while (n >= 0) {
		if (dir_opts[n]) free(dir_opts[n]);
		if (dir_desc[n]) free(dir_desc[n]);
		--n;
	}
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


// 用于数字的输入处理
//   msg： 输入提示 
//  unit： 单位
// value： 作用的数据
void enter_numbers(char *msg, char *unit, char *value)
{
	while (1) {
		printf("%s", msg);
		fgets(value, sizeof(value), stdin);
		value[strlen(value)-1] = '\0';

		if (check_numbers(value, unit) == RET_SUCCESS) {
			break;
		}
		else
			warn("input invalid\n");
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

		printf("%s", msg);

		char str[8];
		fgets(str, sizeof(str), stdin);
		str[strlen(str) - 1] = '\0';

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
