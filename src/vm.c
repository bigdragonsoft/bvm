/*-----------------------------------------------------------------------------
   BVM Copyright (c) 2018-2021, Qiang Guo (guoqiang_cn@126.com)
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

/**************************************************************************************************
 *
 *
 *   ____  _                      __      __          __  __                                   
 *   |  _ \| |                     \ \    / /         |  \/  |                                  
 *   | |_) | |__  _   ___   _____   \ \  / / __ ___   | \  / | __ _ _ __   __ _  __ _  ___ _ __ 
 *   |  _ <| '_ \| | | \ \ / / _ \   \ \/ / '_ ` _ \  | |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ '__|
 *   | |_) | | | | |_| |\ V /  __/    \  /| | | | | | | |  | | (_| | | | | (_| | (_| |  __/ |   
 *   |____/|_| |_|\__, | \_/ \___|     \/ |_| |_| |_| |_|  |_|\__,_|_| |_|\__,_|\__, |\___|_|   
 *                 __/ |                                                         __/ |          
 *                |___/                                                         |___/           
 *
 *
 *
 *                                                           __   __      __           __   __ 
 *                                                            _) /  \ /| (__)    /|     _) |_  
 *                                                           /__ \__/  | (__).    |.   /__ __)
 *
 **************************************************************************************************/
#include "vm.h"
#include "vnet.h"
#include "create.h"
#include "config.h"
#include "zfs.h"

char *osdir = "/usr/local/etc/bvm/";
char *logfile = "/var/log/bvm";
char *dhcp_pool_file = ".dhcp_pool";
FILE *logfp = NULL;
char vmdir[FN_MAX_LEN];
vm_node *vms;
vm_node *boot[MAX_BOOT_NUM] = {0};
os_stru bvm_os[OS_NUM] = {0};
	/* type		   uefi_boot 	   grub_boot 	     grub_cmd*/
	/*-----------------------------------------------------------*/
/*	{"FreeBSD", 		1, 		1,		1},
	{"OpenBSD", 		0, 		1,		1},
	{"NetBSD", 		0, 		1,		1},
	{"Debian", 		1, 		1,		0},
	{"Ubuntu", 		1, 		1,		0},
	NULL,
};*/

// strcpy 函数
char *bvm_strcpy(char *dst, const char *src)
{
	if (src == NULL || dst == NULL) return NULL;

	char *addr = dst;

	while ((*dst++ = *src++));

	return addr;
}

// 写入日志文件(时间部分)
int write_log_time()
{
	logfp = fopen(logfile, "a+");
	if (logfp == NULL) return -1;

	time_t t;
	struct tm *p;
	time(&t);
	p = localtime(&t);

	struct passwd *pwd;
	pwd = getpwuid(getuid());

	/*
	char *month[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", 
			 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", 
			 NULL}; 
	fprintf(logfp, "%s %d %02d:%02d:%02d %s: ", 
			month[p->tm_mon],
			p->tm_mday, 
			p->tm_hour, 
			p->tm_min, 
			p->tm_sec,
			pwd->pw_name);
	*/
	fprintf(logfp, "%d/%02d/%02d %02d:%02d:%02d %s: ",
			p->tm_year + 1900,
			p->tm_mon + 1,
			p->tm_mday,
			p->tm_hour,
			p->tm_min,
			p->tm_sec,
			pwd->pw_name);
	return 0;
}

// 写入日志文件
int write_log(char *fmt, ...)
{
	write_log_time();
	if (logfp == NULL) return -1;


	va_list argptr;
	int cnt;

	va_start(argptr, fmt);
	cnt = vfprintf(logfp, fmt, argptr);
	va_end(argptr);
	
	if (lastch(fmt) != '\n') fprintf(logfp, "\n");

	fclose(logfp);
	return cnt;
}

// 对所有vm进行保护处理
void vm_lock_all(int flag)
{
	if (vms == NULL) return;
	vm_node *p = vms;

	while (p) {
		vm_lock(p->vm.name, flag);
		p = p->next;
	}
}

// 对vm进行保护
void vm_lock(char *vm_name, int flag)
{	
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
	}

	if (get_vm_status(vm_name) == VM_ON) {
		error("can't process, %s is running\n", vm_name);
		return;
	}
	
	if (flag > 0) {
		if (strcmp(p->vm.lock, "1") == 0) return;
		strcpy(p->vm.lock, "1");
		save_vm_info(vm_name, &p->vm);
	}

	char fn[BUFFERSIZE];
	sprintf(fn, "%s%s/device.map", vmdir, p->vm.name);
	file_lock(fn, flag);

	sprintf(fn, "%s%s/%s.conf", vmdir, p->vm.name, p->vm.name);
	file_lock(fn, flag);

	for (int n=0; n<atoi(p->vm.disks); n++) {
		if (n == 0)
			sprintf(fn, "%s%s/disk.img", vmdir, p->vm.name);
		else
			sprintf(fn, "%s%s/disk%d.img", vmdir, p->vm.name, n);

		file_lock(fn, flag);
	}

	if (flag <= 0) {
		strcpy(p->vm.lock, "0");
		save_vm_info(vm_name, &p->vm);
	}
}

// 保护/解除保护某一个文件
// flag=1开启保护
// flag=0解除保护
void file_lock(char *file, int flag)
{
	if (flag > 0) 
		flag = SF_IMMUTABLE;
	else
		flag = 0;

	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		error("lockion %s has been wrong\n");
		err_exit();
	}
	fchflags(fd, flag);
	close(fd);
}

// 监测bvm运行环境
// bvm runtime environment 
void check_bre()
{
	/********************************
	 * Dependency package detection 
	 * 1. bhyve-firmware
	 * 2. tmux
	 * 3. grub-bhyve
	 ********************************/
	
	//bhyve-firmware
	if (access("/usr/local/share/uefi-firmware/BHYVE_UEFI.fd", 0) == -1 ||
	    access("/usr/local/share/uefi-firmware/BHYVE_UEFI_CSM.fd", 0) == -1) {
		warn("unable to support UEFI\n");
		warn("please use 'pkg install bhyve-firmware' to install first\n\n");
	}	

	//tmux
	if (access("/usr/local/bin/tmux", 0) == -1) {
		error("tmux is not installed, use 'pkg install tmux' to install it\n");
		exit(0);
	}

	//grub-bhyve
	if (access("/usr/local/sbin/grub-bhyve", 0) == -1) {
		error("grub2-bhyve is not installed, use 'pkg install grub2-bhyve' to install it\n");
		exit(0);
	}

	/**************************
	 * bhyve module detection
	 **************************/

	//vmm_load="YES"
	//if_bridge_load="YES"
	//if_tap_load="YES"
	init_config("/boot/loader.conf");

	int fvmm = 0;
	int fbridge = 0;
	int ftap = 0;
	int ftuoo = 0;

	char key[200];
	char *value;
	
	strcpy(key, "vmm_load");
	if ((value = get_value_by_name(key)) == NULL || strcmp(strtolower(value), "yes") != 0) fvmm = 1;
	strcpy(key, "if_bridge_load");
	if ((value = get_value_by_name(key)) == NULL || strcmp(strtolower(value), "yes") != 0) fbridge = 1; 
	strcpy(key, "if_tap_load");
	if ((value = get_value_by_name(key)) == NULL || strcmp(strtolower(value), "yes") != 0) ftap = 1;

	free_config();

	//net.link.tap.up_on_open=1
	init_config("/etc/sysctl.conf");

	strcpy(key, "net.link.tap.up_on_open");
	if ((value = get_value_by_name(key)) == NULL || strcmp(value, "1") != 0) ftuoo = 1;

	free_config();
	
	if (fvmm + fbridge + ftap > 0) {
		error("bvm can't run, you need to add the following lines to /boot/loader.conf\n");
		if (fvmm) 	warn("vmm_load=\"YES\"\n");
		if (fbridge) 	warn("if_bridge_load=\"YES\"\n");
		if (ftap)	warn("if_tap_load=\"YES\"\n");
	}

	if (ftuoo > 0) {
		error("bvm can't run, you need to add the following lines to /etc/sysctl.conf\n");
		warn("net.link.tap.up_on_open=1\n");

		exit(0);
	}

	/**************************
	 * IPFW module detection 
	 **************************/
	
	//ipfw_load="YES"
	//ipfw_nat_load="YES"
	//libalias_load="YES"
	//net.inet.ip.fw.default_to_accept=1
	init_config("/boot/loader.conf");

	int fipfw = 0;
	int fnat = 0;
	int flib = 0;
	int faccept = 0;

	strcpy(key, "ipfw_load");
	if ((value = get_value_by_name(key)) == NULL || strcmp(strtolower(value), "yes") != 0) fipfw = 1;
	strcpy(key, "ipfw_nat_load");
	if ((value = get_value_by_name(key)) == NULL || strcmp(strtolower(value), "yes") != 0) fnat = 1; 
	strcpy(key, "libalias_load");
	if ((value = get_value_by_name(key)) == NULL || strcmp(strtolower(value), "yes") != 0) flib = 1; 
	strcpy(key, "net.inet.ip.fw.default_to_accept");
	if ((value = get_value_by_name(key)) == NULL || strcmp(value, "1") != 0) faccept = 1;

	free_config();

	if (fipfw + fnat + flib + faccept > 0) {
		error("In order to help you solve the NAT reflow problem, \nyou need to add the following line to /boot/loader.conf\n");
		if (fipfw) 	warn("ipfw_load=\"YES\"\n");
		if (fnat) 	warn("ipfw_nat_load=\"YES\"\n");
		if (flib) 	warn("libalias_load=\"YES\"\n");
		if (faccept)	warn("net.inet.ip.fw.default_to_accept=1\n");
	}

}

// 设置vm工作目录
void set_vmdir()
{
	char fn[FN_MAX_LEN];
	sprintf(fn, "%s%s", osdir, "bvm.conf");
	init_config(fn);
	char *value = get_value_by_name("vmdir");
	if (value == NULL || strlen(value) == 0) {
		error("please edit '/usr/local/etc/bvm/bvm.conf' first\n");
		warn("vmdir=/your/vm/dir/path/\n");
		err_exit();
	}
	else
		strcpy(vmdir, value);
	
	if (lastch(vmdir) != '/') strcat(vmdir, "/");

	free_config();

	if (access(vmdir, 0) == -1) {
		if (mkdir(vmdir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1)
			error("can't set vmdir\n");
	}
}

// 设置bvm_os
void set_bvm_os()
{
	char fn[FN_MAX_LEN]; 
	sprintf(fn, "%s%s", osdir, "bvm.conf");
	init_config(fn);
	
	char *value;
	char item[BUFFERSIZE];
	
	for (int n=0; n<OS_NUM; n++) {
		sprintf(item, "os%d", n+1);
		if ((value = get_value_by_name(item)) == NULL) {
			break;
		}
		strcpy(bvm_os[n].type, value);

		sprintf(item, "%s_uefi_boot_enable", bvm_os[n].type);
		if (get_value_by_name(item) != NULL)
			bvm_os[n].uefi_boot = atoi(get_value_by_name(item));
		else {
			error("bvm.conf error\n");
			err_exit();
		}
		
		sprintf(item, "%s_grub_boot_enable", bvm_os[n].type);
		if (get_value_by_name(item) != NULL)
			bvm_os[n].grub_boot = atoi(get_value_by_name(item));
		else {
			error("bvm.conf error\n");
			err_exit();
		}

		sprintf(item, "%s_grub_cmd_enable", bvm_os[n].type);
		if (get_value_by_name(item) != NULL)
			bvm_os[n].grub_cmd = atoi(get_value_by_name(item));
		else {
			error("bvm.conf error\n");
			err_exit();
		}

	}

	free_config();
}

// 输出支持的os
void vm_os_list()
{
	printf("-----------------------------------------------\n");
	printf("idx\tos\t\tgrub\t\tuefi\n");
	printf("-----------------------------------------------\n");
	int n = 0;
	while (*bvm_os[n].type) {
		
		printf("%3d\t", n+1);
		printf("%s", bvm_os[n].type);
		
		for (int i=0; i<2-strlen(bvm_os[n].type)/TABSTOP; i++) printf("\t");

		if (bvm_os[n].grub_boot)
			printf("yes\t\t");
		else
			warn("no\t\t");
		if (bvm_os[n].uefi_boot)
			printf("yes\n");
		else
			warn("no\n");

		++n;
	}
}

// 虚拟机列表初始化
void vm_init()
{
	create_vm_list();
	get_vm_name(vmdir);
	//sort_vm_list(LS_BY_NAME);
}

// 虚拟机列表销毁
void vm_end()
{
	destroy_vm_list();
}

/*
 * 输出虚拟机列表
 * Output virtual machine list
 */
void vm_list(int list_type, char *index_key)
{
	//先将虚拟机列表按键值排序
	if (strcmp(index_key, "byname") == 0)
		sort_vm_list(LS_BY_NAME);
	else if (strcmp(index_key, "byip") == 0 && list_type == VM_LONG_LIST)
		sort_vm_list(LS_BY_IP);
	else if (strcmp(index_key, "byos") == 0)
		sort_vm_list(LS_BY_OS);
	else if (strcmp(index_key, "bystatus") == 0)
		sort_vm_list(LS_BY_STATUS);
	else {
		error("Incorrect parameters.\n");
		err_exit();
	}

	//再开始输出列表
	print_vm_list(list_type);
}

// 获的vm最长的名字长度
int max_vm_name_len()
{
	int len = 0;
	vm_node *p = vms;
	while (p) {
		int m = strlen(p->vm.name);
		if (m > len) len = m;
		p = p->next;
	}
	return len;
}

// 显示所有设备关系
void vm_show_device_all(int show_type)
{
	vm_show_device(VNET_DEFAULT_BRIDGE, show_type);
	vm_show_nat(show_type);
	vm_show_switch(show_type);
}

// 显示NAT设备
void vm_show_nat(int show_type)
{
	load_nat_list();
	int n = 0;
	while (nat_list[n]) {
		vm_show_device(nat_list[n]->name, show_type);
		++n;
	}	
}

// 显示Switch设备
void vm_show_switch(int show_type)
{
	load_switch_list();
	int n = 0;
	while (switch_list[n]) {
		vm_show_device(switch_list[n]->name, show_type);
		++n;
	}	
}

// 显示设备名称
void vm_show_device_name(char *device)
{
	warn("%s ", device);
	if (strstr(device, "switch")) {
		get_switch_info(device);	
		if (strlen(Switch.ip) > 0)
			warn("[%s]", Switch.ip);
	}
	else if (strstr(device, "nat")) {
		get_nat_info(device);
		warn("[%s]", nat.ip);
	}
	printf("\n");

}

// 显示设备的关联
void vm_show_device(char *dev, int show_type)
{
	if (vms == NULL) return;

	char device[32];
	if (dev == NULL)
		enter_vm_device(device);
	else
		strcpy(device, dev);

	if (show_type == SD_CLASSICAL)
		vm_show_device_name(device);

	int len = max_vm_name_len();
	int tab = len / TABSTOP + 1;

	int flag = 0;	
	vm_node *p = vms;
	while (p) {
		int num = atoi(p->vm.nics);
		for (int n = 0; n < num; n++) {

			if ((strcmp(p->vm.nic[n].bind, device) == 0) || (strcmp(p->vm.nic[n].nat, device) == 0) || 
			    (strcmp(VNET_DEFAULT_BRIDGE, device) == 0 && (strcmp(p->vm.nic[n].netmode, "NAT") != 0) 
			     					       && is_nic(p->vm.nic[n].bind))) {
				
				if (show_type == SD_SIMPLE && !flag) vm_show_device_name(device);
				{
					if (strcmp(VNET_DEFAULT_BRIDGE, device) == 0 && strlen(p->vm.nic[n].bind) > 0) {
						static int em0 = 1;
						if (em0) {
							printf("  |-%s\n", p->vm.nic[n].bind);
							em0 = 0;
							//continue;
						}
					}
				}

				flag = 1;
				printf("  |-");
				if (get_vm_status(p->vm.name) == VM_ON) {
					success("%s ", p->vm.name);
					for (int i=0; i<(len-strlen(p->vm.name)); i++) printf(" ");
					success("(nic%d)\n", n);
				}
				else {
					printf("%s ", p->vm.name);
					for (int i=0; i<(len-strlen(p->vm.name)); i++) printf(" ");
					printf("(nic%d)\n", n);
				}

			}

		}
		
		p = p->next;
	}
	if (show_type == SD_CLASSICAL && !flag) { printf("  |-"); red("null\n");}
}

// 是否为物理网卡
// 1 是
// 0 否
int is_nic(char *nic_name)
{
	get_nic_list(CABLE_AND_WIRELESS);

	int n = 0;
	while (strlen(nic_list[n]) > 0) {
		if (strcmp(nic_list[n], nic_name) == 0) return 1;
		++n;
	}
	return 0;
}

// 清理vm网桥、tap等
void vm_clean()
{
	get_vnet_list(BRIDGE);
	int n = 0;
	char desc[VNET_BUFFERSIZE] = {0};
	char **p = bridge_list;
	while (*(p+n)) {
		//依次获取网桥的desc字段
		get_bridge_desc(*(p+n), desc);

		//确定bvm使用的网桥
		if (strstr(desc, "bvm")) {
			//清理tap
			get_members_in_bridge(*(p+n));
			if (*tap_list) {
				//printf("%s+\n", *(p+n));	
				int m = 0;
				while (tap_list[m]) {
					//warn("%s\n", tap_list[m]);
					clean_tap(tap_list[m]);
					++m;
				}
			}
			//清理bridge
			clean_bridge(*(p+n));
		}
		++n;
	}
}

// 检测并销毁指定bridge
void clean_bridge(char *bridge_name)
{
	get_members_in_bridge(bridge_name);
	if (tap_list_count(TL_NO_NIC) == 0) {
		strcpy(bridge, bridge_name);
		//error("clean %s\n", bridge);
		run_bridge_command(DESTROY_BRIDGE);
	}
}

// 检测并销毁指定tap
void clean_tap(char *tap_name)
{
	if (strstr(tap_name, "tap") == NULL) return;

	strcpy(tap, tap_name);
	vm_node *p = vms;
	while (p) {
		//error("vm.status=%s\n", p->vm.status);
		//error("get_vm_status=%s\n", get_vm_status(p->vm.name)==VM_ON?"on":"off");
		if (get_vm_status(p->vm.name) == VM_ON) {
		//if (strcmp(p->vm.status, "on") == 0) {
			for (int n=0; n<atoi(p->vm.nics); n++)
				if (strcmp(tap, p->vm.nic[n].tap) == 0) return;
		}
		p = p->next;
	}
	//error("clean %s\n", tap);
	run_bridge_command(DESTROY_TAP);
}

// 搜索ip地址来确定虚拟机
// 参数: ip不包含掩码
// 	 self所搜中需要排除的自己
int find_vm_by_ip(char *ip, find_vm_stru *result, vm_stru *self)
{
	vm_node *p = vms;
	while (p) {
		if (self == NULL || strcmp(p->vm.name, self->name) != 0) {
			for (int n = 0; n < atoi(p->vm.nics); n++) {
				char vm_ip[32];
				strcpy(vm_ip, p->vm.nic[n].ip);
				get_ip(vm_ip);

				if (strcmp(ip, vm_ip) == 0) {
					if (result) {
						strcpy(result->vm_name, p->vm.name);
						*result->nic_index = n;
					}
					return RET_SUCCESS;
				}
			}
		}
		p = p->next;
	}
	return RET_FAILURE;
}

// 显示所有虚拟机的端口转向列表
void vm_show_ports(int show_type, scan_redirect_port_stru *check)
{
	vm_node *p = vms;
	while(p) {
		scan_port(show_type, &p->vm, check);
		if (show_type == SP_VALID && *check->ret == RET_FAILURE)
			return;
		else
			p = p->next;
	}

}

// 扫描端口
int scan_port(int scan_type, vm_stru *vm, scan_redirect_port_stru *check)
{
	//对所有网卡进行扫描
	for (int n = 0; n < atoi(vm->nics); n++) {
		if (strcmp(vm->nic[n].netmode, "NAT") == 0 && strcmp(vm->nic[n].rpstatus, "enable") == 0) {

			switch (scan_type) {

			case SP_SHOW:
				show_port(vm, n);
				break;

			case SP_VALID:
				if (is_valid_port(vm, n, check) == RET_FAILURE) 
					return RET_FAILURE;
				break;

			default:
				break;

			}
		}
	}
	return RET_SUCCESS;
}

// 显示vm的端口转向
// tcp 172.16.1.3:80	-> 80
// udp 172.16.1.3:1194	-> 1194
void show_port(vm_stru *vm, int nic_index)
{
	int n = nic_index;

	char ip[32];
	char proto[PROTO_LEN];

	for (int r = 0; r < vm->nic[n].rpnum; r++) {
		
		strcpy(ip, vm->nic[n].ip);
		get_ip(ip);

		strcpy(proto, vm->nic[n].ports[r].proto);

		printf("%s %s:%d\t-> %d\t%s\n",	(strlen(proto) > 0) ? proto : "tcp",
						ip,
						vm->nic[n].ports[r].vm_port,
						vm->nic[n].ports[r].host_port,
						vm->name);
	}
}

// 端口号是否有效
// 检测端口号是否存在重复
int is_valid_port(vm_stru *vm, int nic_index, scan_redirect_port_stru *check)
{
	int n = nic_index;

	//排除本机，只对其他vm进行检测
	if (strcmp(vm->name, check->vm_name) == 0)
		return RET_SUCCESS;

	for (int r = 0; r < vm->nic[n].rpnum; r++) {
		if (strlen(vm->nic[n].ports[r].proto) == 0) 
			strcpy(vm->nic[n].ports[r].proto, "tcp");
		int f1 = (strcmp(check->port->proto, vm->nic[n].ports[r].proto) == 0);
		int f2 = (check->port->host_port == vm->nic[n].ports[r].host_port);

		if (f1 && f2) return *check->ret = RET_FAILURE;
	}

	return *check->ret = RET_SUCCESS;
}

// 启动vm
int vm_booting(autoboot_stru *boot)
{
	clock_t start, finish;
	start = clock();
	printf("%s booting...", boot->vm_name);
	vm_start(boot->vm_name);

	while (1) {
		finish = clock();
		double pass = (double)(finish - start) / CLOCKS_PER_SEC;
		if ((int)pass > boot->delay) {
			return 1;
		}
	}
}

// 自动启动vm
void vm_autoboot()
{
	int n = 0;
	gen_autoboot(&n);

	//按顺序依次启动
	for (int i=0; i<n; i++) {
		printf("%s, idx=%s, time=%s\n", boot[i]->vm.name, boot[i]->vm.bootindex, boot[i]->vm.bootdelay);
		autoboot_stru ab;
		ab.vm_name = boot[i]->vm.name;
		ab.delay = atoi(boot[i]->vm.bootdelay);
		//wait_exec((int*)vm_booting, (autoboot_stru*)&ab);
		wait_exec((fun)(int*)vm_booting, (autoboot_stru*)&ab);
	}
}

// 生成vm自动启动数组
void gen_autoboot(int *count)
{
	//vm_node *boot[MAX_BOOT_NUM] = {0};

	//生成autoboot数组
	int n = 0;
	vm_node *p = vms;
	while (p) {
		if (strcmp(p->vm.autoboot, "yes") == 0) {
			//printf("%s, idx=%s, time=%s\n", p->vm.name, p->vm.bootindex, p->vm.bootdelay);
			if (atoi(p->vm.bootindex) == 0) strcpy(p->vm.bootindex, "1");
			if (atoi(p->vm.bootdelay) == 0) strcpy(p->vm.bootdelay, "1");
			boot[n++] = p;
		}
		p = p->next;
	}

	//对启动vm按bootindex排序
	for (int i=0; i<n-1; i++) {
		if (strcmp(boot[i]->vm.autoboot, "no") == 0) continue;
		for (int j=i+1; j<n; j++) {
			if (strcmp(boot[j]->vm.autoboot, "no") == 0) continue;
			if (atoi(boot[i]->vm.bootindex) > atoi(boot[j]->vm.bootindex)) {
				vm_node *t;
				t = boot[i];
				boot[i] = boot[j];
				boot[j] = t;
			}
		}
	}
	
	*count = n;
}


// 输出自动启动vm列表
void vm_autoboot_list()
{
	int n = 0;
	gen_autoboot(&n);
	if (n == 0) return;

	printf("---------------------------------\n");
	printf("idx\tvm\t\ttime(sec)\n");
	printf("---------------------------------\n");
	
	for (int i=0; i<n; i++) {
		//printf("%s\t%s\t%s\n", boot[i]->vm.bootindex, boot[i]->vm.name, boot[i]->vm.bootdelay);
		printf("%s\t%s", boot[i]->vm.bootindex, boot[i]->vm.name);
		for (int t=0; t<(2-strlen(boot[i]->vm.name) / TABSTOP); t++) printf("\t");
		printf("%s\n", boot[i]->vm.bootdelay);
	}
}

// 新建vm
void vm_create(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) != NULL) {
		error("%s already exist\n", vm_name);
		return;
	}

	create_init();
	welcome();
	enter_vm(vm_name);

	//新建vm文件夹
	char dir[FN_MAX_LEN];
	sprintf(dir, "%s%s", vmdir, new_vm.name);
	if (mkdir(dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1) {
		error("%s already exist\n", dir);
		err_exit();
	}

	//生成vm配置文件
	save_vm_info(new_vm.name, &new_vm);

	//生成device.map
	if (write_vm_device_map(&new_vm) == RET_FAILURE) {
		error("creating device_map failure\n");
		err_exit();
	}

	//生成disk.img
	create_vm_disk_all(&new_vm);
}

// 创建虚拟机中所有磁盘
// 根据虚拟机中磁盘数量而确定
void create_vm_disk_all(vm_stru *vm)
{
	int zfs = 0;
	if (support_zfs() && strcmp(vm->zfs, "on") == 0) zfs = 1;

	for (int n=0; n<atoi(vm->disks); n++) {
		if (zfs)
			create_zfs_disk(vm, n);
		else
			create_vm_disk(vm, n);
	}
}

// 创建vm磁盘文件
// vm:虚拟机
// disk_ord:盘号
void create_vm_disk(vm_stru *vm, int disk_ord)
{
	char fn[FN_MAX_LEN];
	char cmd[BUFFERSIZE];
	char disk[32];
	//int offset = &vm->img1size - &vm->imgsize;
	int n = disk_ord;

	if (n == 0)
		strcpy(disk, "/disk.img");
	else
		sprintf(disk, "/disk%d.img", n);
	sprintf(fn, "%s%s%s", vmdir, vm->name, disk);
	
	if (access(fn, 0) == -1) {
		//truncate -s [+|-]size[K|k|M|m|G|g|T|t] file
		//sprintf(cmd, "truncate -s %s %s", (char*)(&vm->imgsize + n * offset), fn);
		sprintf(cmd, "truncate -s %s %s", vm->vdisk[n].size, fn);
		run_cmd(cmd);
	}
}

// 调整虚拟机中全部磁盘大小
// 调整的依据是new_vm中的参数
void adjust_vm_disk_all(vm_stru *vm)
{
	//int offset = &vm->img1size - &vm->imgsize;
	for (int n=0; n<atoi(vm->disks); n++) {
		//adjust_vm_disk(vm, (char*)(&new_vm.imgsize + n * offset), n);
		adjust_vm_disk(vm, vm->vdisk[n].size, n);
	}
	
}

// 调整vm磁盘大小
// vm:虚拟机
// size:调整后的磁盘空间大小
// disk_ord:盘号
void adjust_vm_disk(vm_stru *vm, char *size, int disk_ord)
{
	int n = disk_ord;
	/*
	int step = &vm->img1size - &vm->imgsize; 
	char *p = (char*)(&vm->imgsize + n * step);
	char *newp = (char*)(&new_vm.imgsize + n * step);
	*/
	char *p = vm->vdisk[n].size;
	char *newp = new_vm.vdisk[n].size;
	long offset;
	offset = imgsize_cmp(size, p);//vm->imgsize);	
	if (offset == 0) return;

	char disk[32];
	if (n == 0)
		strcpy(disk, "/disk.img");
	else
		sprintf(disk, "/disk%d.img", n);

	char fn[FN_MAX_LEN]; 
	sprintf(fn, "%s%s%s", vmdir, vm->name, disk);

//	char fn[FN_MAX_LEN];
//	sprintf(fn, "%s%s%s", vmdir, vm->name, "/disk.img");
	if (access(fn, 0) == 0) {
		char cmd[BUFFERSIZE];
		if (offset > 0) {
			sprintf(cmd, "truncate -s %s%ld%s %s", "+", offset, "K", fn);
			run_cmd(cmd);
		}
		if (offset < 0) {
			//对磁盘容量减少暂不处理
			//sprintf(cmd, "truncate -s %ld%s %s", offset, "K", fn);
			//run_cmd(cmd);
			strcpy(newp, p);
			//strcpy(new_vm.imgsize, vm->imgsize);
		}
	}


}

// 比较两个磁盘文件的大小
// 以k为计算单位
long imgsize_cmp(char *size1, char *size2)
{
	long sz1 = disk_size_to_kb(size1);
	long sz2 = disk_size_to_kb(size2);

	return (sz1 - sz2);
}

// 转换磁盘文件容量为单位K
long disk_size_to_kb(char *size)
{
	long base;
	switch (tolower(lastch(size))) {
	case 'k':
		base = 1;
		break;
	case 'm':
		base = 1024;
		break;
	case 'g':
		base = 1024 * 1024;
		break;
	case 't':
		base = 1024 * 1024 * 1024;
		break;
	default:
		break;
	}
	int n = 0;
	int vol = 0;
	char ch;
	while ((ch = size[n])) {
		if (ch >= '0' && ch <= '9') {
			vol = vol * 10 + ch - '0';
			++n;
		}
		else 
			break;
	}
	return base * vol;
}

// 所有磁盘容量合计
double total_disk_size(vm_stru *vm)
{
	long total = 0;
	for (int n=0; n<atoi(vm->disks); n++) {
		//total += disk_size_to_kb(&vm->imgsize + n * disk_offset(vm));
		total += disk_size_to_kb(vm->vdisk[n].size);
	}
	return (double)total;
}

// 存储单位转换
// n:输入KB
// flag_int:是否需要整数
// save:输出最适合的单位
void unit_convert(double n, int flag_int, char *save)
{
	char *unit = "kmgt";
	static int base = 0;

	if (n >= 1024) {
		++base;
		unit_convert(n / 1024, flag_int, save);
	}
	else {
		if (save)
			if (flag_int && is_integer(n))
				sprintf(save, "%d%c", (int)n, *(unit+base));
			else
				sprintf(save, "%.1f%c", n, *(unit+base));
		else
			if (flag_int && is_integer(n))
				printf("%d%c", (int)n, *(unit+base));
			else
				printf("%.1f%c", n, *(unit+base));
		base = 0;
	}
}

// 判断浮点数是否为整数
// 返回1 是整数
// 返回0 不是整数
int is_integer(double num)
{
	const double delta = 1e-5;
	int x = num;
	double diff = num - x;

	if (diff > -delta && diff < delta)
		return 1;
	else
		return 0;
}

// 编辑vm
void vm_config(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
		select_vm(vm_name, VM_OFF);
		p = find_vm_list(vm_name);
	}
	if (get_vm_status(vm_name) == VM_ON) {
		error("%s is running, can't edit\n", vm_name);
		return;
	}
	if (atoi(p->vm.lock)) {
		error("%s has been locked up\n", vm_name);
		return;
	}

	create_init();
	welcome();

	load_vm_info(vm_name, &new_vm);
	edit_vm(vm_name);


	//保存device.map
	if (write_vm_device_map(&new_vm) == RET_FAILURE) {
		error("creating device_map failure\n");
		err_exit();
	}

	//调整disk.img
	adjust_vm_disk_all(&p->vm);//, new_vm.imgsize);
	create_vm_disk_all(&new_vm);
	
	//保存vm配置文件
	save_vm_info(new_vm.name, &new_vm);
}

// 启动vm
void vm_start(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
		select_vm(vm_name, VM_OFF);
		p = find_vm_list(vm_name);
	}

	if (get_vmx(&p->vm) != 1) {
		error("This machine does not support virtualization.\n");
		return;
	}

	if (get_vm_status(vm_name) == VM_ON) {
		error("%s is running\n", vm_name);
		return;
	}

	if (atoi(p->vm.lock)) {
		error("%s has been locked up, can't run\n", vm_name);
		return;
	}

	if (strcmp(p->vm.cdstatus, "on") == 0 && access(p->vm.iso, 0) == -1) {
		error("%s not found, can't run\n", p->vm.iso);
		return;
	}

	int ret = create_networking(vm_name) == RET_SUCCESS && 
		  gen_vm_start_code(vm_name) == RET_SUCCESS;

	if (ret) {
		char shell[FN_MAX_LEN];
		//sprintf(shell, "/usr/local/bin/tmux -2 -u new -d -s %s \"/bin/sh /tmp/start_%s.sh\"", vm_name, vm_name);
		sprintf(shell, "/usr/local/bin/tmux -2 -u new -d -s %s \"bvmb %s\"", vm_name, vm_name);
		run_cmd(shell);

		//等待虚拟机启动成功
		waitting_boot(vm_name);

		//开启dhcp服务
		if (bvm_get_pid("bvmdhcp") == -1) {
			char *fn = "/usr/local/bin/bvmdhcp";
			char *arg = "9250b212ea95c6897aeef888c0b6611c18682957";
			sprintf(shell, "/usr/local/bin/tmux -2 -u new -d -s bvmdhcp %s %s", fn, arg);
			run_cmd(shell);
		}

	}
	else  {
		error("can't start the vm!\n");
	}
}

// 登陆vm
void vm_login(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ON);
		return;
		select_vm(vm_name, VM_ON);
		p = find_vm_list(vm_name);
	}

	if (strcmp(p->vm.uefi, "none") != 0) {
		warn("Please use a remote desktop or SSH to login\n");
		return;
	}

	if (get_vm_status(vm_name) == VM_ON) { 
		char cmd[CMD_MAX_LEN];
		sprintf(cmd, "tmux attach-session -t %s", vm_name);
		run_cmd(cmd);
	}
	else {
		error("%s does not start\n", vm_name);
	}
}

// vm关机处理
void vm_stop(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ON);
		return;
		select_vm(vm_name, VM_ON);
		p = find_vm_list(vm_name);
	}

	if (get_vm_status(vm_name) == VM_ON) {
		
		setvbuf(stdout, NULL, _IONBF, 0);
		printf("shutting down ...");

		// 向vm发送信号15，vm做出关机处理
		// Shutting down ...
		char cmd[CMD_MAX_LEN];
		int pid = get_vm_pid(&p->vm);	
		//warn("pid=%d\n", pid);

		if (pid < 0) {
			warn("\n%s can't stop, try again later or use 'bvm --poweroff %s' to stop\n", vm_name, vm_name);
			return;
		}
		sprintf(cmd, "kill 15 %d", pid);
		run_cmd(cmd);

		//等待vm进程消失
		sprintf(cmd, "ps | grep %d | grep -v grep", pid);
		//printf("wait=%s\n", cmd);
		//int ret = wait_exec((int*)check_shutdown, cmd);
		int ret = wait_exec((fun)(int*)check_shutdown, cmd);
		printf("\033[1A");
		if (ret == 0) { //成功
			delay(1);
			if (get_vm_status(vm_name) == VM_ON) {
				//warn("run poweroff\n");
				vm_poweroff(vm_name, 0);
			}
			//update_vm_status(vm_name, VM_OFF);
		}
		if (ret == -1) { //超时
			warn("\nit's out of time, use 'bvm --poweroff %s' to stop", vm_name);
		}
		printf("\n");
	}
	else {
		error("%s does not start\n", vm_name);
	}
}

// 检查关机
int check_shutdown(char *cmd)
{
	clock_t start, finish;
	start = clock();
	while (1) {
		char buf[16];
		FILE *fp = popen(cmd, "r");
		if (fgets(buf, 16, fp)) {
			pclose(fp);
		}
		else {
			pclose(fp);
			return 0;
		}

		finish = clock();
		//long pass = finish - start;
		double pass = (double)(finish - start) / CLOCKS_PER_SEC;
		//printf("%lf\n", pass);
		if ((int)pass > 10) {
			return -1;
		}
	}

}

// 等待启动成功
int waitting_boot(char *vm_name)
{
	while (1) {
		if (get_vm_status(vm_name) == VM_ON) return 1;
	}
}

// 关闭电源
void vm_poweroff(char *vm_name,int flag_msg)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ON);
		return;
		select_vm(vm_name, VM_ON);
		p = find_vm_list(vm_name);
	}

	char cmd[CMD_MAX_LEN];
	if (get_vm_status(vm_name) == VM_ON) {
		sprintf(cmd, "/usr/sbin/bhyvectl --force-poweroff --vm=%s", vm_name);
		run_cmd(cmd);

		//给 --force-poweroff 一秒钟的处理时间
		//避免下面执行 --destroy 时发生错误
		//Give --force-poweroff a one-second processing time 
		//to avoid an error when executing --destroy below
		delay(1);
		
		if (get_vm_status(vm_name) == VM_ON) {
			sprintf(cmd, "/usr/sbin/bhyvectl --destroy --vm=%s", vm_name);
			run_cmd(cmd);
		}
		//删除tmux窗口
		if (strcmp(p->vm.uefi, "none") == 0) {
			sprintf(cmd, "tmux kill-session -t %s", vm_name);
			//run_cmd(cmd);
		}
		//删除tap
		/*
		for (int n=0; n<atoi(p->vm.nics); n++) {
			sprintf(cmd, "ifconfig %s destroy", p->vm.nic[n].tap);
			run_cmd(cmd);
		}
		*/
	}
	else {
		if (flag_msg) 
			error("%s does not start\n", vm_name);
	}
}


// 重启vm
void vm_restart(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ON);
		return;
		select_vm(vm_name, VM_ON);
		p = find_vm_list(vm_name);
	}

	if (get_vm_status(vm_name) == VM_ON) {
		char cmd[CMD_MAX_LEN];
		sprintf(cmd, "/usr/sbin/bhyvectl --force-reset --vm=%s", vm_name);
		run_cmd(cmd);
	}
	else {
		error("%s does not start\n", vm_name);
	}
}

// 输出vm配置文件信息(完整版)
void vm_info_all(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ALL);
		return;
		select_vm(vm_name, VM_ALL);
		p = find_vm_list(vm_name);
	}

	welcome();

	char str[BUFFERSIZE];
	printf("%-13s = %s\n", 	"vm_name", 	p->vm.name);
	printf("%-13s = %s\n", 	"vm_profile", 	p->vm.profile);
	printf("%-13s = %s\n",	"vm_disks", 	p->vm.disks);
	for (int n=0; n<atoi(p->vm.disks); n++) {
		sprintf(str, "vm_disk%d_name", n);
		printf("%-13s = %s\n", str,	p->vm.vdisk[n].name);
		sprintf(str, "vm_disk%d_size", n);
		printf("%-13s = %s\n", str,	p->vm.vdisk[n].size);
		sprintf(str, "vm_disk%d_path", n);
		printf("%-13s = %s\n", str,	p->vm.vdisk[n].path);
	}
	printf("%-13s = %s\n",	"vm_zfs", 	p->vm.zfs);
	printf("%-13s = %s\n",	"vm_zpool", 	p->vm.zpool);
	printf("%-13s = %s\n",	"vm_ram", 	p->vm.ram);
	printf("%-13s = %s\n",	"vm_cpus", 	p->vm.cpus);
	printf("\n");
	printf("%-13s = %s\n",	"vm_ostype", 	p->vm.ostype);
	printf("%-13s = %s\n",	"vm_version", 	p->vm.version);
	printf("%-13s = %s\n",	"vm_cdstatus", 	p->vm.cdstatus);
	printf("%-13s = %s\n",	"vm_iso", 	p->vm.iso);
	printf("%-13s = %s\n",	"vm_bootfrom", 	p->vm.bootfrom);
	printf("%-13s = %s\n",	"vm_hostbridge",p->vm.hostbridge);
	printf("%-13s = %s\n",	"vm_uefi",	p->vm.uefi);
	printf("%-13s = %s\n",	"vm_disk",	p->vm.disk);
	printf("%-13s = %s\n",	"vm_devicemap",	p->vm.devicemap);
	printf("%-13s = %s\n",	"vm_grubcmd",	p->vm.grubcmd);
	printf("\n");
	printf("%-13s = %s\n",	"vm_nics",	p->vm.nics);
	for (int n=0; n<atoi(p->vm.nics); n++) {
		sprintf(str, "vm_nic%d_netmode", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].netmode);
		sprintf(str, "vm_nic%d_nat", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].nat);
		sprintf(str, "vm_nic%d_rpstatus", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].rpstatus);
		sprintf(str, "vm_nic%d_rplist", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].rplist);
		sprintf(str, "vm_nic%d_bind", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].bind);
		sprintf(str, "vm_nic%d_bridge", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].bridge);
		sprintf(str, "vm_nic%d_tap", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].tap);
		sprintf(str, "vm_nic%d_ip", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].ip);
	}
	

	printf("\n");
	printf("%-13s = %s\n",	"vm_vncstatus",	p->vm.vncstatus);
	printf("%-13s = %s\n",	"vm_vncport",	p->vm.vncport);
	printf("%-13s = %s\n",	"vm_vncwidth",	p->vm.vncwidth);
	printf("%-13s = %s\n",	"vm_vncheight",	p->vm.vncheight);
	printf("\n");
	printf("%-13s = %s\n",	"vm_autoboot",	p->vm.autoboot);
	printf("%-13s = %s\n",	"vm_bootindex",	p->vm.bootindex);
	printf("%-13s = %s\n",	"vm_bootdelay",	p->vm.bootdelay);
	printf("\n");
	printf("%-13s = ",	"vm_status");
	if (get_vm_status(p->vm.name) == VM_ON)  printf("on\n");
	if (get_vm_status(p->vm.name) == VM_OFF) printf("off\n");
	printf("%-13s = %s\n",	"vm_lock",	p->vm.lock);

}


// 输出vm配置资料
void vm_info(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ALL);
		return;
		select_vm(vm_name, VM_ALL);
		p = find_vm_list(vm_name);
	}

	welcome();
	printf("%-14s : \033[4m%s\n\033[0m", "name", 	p->vm.name);
	printf("%-14s : %s\n", "os type", p->vm.ostype);
	if (strlen(p->vm.version) > 0)
		printf("%-14s : %s\n", "version", 	p->vm.version);	
	printf("%-14s : %s\n", "ram", 			p->vm.ram);
	printf("%-14s : %s\n", "cpus", 			p->vm.cpus);
	printf("%-14s : %s\n", "disk interface",	p->vm.storage_interface);
	printf("%-14s : %s\n", "disk numbers",		p->vm.disks);

	if (support_zfs()) {
		printf("|-%-12s : %s\n", "ZFS support",	p->vm.zfs);
		if( strcmp(p->vm.zfs, "on") == 0) {
			printf("|-%-12s : %s\n", "zpool",	p->vm.zpool);
		}
	}
	for (int n=0; n<atoi(p->vm.disks); n++) {
		char t[32];
		sprintf(t, "disk(%d) size", n);
		printf("|-%-12s : %s\n", t,              p->vm.vdisk[n].size);
	}

	/*
	//------------
	int offset = &p->vm.img1size - &p->vm.imgsize;
	for (int n=0; n<atoi(p->vm.disks); n++) {
		char t[32];
		sprintf(t, "disk(%d) size", n);
		printf("|-%-11s: %s\n", t, 		(char*)(&p->vm.imgsize + n * offset));
	}
	//------------
	*/

	printf("%-14s : %s\n", "cd status", 		p->vm.cdstatus);
	if (strcmp(p->vm.cdstatus, "on") == 0)
		printf("|-%-12s : %s\n", "iso path",	p->vm.iso);
	printf("%-14s : %s\n", "boot from", 		p->vm.bootfrom);
	printf("%-14s : %s\n", "hostbridge", 		p->vm.hostbridge);
	printf("%-14s : %s\n", "uefi", 			p->vm.uefi);
	if (support_uefi(p->vm.ostype) && strcmp(p->vm.uefi, "none") != 0) {
		printf("|-%-12s : %s\n", "vnc status", 	p->vm.vncstatus);
		printf("|-%-12s : %s\n", "vnc port", 	p->vm.vncport);
		printf("|-%-12s : %s\n", "width", 	p->vm.vncwidth);
		printf("|-%-12s : %s\n", "height", 	p->vm.vncheight);
	}

	printf("%-14s : %s\n", "auto boot",		p->vm.autoboot);
	if (strcmp(p->vm.autoboot, "yes") == 0) {
		printf("|-%-12s : %s\n", "index",	p->vm.bootindex);
		printf("|-%-12s : %s sec.\n", "time",	p->vm.bootdelay);
	}

	printf("%-14s : %s\n", "nic interface",		p->vm.network_interface);
	printf("%-14s : %s\n", "nic numbers", 		p->vm.nics);
	for (int n=0; n<atoi(p->vm.nics); n++) {
		printf("%s\n", p->vm.nic[n].name);
		printf("|-%-12s : %s\n", "network mode",		p->vm.nic[n].netmode);
		if (strcmp(p->vm.nic[n].netmode, "NAT") == 0) 
			printf("|-%-12s : %s\n", "wan",		p->vm.nic[n].bind);
		else
			printf("|-%-12s : %s\n", "bind",		p->vm.nic[n].bind);
		if (strcmp(p->vm.nic[n].netmode, "NAT") == 0) {
			printf("|-%-12s : %s", "gateway", 		p->vm.nic[n].nat);
			get_nat_info(p->vm.nic[n].nat);
			printf(" [GW %s]\n", nat.ip);
			printf("|-%-12s : %s\n", "redirect",	p->vm.nic[n].rpstatus);
			if (strcmp(p->vm.nic[n].rpstatus, "enable") == 0) {
				for (int m=0; m<p->vm.nic[n].rpnum; m++) {
					char t[16];
					sprintf(t, "port(%d)", m);
					printf("  |-%-10s : %s %d:%d\n", t, 	p->vm.nic[n].ports[m].proto,	
										p->vm.nic[n].ports[m].vm_port, 
									      	p->vm.nic[n].ports[m].host_port);
				}
				//printf("  |-%-9s : %s\n", "ports",	p->vm.nic[n].rplist);
				//printf("  |-%-9s : %s\n", "bind",	p->vm.nic[n].bind);
			}
		}
		if (strcmp(p->vm.nic[n].netmode, "Bridged") == 0) {	
			//printf("|-%-11s : %s", "bind",        p->vm.nic[n].bind);
			get_switch_info(p->vm.nic[n].bind);
			if (strstr(p->vm.nic[n].bind, "switch") && strlen(Switch.ip) > 0)
				printf(" [GW %s]\n", Switch.ip);
			//printf("\n");
		}
		if (strlen(p->vm.nic[n].bridge) > 0)
		printf("|-%-12s : %s\n", "bridge", 		p->vm.nic[n].bridge);
		if (strlen(p->vm.nic[n].tap) > 0)
		printf("|-%-12s : %s\n", "tap",	 		p->vm.nic[n].tap);
		if (strlen(p->vm.nic[n].ip) > 0)
		printf("|-%-12s : %s\n", "ip",	 		p->vm.nic[n].ip);
	}



	printf("%-14s : ",     "status");
	if (get_vm_status(p->vm.name) == VM_ON)  printf("on\n");
	if (get_vm_status(p->vm.name) == VM_OFF) printf("off\n");
	printf("%-14s : %s\n", "lock", !strcmp(p->vm.lock, "1")?"yes":"no");
	
}

// 设置vm从hd启动
void vm_boot_from_hd(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ALL);
		return;
		select_vm(vm_name, VM_ALL);
		p = find_vm_list(vm_name);
	}

	strcpy(p->vm.bootfrom, "hd0");
	save_vm_info(vm_name, &p->vm);
}

void get_vm_name(char *dir)
{
	DIR *dp;
	struct dirent *dirp;

	if ((dp = opendir(dir)) == NULL) {
		error("can't open %s\n", dir);
		return;
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (dirp->d_type == DT_DIR)
			if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0)
				continue;
		
		//printf("%s\n", dirp->d_name);
		if (check_vm_files(dirp->d_name) == RET_SUCCESS)
			add_to_vm_list(dirp->d_name);
    }

    closedir(dp);
}

// 克隆vm
int vm_clone(char *src_vm_name, char *dst_vm_name)
{
	vm_node *p_src;	
	vm_node *p_dst;
	if ((p_src = find_vm_list(src_vm_name)) == NULL) {
		error("%s not exist\n", src_vm_name);
		show_vm_name(VM_OFF);
		return RET_FAILURE;
	}
	if ((p_dst = find_vm_list(dst_vm_name)) != NULL) {
		error("%s already existed\n", dst_vm_name);
		return RET_FAILURE;
	}
	if (get_vm_status(src_vm_name) == VM_ON) {
		error("%s is running, can't clone\n", src_vm_name);
		return RET_FAILURE;
	}
	if (atoi(p_src->vm.lock)) {
		error("%s has been locked up\n", src_vm_name);
		return RET_FAILURE;
	}

	printf("cloning ... ");

	//新建vm文件夹
	char dir[FN_MAX_LEN];
	sprintf(dir, "%s%s", vmdir, dst_vm_name);
	if (mkdir(dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1)
		return RET_FAILURE;

	//生成vm配置文件
	vm_stru vm;
	load_vm_info(src_vm_name, &vm);
	
	strcpy(vm.name, dst_vm_name);

	char str[FN_MAX_LEN];
	sprintf(str, "%s%s%s", vmdir, dst_vm_name, "/disk.img");
	strcpy(vm.disk, str);

	sprintf(str, "%s%s%s", vmdir, dst_vm_name, "/device.map");
	strcpy(vm.devicemap, str);

	save_vm_info(dst_vm_name, &vm);

	//生成device.map
	if (write_vm_device_map(&vm) == RET_FAILURE) {
		error("cloning device_map failure\n");
		return RET_FAILURE;
	}

	int ret;
	//克隆卷
	if (support_zfs() && strcmp(vm.zfs, "on") == 0) {
		ret = clone_zvol(&vm, src_vm_name, dst_vm_name, 1);
		printf("\033[100D\033[K\033[?25h\033[0m");
	}
	else {

		//复制disk.img
		copy_stru name;
		name.src = src_vm_name;
		name.dst = dst_vm_name;
		name.disks = atoi(p_src->vm.disks);
		//ret = wait_exec((int*)copy_vm_disk, (copy_stru*)&name);
		ret = wait_exec((fun)(int*)copy_vm_disk, (copy_stru*)&name);
	}

	if (ret == RET_FAILURE) {
		error("cloning disk failure\n");
		return RET_FAILURE;
	}
	else {
		success("Complete cloning\n");
		return RET_SUCCESS;
	}
}

// vm更名
int  vm_rename(char *old_vm_name, char *new_vm_name)
{
	char old_dir[FN_MAX_LEN];
	char new_dir[FN_MAX_LEN];
	sprintf(old_dir, "%s%s", vmdir, old_vm_name);
	sprintf(new_dir, "%s%s", vmdir, new_vm_name);

	if (access(old_dir, 0) == -1) {
		error("%s not exist\n", old_vm_name);
		show_vm_name(VM_OFF);
		return RET_FAILURE;
	}

	if (access(new_dir, 0) == 0) {
		error("%s already existed\n", new_vm_name);
		return RET_FAILURE;
	}

	if (get_vm_status(old_vm_name) == VM_ON) {
		error("%s is running, can't rename\n", old_vm_name);
		return RET_FAILURE;
	}

	vm_node *p = find_vm_list(old_vm_name);
	if (atoi(p->vm.lock)) {
		error("%s has been locked up\n", old_vm_name);
		return RET_FAILURE;
	}

	//修改vm配置文件
	vm_stru vm;
	load_vm_info(old_vm_name, &vm);
	
	strcpy(vm.name, new_vm_name);

	char str[FN_MAX_LEN];
	sprintf(str, "%s%s", new_dir, "/disk.img");
	strcpy(vm.disk, str);

	sprintf(str, "%s%s", new_dir, "/device.map");
	strcpy(vm.devicemap, str);

	save_vm_info(old_vm_name, &vm);

	//vm文件夹更名
	if (rename(old_dir, new_dir) == -1) {
		error("directory file\n");
		return RET_FAILURE;
	}

	//vm配置文件更名
	char old[FN_MAX_LEN];
	char new[FN_MAX_LEN];
	sprintf(old, "%s/%s.conf", new_dir, old_vm_name);
	sprintf(new, "%s/%s.conf", new_dir, new_vm_name);

	if (rename(old, new) == -1) {
		error("configure file\n");
		return RET_FAILURE;
	}

	//修改device.map
	if (write_vm_device_map(&vm) == RET_FAILURE) {
		error("device_map file\n");
		return RET_FAILURE;
	}

	//卷更名
	if (support_zfs() && strcmp(p->vm.zfs, "on") == 0)
		rename_zvol(&vm, old_vm_name, new_vm_name);

	success("Rename success\n");
	return RET_SUCCESS;
}

// 删除vm
int vm_remove(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return RET_FAILURE;
	}
	
	if (atoi(p->vm.lock)) {
		error("%s has been locked up\n", vm_name);
		return RET_FAILURE;
	}

	WARN("Enter 'YES' To remove the vm: ");
	char str[BUFFERSIZE];
	fgets(str, BUFFERSIZE, stdin);
	str[strlen(str)-1] = '\0';
	if (strcmp(str, "YES") == 0) {
		printf("\033[1A\033[K");
	}
	else {
		printf("\033[1A\033[K");
		warn("cancelled\n");
		return RET_FAILURE;
	}

	char filename[FN_MAX_LEN];

	//disk
	for (int n=0; n<atoi(p->vm.disks); n++) {
		char disk[32];
		if (n == 0)
			strcpy(disk, "/disk.img");
		else
			sprintf(disk, "/disk%d.img", n);
		sprintf(filename, "%s%s%s", vmdir, vm_name, disk);

		if (support_zfs() && strcmp(p->vm.zfs, "on") == 0) 
			remove_zvol(&p->vm, n);
		
		if (remove(filename) == -1) {
			error("%s can't remove\n", filename);
			return RET_FAILURE;
		}

	}
	
	//device.map
	sprintf(filename, "%s%s/device.map", vmdir, vm_name);
	if (remove(filename) == -1) {
	       	error("%s can't remove\n", filename);
		return RET_FAILURE;
	}

	//config file
	sprintf(filename, "%s%s/%s.conf", vmdir, vm_name, vm_name);
	if (remove(filename) == -1) {
		error("%s can't remove\n", filename);
		return RET_FAILURE;
	}

	//directory
	sprintf(filename, "%s%s", vmdir, vm_name);
	if (remove(filename) == 0) {
		success("Remove success\n");
		return RET_SUCCESS;
	}
	else {
		error("%s can't remove\n", filename);
		return RET_FAILURE;
	}
}

// 增加一块新磁盘
void vm_add_disk(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
	}

	if (get_vm_status(vm_name) == VM_ON) {
		error("%s is running, can't add an new disk\n", vm_name);
		return;
	}

	if (atoi(p->vm.lock)) {
		error("%s has been locked up\n", vm_name);
		return;
	}

	int new_disk_ord = atoi(p->vm.disks);
	if (new_disk_ord == DISK_NUM) {
		error("The number of disks reached the limit\n");
		err_exit();
	}
	char msg[BUFFERSIZE];
	sprintf(msg, "Enter new vm disk(%d) size (e.g. 5g): ", new_disk_ord);
	char disk_size[32];
	enter_numbers(msg, "mMgGtT", (char*)&disk_size);

	//char *img = &p->vm.imgsize + new_disk_ord * disk_offset(&p->vm);
	char *img = (char*)&p->vm.vdisk[new_disk_ord].size;
	strcpy(img, disk_size);

	create_vm_disk(&p->vm, new_disk_ord);

	sprintf(p->vm.disks, "%d", new_disk_ord + 1);
	save_vm_info(vm_name, &p->vm);
}

// 删除一块磁盘
void vm_del_disk(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
	}

	if (get_vm_status(vm_name) == VM_ON) {
		error("%s is running, can't del disk\n", vm_name);
		return;
	}

	if (atoi(p->vm.lock)) {
		error("%s has been locked up\n", vm_name);
		return;
	}

	//选择盘号
	int n = select_disk(&p->vm);
	if (n == 0) {
		error("can't delete disk(0)\n");
		err_exit();
	}

	
	//删除选中的磁盘
	char filename[FN_MAX_LEN];
	char disk[32];
	if (n == 0)
		strcpy(disk, "/disk.img");
	else
		sprintf(disk, "/disk%d.img", n);
	sprintf(filename, "%s%s%s", vmdir, vm_name, disk);
	if (remove(filename) == -1) {
		error("%s can't remove\n", filename);
		err_exit();
	}

	//修改受影响的磁盘文件名
	for (int i=n+1; i<atoi(p->vm.disks); i++) {
		char old[FN_MAX_LEN];
		char new[FN_MAX_LEN];
		sprintf(old, "%s%s/disk%d.img", vmdir, vm_name, i); 
		sprintf(new, "%s%s/disk%d.img", vmdir, vm_name, i - 1); 
		if (rename(old, new) == -1) {
			error("reanme %s error\n");
			err_exit();
		}
		//printf("old=%s ==> new=%s\n", old, new);
	}

	//修改vm配置文件
	for (int i=n+1; i<atoi(p->vm.disks); i++) {
		char *old;
		char *new;
		//old = &p->vm.imgsize + i * disk_offset(&p->vm);
		//new = &p->vm.imgsize + (i - 1) * disk_offset(&p->vm);
		old = p->vm.vdisk[i].size;
		new = p->vm.vdisk[i-1].size;
		strcpy(new, old);
		//printf("old=%s ==> new=%s\n", old, new);
	}
	//strcpy(&p->vm.imgsize + (atoi(p->vm.disks) - 1) * disk_offset(&p->vm), "");
	strcpy(p->vm.vdisk[atoi(p->vm.disks) - 1].size, "");
	sprintf(p->vm.disks, "%d", atoi(p->vm.disks) - 1);

	//写入配置文件
	save_vm_info(vm_name, &p->vm);

}

// 选择磁盘
int select_disk(vm_stru *vm)
{
	char *msg = "Which disk: ";
	char *opts[DISK_NUM] = {"0", "1", "2", "3", "4", "5", "6", "7"};
	char *desc[DISK_NUM] = {0};
	int disk_num = atoi(vm->disks);
	opts[disk_num] = NULL;
	for(int n=0; n<disk_num; n++) {
		desc[n] = (char*)malloc(BUFFERSIZE * sizeof(char));
		memset(desc[n], 0, BUFFERSIZE * sizeof(char)); 
		//sprintf(desc[n], "disk(%d) - %s", n, (char*)(&vm->imgsize + n * disk_offset(vm)));
		sprintf(desc[n], "disk(%d) - %s", n, vm->vdisk[n].size);
	}

	char disk[32];
	enter_options(msg, opts, desc, (char*)&disk);

	int n = 0;
	while (desc[n]) {
		free(desc[n]);
		++n;
	}

	return atoi(disk);
}


// 复制vm磁盘文件
int copy_vm_disk(copy_stru *name)
{
	char src[FN_MAX_LEN];
	char dst[FN_MAX_LEN];

	for (int n=0; n<name->disks; n++) {
		char disk[32];
		if (n == 0)
			strcpy(disk, "/disk.img");
		else
			sprintf(disk, "/disk%d.img", n);
		sprintf(src, "%s%s%s", vmdir, name->src, disk);
		sprintf(dst, "%s%s%s", vmdir, name->dst, disk);

		FILE *in, *out;
		if ((in = fopen(src, "rb")) == NULL) {
			error("open %s error\n", src);
			return RET_FAILURE;
		}

		if ((out = fopen(dst, "wb")) == NULL) {
			error("open %s error\n", dst);
			return RET_FAILURE;
		}

		char buf[BUFFERSIZE];
		memset(buf, 0, BUFFERSIZE);

		int len_in, len_out;

		while ((len_in = fread(buf, 1, BUFFERSIZE, in)) > 0) {
			if ((len_out = fwrite(buf, 1, len_in, out)) != len_in) {
				error("write to file '%s' failed!\n", dst);
				fclose(in);
				fclose(out);
				return RET_FAILURE;
			}
			memset(buf, 0, BUFFERSIZE);
		}
		
		fclose(in);
		fclose(out);
	}

	return RET_SUCCESS;
}



// 检测vm文件的完整性
int check_vm_files(char *vm_name)
{
	char file1[FN_MAX_LEN];
	char file2[FN_MAX_LEN];
	char file3[FN_MAX_LEN];
	
	sprintf(file1, "%s%s/device.map", vmdir, vm_name);
	sprintf(file2, "%s%s/disk.img", vmdir, vm_name);
	sprintf(file3, "%s%s/%s.conf", vmdir, vm_name, vm_name);

	//struct stat st;
	//if (stat(file2, &st) == -1) return RET_FAILURE;
	if (access(file1, 0) == -1) return RET_FAILURE;
	if (access(file2, 0) == -1) return RET_FAILURE;
	if (access(file3, 0) == -1) return RET_FAILURE;

	return RET_SUCCESS;

}

// 创建vm列表
void create_vm_list()
{
	destroy_vm_list();
	vms = NULL;
}

// 销毁vm列表
void destroy_vm_list()
{
	if (vms == NULL) 
		return;

	vm_node *p = vms;
	while (p) {
		p = vms->next;
		free(vms);
		vms = p;
	}
}

// 在列表中查找指定的vm
vm_node* find_vm_list(char *vm_name)
{
	if (vm_name == NULL) return NULL;

	vm_node *p = vms;
	while(p) {
		if (strcmp(vm_name, p->vm.name) == 0)
			return p;
		else
			p = p->next;
	}

	return NULL;
}

// 从列表中删除一个vm
int  del_from_vm_list(char *vm_name)
{
	vm_node *prev, *cur;
	prev = cur = vms;

	while (cur) {
		if (strcmp(vm_name, cur->vm.name) == 0) {
			prev->next = cur->next;
			free(cur);
			return RET_SUCCESS;
		}
		else {
			prev = cur;
			cur = cur->next;
		}
	}

	return RET_FAILURE;
}


// 添加vm到列表
void add_to_vm_list(char *vm_name)
{
	char filename[FN_MAX_LEN];
	sprintf(filename, "%s%s/%s.conf", vmdir, vm_name, vm_name);	
	if (access(filename, 0) == -1) {
		error("%s not exist\n", filename);
		return;
	}

	vm_node *new;
	new = (vm_node*)malloc(sizeof(vm_node));
	if (new == NULL) {
		error("malloc vm error");
		return;
	}

	memset(new, 0, sizeof(vm_node));

	if (vms == NULL)
		vms = new;

	vm_node *p = vms;
	while (p->next) 
		p = p->next;

	p->next = new;
	load_vm_info(vm_name, &(new->vm));	
	new->next = NULL;
}

// 将vm列表按名称排序
void sort_vm_list(int type)
{
	char *s1, *s2;
	for (vm_node *p1=vms; p1!=NULL; p1=p1->next)
		for (vm_node *p2=p1->next; p2!=NULL; p2=p2->next) {
			if (type == LS_BY_NAME) {
				s1 = p1->vm.name;
				s2 = p2->vm.name;
			} 
			else if (type == LS_BY_IP) {
				s1 = p1->vm.nic[0].ip;
				s2 = p2->vm.nic[0].ip;
			}
			else if (type == LS_BY_OS) {
				s1 = p1->vm.ostype;
				s2 = p2->vm.ostype;
			}
			else if (type == LS_BY_STATUS) {
				s1 = p1->vm.status;
				s2 = p2->vm.status;
			}
			if (strcmp(s1, s2) > 0) {
			//if (strcmp(p1->vm.name, p2->vm.name) > 0) {
				vm_stru t;
				t = p1->vm;
				p1->vm = p2->vm;
				p2->vm = t;
			}
		}
}

// 载入vm配置信息
void load_vm_info(char *vm_name, vm_stru *vm)
{
	char filename[FN_MAX_LEN];
	sprintf(filename, "%s%s/%s.conf", vmdir, vm_name, vm_name);

	init_config(filename);
	
	char *value;
	char str[BUFFERSIZE];

	if ((value = get_value_by_name("vm_name")) != NULL)
		strcpy(vm->name, value);
	if ((value = get_value_by_name("vm_profile")) != NULL)
		strcpy(vm->profile, value);
	if ((value = get_value_by_name("vm_disks")) != NULL)
		strcpy(vm->disks, value);
	else
		strcpy(vm->disks, "1");

	for (int n=0; n<atoi(vm->disks); n++) {
		sprintf(str, "vm_disk%d_name", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->vdisk[n].name, value);
		sprintf(str, "vm_disk%d_size", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->vdisk[n].size, value);
		sprintf(str, "vm_disk%d_path", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->vdisk[n].path, value);
	}
	if ((value = get_value_by_name("vm_zfs")) != NULL)
		strcpy(vm->zfs, value);
	if ((value = get_value_by_name("vm_zpool")) != NULL)
		strcpy(vm->zpool, value);

	if ((value = get_value_by_name("vm_ram")) != NULL)
		strcpy(vm->ram, value);
	if ((value = get_value_by_name("vm_cpus")) != NULL)
		strcpy(vm->cpus, value);
	if ((value = get_value_by_name("vm_ostype")) != NULL)
		strcpy(vm->ostype, value);
	if ((value = get_value_by_name("vm_version")) != NULL)
		strcpy(vm->version, value);
	if ((value = get_value_by_name("vm_cdstatus")) != NULL)
		strcpy(vm->cdstatus, value);
	else
		strcpy(vm->cdstatus, "on");
	if ((value = get_value_by_name("vm_iso")) != NULL)
		strcpy(vm->iso, value);
	if ((value = get_value_by_name("vm_bootfrom")) != NULL)
		strcpy(vm->bootfrom, value);
	if ((value = get_value_by_name("vm_hostbridge")) != NULL)
		strcpy(vm->hostbridge, value);
	if ((value = get_value_by_name("vm_uefi")) != NULL)
		strcpy(vm->uefi, value);
	if ((value = get_value_by_name("vm_disk")) != NULL)
		strcpy(vm->disk, value);
	if ((value = get_value_by_name("vm_devicemap")) != NULL)
		strcpy(vm->devicemap, value);
	if ((value = get_value_by_name("vm_grubcmd")) != NULL)
		strcpy(vm->grubcmd, value);
	if ((value = get_value_by_name("vm_nics")) != NULL)
		strcpy(vm->nics, value);
	for (int n=0; n<atoi(vm->nics); n++) {
		sprintf(str, "vm_nic%d_name", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].name, value);
		sprintf(str, "vm_nic%d_netmode", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].netmode, value);
		sprintf(str, "vm_nic%d_nat", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].nat, value);
		sprintf(str, "vm_nic%d_rpstatus", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].rpstatus, value);
		sprintf(str, "vm_nic%d_rpnum", n);
		if ((value = get_value_by_name(str)) != NULL)
			vm->nic[n].rpnum = atoi(value);

		for (int m=0; m<vm->nic[n].rpnum; m++) {
			sprintf(str, "vm_nic%d_ports%d_protocol", n, m);
			if ((value = get_value_by_name(str)) != NULL)
				strcpy(vm->nic[n].ports[m].proto, value);
			sprintf(str, "vm_nic%d_ports%d_vm_port", n, m);
			if ((value = get_value_by_name(str)) != NULL)
				vm->nic[n].ports[m].vm_port = atoi(value);
			sprintf(str, "vm_nic%d_ports%d_host_port", n, m);
			if ((value = get_value_by_name(str)) != NULL)
				vm->nic[n].ports[m].host_port = atoi(value);
		}

		sprintf(str, "vm_nic%d_rplist", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].rplist, value);
		sprintf(str, "vm_nic%d_bridge", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].bridge, value);
		sprintf(str, "vm_nic%d_tap", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].tap, value);
		sprintf(str, "vm_nic%d_ip", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].ip, value);
		sprintf(str, "vm_nic%d_bind", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].bind, value);
	}

	if ((value = get_value_by_name("vm_vncstatus")) != NULL)
		strcpy(vm->vncstatus, value);
	else
		strcpy(vm->vncstatus, "on");
	if ((value = get_value_by_name("vm_vncport")) != NULL)
		strcpy(vm->vncport, value);
	if ((value = get_value_by_name("vm_vncwidth")) != NULL)
		strcpy(vm->vncwidth, value);
	if ((value = get_value_by_name("vm_vncheight")) != NULL)
		strcpy(vm->vncheight, value);

	if ((value = get_value_by_name("vm_autoboot")) != NULL)
		strcpy(vm->autoboot, value);
	else
		strcpy(vm->autoboot, "no");
	if ((value = get_value_by_name("vm_bootindex")) != NULL)
		strcpy(vm->bootindex, value);
	if ((value = get_value_by_name("vm_bootdelay")) != NULL)
		strcpy(vm->bootdelay, value);

	if ((value = get_value_by_name("vm_status")) != NULL) {
		if (get_vm_status(vm->name) == VM_OFF)
			strcpy(vm->status, "off");
		else {
			if (get_vm_status(vm->name) == VM_ON)
				strcpy(vm->status, "on");
		}
	}

	if ((value = get_value_by_name("vm_lock")) != NULL)
		strcpy(vm->lock, value);
	if ((value = get_value_by_name("vm_booter")) != NULL)
		strcpy(vm->booter, value);
	else
		strcpy(vm->booter, "bvmb");

	if ((value = get_value_by_name("vm_network_interface")) != NULL)
		strcpy(vm->network_interface, value);
	else
		strcpy(vm->network_interface, "e1000");

	if ((value = get_value_by_name("vm_storage_interface")) != NULL)
		strcpy(vm->storage_interface, value);
	else
		strcpy(vm->storage_interface, "ahci-hd");


	free_config();
}

// 写入vm配置信息
void save_vm_info(char *vm_name, vm_stru *vm)
{
	char filename[FN_MAX_LEN];
	sprintf(filename, "%s%s/%s.conf", vmdir, vm_name, vm_name);

	FILE *fp;
	if ((fp = fopen(filename, "w")) == NULL) {
		error("open %s error\n", filename);
		exit(1);
	}

	char str[BUFFERSIZE];

	sprintf(str, "vm_name=%s\n", vm->name);
	fputs(str, fp);
	sprintf(str, "vm_profile=%s\n", vm->profile);
	fputs(str, fp);
	sprintf(str, "vm_storage_interface=%s\n", vm->storage_interface);
	fputs(str, fp);
	sprintf(str, "vm_disks=%s\n", vm->disks);
	fputs(str, fp);
	for (int n=0; n<atoi(vm->disks); n++) {
		sprintf(str, "vm_disk%d_name=disk%d\n", n, n);
		fputs(str, fp);
		sprintf(str, "vm_disk%d_size=%s\n", n, vm->vdisk[n].size);
		fputs(str, fp);
		char disk[BUFFERSIZE];
		if (n == 0) 
			strcpy(disk, "disk.img");
		else
			sprintf(disk, "disk%d.img", n);
		sprintf(str, "vm_disk%d_path=%s%s/%s\n", n, vmdir, vm->name, disk);
		fputs(str, fp);
	}
	sprintf(str, "vm_zfs=%s\n", vm->zfs);
	fputs(str, fp);
	sprintf(str, "vm_zpool=%s\n", vm->zpool);
	fputs(str, fp);


	/*
	//------------
	sprintf(str, "vm_imgsize=%s\n", vm->imgsize);
	fputs(str, fp);

	int offset = &vm->img1size - &vm->imgsize;
	for (int n=1; n<atoi(vm->disks); n++) {
		sprintf(str, "vm_img%dsize=%s\n", n, (char*)(&vm->imgsize + n * offset));
		fputs(str, fp);
	}
	//------------
	*/

	sprintf(str, "vm_ram=%s\n", vm->ram);
	fputs(str, fp);
	sprintf(str, "vm_cpus=%s\n", vm->cpus);
	fputs(str, fp);
	fputs("\n", fp);

	sprintf(str, "vm_ostype=%s\n", vm->ostype);
	fputs(str, fp);
	sprintf(str, "vm_version=%s\n", vm->version);
	fputs(str, fp);
	sprintf(str, "vm_cdstatus=%s\n", vm->cdstatus);
	fputs(str, fp);
	sprintf(str, "vm_iso=%s\n", vm->iso);
	fputs(str, fp);
	sprintf(str, "vm_bootfrom=%s\n", vm->bootfrom);
	fputs(str, fp);
	sprintf(str, "vm_hostbridge=%s\n", vm->hostbridge);
	fputs(str, fp);
	sprintf(str, "vm_uefi=%s\n", vm->uefi);
	fputs(str, fp);
	sprintf(str, "vm_disk=%s\n", vm->disk);
	fputs(str, fp);
	sprintf(str, "vm_devicemap=%s\n", vm->devicemap);
	fputs(str, fp);
	sprintf(str, "vm_grubcmd=%s\n", vm->grubcmd);
	fputs(str, fp);
	fputs("\n", fp);
	
	sprintf(str, "vm_network_interface=%s\n", vm->network_interface);
	fputs(str, fp);
	sprintf(str, "vm_nics=%s\n", vm->nics);
	fputs(str, fp);
	for (int n=0; n<atoi(vm->nics); n++) {
		sprintf(str, "vm_nic%d_name=nic_%d\n", n, n);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_netmode=%s\n", n, vm->nic[n].netmode);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_nat=%s\n", n, vm->nic[n].nat);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_rpstatus=%s\n", n, vm->nic[n].rpstatus);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_rpnum=%d\n", n, vm->nic[n].rpnum);
		fputs(str, fp);

		for (int m=0; m<vm->nic[n].rpnum; m++) {
			sprintf(str, "vm_nic%d_ports%d_protocol=%s\n", n, m, vm->nic[n].ports[m].proto);
			fputs(str, fp);
			sprintf(str, "vm_nic%d_ports%d_vm_port=%d\n", n, m, vm->nic[n].ports[m].vm_port);
			fputs(str, fp);
			sprintf(str, "vm_nic%d_ports%d_host_port=%d\n", n, m, vm->nic[n].ports[m].host_port);
			fputs(str, fp);
		}

		sprintf(str, "vm_nic%d_rplist=%s\n", n, vm->nic[n].rplist);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_bridge=%s\n", n, vm->nic[n].bridge);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_tap=%s\n", n, vm->nic[n].tap);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_ip=%s\n", n, vm->nic[n].ip);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_bind=%s\n", n, vm->nic[n].bind);
		fputs(str, fp);
	}
	fputs("\n", fp);

	sprintf(str, "vm_vncstatus=%s\n", vm->vncstatus);
	fputs(str, fp);
	sprintf(str, "vm_vncport=%s\n", vm->vncport);
	fputs(str, fp);
	sprintf(str, "vm_vncwidth=%s\n", vm->vncwidth);
	fputs(str, fp);
	sprintf(str, "vm_vncheight=%s\n", vm->vncheight);
	fputs(str, fp);
	fputs("\n", fp);

	sprintf(str, "vm_autoboot=%s\n", vm->autoboot);
	fputs(str, fp);
	sprintf(str, "vm_bootindex=%s\n", vm->bootindex);
	fputs(str, fp);
	sprintf(str, "vm_bootdelay=%s\n", vm->bootdelay);
	fputs(str, fp);
	fputs("\n", fp);

	sprintf(str, "vm_status=%s\n", get_vm_status(vm->name)==VM_ON?"on":"off");
	//sprintf(str, "vm_status=%s\n", vm->status);
	fputs(str, fp);
	sprintf(str, "vm_lock=%s\n", vm->lock);
	fputs(str, fp);
	sprintf(str, "vm_booter=%s\n", vm->booter);
	fputs(str, fp);
	fputs("\n", fp);


	fclose(fp);

}

// 显示所有vm_name
void show_vm_name(int status)
{
	if (vms == NULL) return;

	char *msg = "Optional vms: ";
	int printed = 0;

	int n = 0;
	vm_node *p = vms;
	while (p) {
		if (status == VM_ALL || get_vm_status(p->vm.name) == status) {
			if (printed == 0) warn("%s\n", msg);
			printed = 1;		
			printf("%2d.%s\n", ++n, p->vm.name);
		}
		p = p->next;
	}
}

// 从状态相同的vm列表中选择
// 用于命令行没有输入vm_name的处理
void select_vm(char *vm_name, int status)
{
	if (vms == NULL) return;

	char *msg = "Select vm: ";
	char *jname[BUFFERSIZE] = {0};
	
	int n = 0;
	vm_node *p = vms;
	while (p) {
		if (status == VM_ALL || get_vm_status(p->vm.name) == status) {
			jname[n++] = p->vm.name;
		}
		p = p->next;
	}

	if (n > 0)
		enter_options(msg, jname, NULL, vm_name);
}

// 输出vm列表
void print_vm_list(int list_type)
{
	if (vms == NULL) return;

	if (list_type == VM_LONG_LIST)
		title("NAME\t\tIP\t\t\tGUEST\t\tLOADER\tAUTOSTART\tCPU\tMEMORY\tDISK\t\tSTATE\n");
	else
		title("NAME\t\tGUEST\t\tCPU\tMEMORY\tDISK\t\tSTATE\n");
	vm_node *p = vms;
	while (p) {
		/* NAME */
		printf("%s", p->vm.name);
		for (int n=0; n<(2-strlen(p->vm.name) / TABSTOP); n++) printf("\t");

		/* IP */
		if (list_type == VM_LONG_LIST) {
			printf("%s", p->vm.nic[0].ip);
			for (int n=0; n<(3-strlen(p->vm.nic[0].ip) / TABSTOP); n++) printf("\t");
		}

		/* GUEST */
		printf("%s", p->vm.ostype);
		for (int n=0; n<(2-strlen(p->vm.ostype) / TABSTOP); n++) printf("\t");
		
		/* LOADER */
		if (list_type == VM_LONG_LIST) {
			if (strcmp(p->vm.uefi, "uefi") == 0)
				printf("uefi\t");
			else
				printf("grub\t");
		}

		/* AUTO-START */
		if (list_type == VM_LONG_LIST) {
			if (strcmp(p->vm.autoboot, "yes") == 0) {
				char str[16];
				sprintf(str, "Yes [%d]", atoi(p->vm.bootindex));
				printf("%s", str);
				for (int n=0; n<(2-strlen(str) / TABSTOP); n++) printf("\t");
			}
			else
				printf("No\t\t");
		}


		/* CPU */
		printf("%s\t"  , p->vm.cpus);

		/* MEMORY */
		printf("%s\t"  , strtoupper(p->vm.ram));

		/* 容量 
		char str[16];
		unit_convert(total_disk_size(&p->vm), 1, str);
		printf("%s\t\t", str);
		*/

		/* 容量[磁盘数量]
		char str[16];
		unit_convert(total_disk_size(&p->vm), 1, str); 
		int n = atoi(p->vm.disks);
		//if (n > 1)
			sprintf(str, "%s[%d]", str, n);
		printf("%s", str);
		for (int n=0; n<(2-strlen(str)/TABSTOP); n++) printf("\t");
		*/

		/* [磁盘数量]容量 */
		char str1[16], str2[16];
		int n = atoi(p->vm.disks);
		sprintf(str1, "[%d]", n);
		unit_convert(total_disk_size(&p->vm), 1, str2);
		strcat(str1, str2);
		printf("%s", strtoupper(str1));
		for (int n=0; n<(2-strlen(str1)/TABSTOP); n++) printf("\t");
		
		/* STATE */
		//if (strcmp(p->vm.status, "off") == 0)
		//	printf("\033[33m");
		if (strcmp(p->vm.status, "on") == 0)
			printf("\033[32;1m");
		printf("%s\033[0m", p->vm.status);

		/* PID */
		//if (strcmp(p->vm.status, "on") == 0) 
		//	printf(" (%d)", get_vm_pid(&p->vm));

		if (strcmp(p->vm.lock, "1") == 0)
			warn(" *");
		printf("\n");
		p = p->next;
	}
}

// 获得vm的数量
int get_vm_count()
{
	int cnt = 0;

	if (vms == NULL) 
		return 0;

	vm_node *p = vms;
	while (p) {
		++cnt;
		p = p->next;
	}
	return cnt;
}

// 获取vm的状态
// 开机：VM_ON / 关机：VM_OFF
int get_vm_status(char *vm_name)
{
	char fn[FN_MAX_LEN];
	sprintf(fn, "/dev/vmm/%s", vm_name);
	
	if (access(fn, 0) == -1)
		return VM_OFF;
	else
		return VM_ON;
}

// 更新vm状态
void update_vm_status(char *vm_name, int status)
{
	vm_stru vm;
	load_vm_info(vm_name, &vm);
	if (status == VM_ON)
		strcpy(vm.status, "on");
	if (status == VM_OFF)
		strcpy(vm.status, "off");
	save_vm_info(vm_name, &vm);
}

// 生成uefi启动代码
void gen_uefi_boot_code(char **code, vm_node *p)
{
}

// 生成grub启动代码
void gen_grub_boot_code(char **code, vm_node *p)
{
	//设置启动方式对应的grubcmd
	set_grub_cmd(p);
	
	//个别操作系统的处理
}

// 将启动代码写入文件
int write_boot_code(char **code, vm_node *p)
{
	//生成start.sh脚本
	char fn[FN_MAX_LEN];
	sprintf(fn, "/tmp/start_%s.sh", p->vm.name);

	FILE *fp;
	if ((fp = fopen(fn, "w")) == NULL) {
		perror(fn);
		return RET_FAILURE;
	}
	
	char vm_disk[256];
	int line = 0;
	char str[BUFFERSIZE];
	while (code[line]) {
		strcpy(str, code[line++]);
		strcat(str, "\n");

		if (strlen(p->vm.grubcmd) > 0)
			str_replace(str, "${vm_grubcmd}", p->vm.grubcmd);
		//else
		//	str_replace(str, "echo -e \"${vm_grubcmd}\" |", "");
		str_replace(str, "${vm_grubcd}", 	p->vm.grubcd);
		str_replace(str, "${vm_grubhd}", 	p->vm.grubhd);
		str_replace(str, "${vm_name}", 		p->vm.name);
		str_replace(str, "${vm_start_sh}", 	fn);
		str_replace(str, "${vm_version}", 	p->vm.version);
		str_replace(str, "${vm_bootfrom}", 	p->vm.bootfrom);
		str_replace(str, "${vm_uefi}", 		p->vm.uefi);
		str_replace(str, "${vm_devicemap}", 	p->vm.devicemap);
		str_replace(str, "${vm_ram}", 		p->vm.ram);
		str_replace(str, "${vm_cpus}", 		p->vm.cpus);
		str_replace(str, "${vm_hostbridge}", 	p->vm.hostbridge);
		str_replace(str, "${vm_disk}", 		p->vm.disk);
		str_replace(str, "${vm_iso}", 		p->vm.iso);
		str_replace(str, "${vm_vncport}", 	p->vm.vncport);
		str_replace(str, "${vm_vncwidth}", 	p->vm.vncwidth);
		str_replace(str, "${vm_vncheight}", 	p->vm.vncheight);
		if (strcmp(p->vm.uefi, "uefi") == 0)
			str_replace(str, "${vm_bhyve_uefi_fd}", "BHYVE_UEFI.fd");
		if (strcmp(p->vm.uefi, "uefi_csm")== 0)
			str_replace(str, "${vm_bhyve_uefi_fd}", "BHYVE_UEFI_CSM.fd"); 

		if (strstr(str, "${vm_tap1}") && atoi(p->vm.nics) < 2) continue;
		if (strstr(str, "${vm_tap2}") && atoi(p->vm.nics) < 3) continue;
		if (strstr(str, "${vm_tap3}") && atoi(p->vm.nics) < 4) continue;
		if (strstr(str, "${vm_tap4}") && atoi(p->vm.nics) < 5) continue;
		if (strstr(str, "${vm_tap5}") && atoi(p->vm.nics) < 6) continue;
		if (strstr(str, "${vm_tap6}") && atoi(p->vm.nics) < 7) continue;
		if (strstr(str, "${vm_tap7}") && atoi(p->vm.nics) < 8) continue;

		str_replace(str, "${vm_tap}", 		p->vm.nic[0].tap);
		str_replace(str, "${vm_tap1}", 		p->vm.nic[1].tap);
		str_replace(str, "${vm_tap2}", 		p->vm.nic[2].tap);
		str_replace(str, "${vm_tap3}", 		p->vm.nic[3].tap);
		str_replace(str, "${vm_tap4}", 		p->vm.nic[4].tap);
		str_replace(str, "${vm_tap5}", 		p->vm.nic[5].tap);
		str_replace(str, "${vm_tap6}", 		p->vm.nic[6].tap);
		str_replace(str, "${vm_tap7}", 		p->vm.nic[7].tap);

	
		sprintf(vm_disk, "%s%s/disk1.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk1}",          vm_disk);
		sprintf(vm_disk, "%s%s/disk2.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk2}",          vm_disk);
		sprintf(vm_disk, "%s%s/disk3.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk3}",          vm_disk);
		sprintf(vm_disk, "%s%s/disk4.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk4}",          vm_disk);
		sprintf(vm_disk, "%s%s/disk5.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk5}",          vm_disk);
		sprintf(vm_disk, "%s%s/disk6.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk6}",          vm_disk);
		sprintf(vm_disk, "%s%s/disk7.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk7}",          vm_disk);

		//输入shell（测试用）
		//printf("%s", str);

		fputs(str, fp);
	}

	fclose(fp);

	//赋予start.sh执行权限
	chmod(fn, S_IRUSR | S_IWUSR | S_IXUSR);
	
	return RET_SUCCESS;
}

// 生成start.sh代码
int  gen_vm_start_code(char *vm_name)
{
	char *grub_boot[] = {
		"#!/bin/sh",
		"# tmux -2 -u new -d -s ${vm_name} \"/bin/sh ${vm_start_sh}\"",
		"# tmux attach-session -t ${vm_name}",
		"boot=\"${vm_bootfrom}\"",
		"while [ 1 ]; do",
		"	if [ \"$boot\" == \"hd0\" ]; then",
		"		${vm_grubhd}",
		"	else",
		"		${vm_grubcd}",
		"	fi",
		"	bhyve   -c ${vm_cpus} -m ${vm_ram} -HAPuw \\",
		"		-s 0:0,${vm_hostbridge} \\",
		"		-s 3:0,ahci-hd,${vm_disk}  \\",
		"		-s 3:1,ahci-hd,${vm_disk1} \\",
		"		-s 3:2,ahci-hd,${vm_disk2} \\",
		"		-s 3:3,ahci-hd,${vm_disk3} \\",
		"		-s 3:4,ahci-hd,${vm_disk4} \\",
		"		-s 3:5,ahci-hd,${vm_disk5} \\",
		"		-s 3:6,ahci-hd,${vm_disk6} \\",
		"		-s 3:7,ahci-hd,${vm_disk7} \\",
		"		-s 2:0,ahci-cd,${vm_iso} \\",
		"		-s 4:0,e1000,${vm_tap} \\",
		"		-s 4:1,e1000,${vm_tap1} \\",
		"		-s 4:2,e1000,${vm_tap2} \\",
		"		-s 4:3,e1000,${vm_tap3} \\",
		"		-s 4:4,e1000,${vm_tap4} \\",
		"		-s 4:5,e1000,${vm_tap5} \\",
		"		-s 4:6,e1000,${vm_tap6} \\",
		"		-s 4:7,e1000,${vm_tap7} \\",
		"		-s 31,lpc -l com1,stdio \\",
		"		${vm_name}",
		"		",
		"	exit_stat=$?",
		"	if [ $exit_stat != 0 ]; then",
		"		break;",
		"	fi",
		"	/usr/sbin/bhyvectl --destroy --vm=${vm_name}",
		"	boot=\"hd0\"",
		"	bvm --hd-booting ${vm_name}",
		"done",
		"/usr/sbin/bhyvectl --destroy --vm=${vm_name}",
		"/sbin/ifconfig ${vm_tap} destroy",
		"/sbin/ifconfig ${vm_tap1} destroy",
		"/sbin/ifconfig ${vm_tap2} destroy",
		"/sbin/ifconfig ${vm_tap3} destroy",
		"/sbin/ifconfig ${vm_tap4} destroy",
		"/sbin/ifconfig ${vm_tap5} destroy",
		"/sbin/ifconfig ${vm_tap6} destroy",
		"/sbin/ifconfig ${vm_tap7} destroy",
		NULL
	};

	char *uefi_boot[] = {
		"#!/bin/sh",
		"boot=\"${vm_bootfrom}\"",
		"while [ 1 ]; do",
		"	if [ \"$boot\" == \"hd0\" ]; then",
		"	bhyve 	-c ${vm_cpus} -m ${vm_ram} -HAPuw \\",
		"		-s 0:0,${vm_hostbridge} \\",
		"		-s 4:0,ahci-hd,${vm_disk} \\",
		"		-s 4:1,ahci-hd,${vm_disk1} \\",
		"		-s 4:2,ahci-hd,${vm_disk2} \\",
		"		-s 4:3,ahci-hd,${vm_disk3} \\",
		"		-s 4:4,ahci-hd,${vm_disk4} \\",
		"		-s 4:5,ahci-hd,${vm_disk5} \\",
		"		-s 4:6,ahci-hd,${vm_disk6} \\",
		"		-s 4:7,ahci-hd,${vm_disk7} \\",
		"		-s 5:0,e1000,${vm_tap} \\",
		"		-s 5:1,e1000,${vm_tap1} \\",
		"		-s 5:2,e1000,${vm_tap2} \\",
		"		-s 5:3,e1000,${vm_tap3} \\",
		"		-s 5:4,e1000,${vm_tap4} \\",
		"		-s 5:5,e1000,${vm_tap5} \\",
		"		-s 5:6,e1000,${vm_tap6} \\",
		"		-s 5:7,e1000,${vm_tap7} \\",
		//"		-s 29,fbuf,tcp=0.0.0.0:${vm_vncport},w=${vm_vncwidth},h=${vm_vncheight} \\",
		"		-s 30,xhci,tablet \\",
		"		-s 31,lpc -l com1,stdio \\",
		"		-l bootrom,/usr/local/share/uefi-firmware/${vm_bhyve_uefi_fd} \\",
		"		${vm_name} ",

		"	else",
		"	bhyve 	-c ${vm_cpus} -m ${vm_ram} -HAPuw \\",
		"		-s 0:0,${vm_hostbridge} \\",
		"		-s 3:0,ahci-cd,${vm_iso} \\",
		"		-s 4:0,ahci-hd,${vm_disk} \\",
		"		-s 4:1,ahci-hd,${vm_disk1} \\",
		"		-s 4:2,ahci-hd,${vm_disk2} \\",
		"		-s 4:3,ahci-hd,${vm_disk3} \\",
		"		-s 4:4,ahci-hd,${vm_disk4} \\",
		"		-s 4:5,ahci-hd,${vm_disk5} \\",
		"		-s 4:6,ahci-hd,${vm_disk6} \\",
		"		-s 4:7,ahci-hd,${vm_disk7} \\",
		"		-s 5:0,e1000,${vm_tap} \\",
		"		-s 5:1,e1000,${vm_tap1} \\",
		"		-s 5:2,e1000,${vm_tap2} \\",
		"		-s 5:3,e1000,${vm_tap3} \\",
		"		-s 5:4,e1000,${vm_tap4} \\",
		"		-s 5:5,e1000,${vm_tap5} \\",
		"		-s 5:6,e1000,${vm_tap6} \\",
		"		-s 5:7,e1000,${vm_tap7} \\",
		"		-s 29,fbuf,tcp=0.0.0.0:${vm_vncport},w=${vm_vncwidth},h=${vm_vncheight},wait \\",
		"		-s 30,xhci,tablet \\",
		"		-s 31,lpc -l com1,stdio \\",
		"		-l bootrom,/usr/local/share/uefi-firmware/${vm_bhyve_uefi_fd} \\",
		"		${vm_name} ",
		"	fi",
		"		",
		"	exit_stat=$?",
		"	if [ $exit_stat != 0 ]; then",
		"		break;",
		"	fi",
		"	/usr/sbin/bhyvectl --destroy --vm=${vm_name}",
		"	boot=\"hd0\"",
		"	bvm --hd-booting ${vm_name}",
		"done",
		NULL
	};


	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) return RET_FAILURE;
	
	//生成启动代码
	char **code;
	if (strcmp(p->vm.uefi, "none") == 0) {
		code = grub_boot;
		gen_grub_boot_code(code, p);
	}
	else {
		code = uefi_boot;
		gen_uefi_boot_code(code, p);
	}

	return RET_SUCCESS;

	//写入启动代码
	//shell脚本
	//return write_boot_code(code, p);
}

// 设置vm的grubcmd字段
void set_grub_cmd(vm_node *p)
{
	char fn[BUFFERSIZE];
	sprintf(fn, "%s%s", osdir, "bvm.conf");
	init_config(fn);

	char item[BUFFERSIZE];
	char *value;
	if (strcmp(p->vm.bootfrom, "cd0") == 0) {
		sprintf(item, "%s_vm_grubcmd_cd", p->vm.ostype);
		if ((value = get_value_by_name(item)) != NULL)
			strcpy(p->vm.grubcmd, value);
		else {
			error("bvm.conf is error\n");
			err_exit();
		}
	}
	if (strcmp(p->vm.bootfrom, "hd0") == 0) {
		sprintf(item, "%s_vm_grubcmd_hdd", p->vm.ostype);
		if ((value = get_value_by_name(item)) != NULL)
			strcpy(p->vm.grubcmd, value);
		else {
			error("bvm.conf is error\n");
			err_exit();
		}
	}

	//设置grubcd/grubhd
	sprintf(item, "%s_vm_grubcmd_cd", p->vm.ostype);
	if ((value = get_value_by_name(item)) != NULL)
		strcpy(p->vm.grubcd, value);
	sprintf(item, "%s_vm_grubcmd_hdd", p->vm.ostype); 
	if ((value = get_value_by_name(item)) != NULL) 
		strcpy(p->vm.grubhd, value);

	
	free_config();
}

// 写入devicemap文件
int write_vm_device_map(vm_stru *vm)
{

	FILE *fp = fopen(vm->devicemap, "w");
	if (fp == NULL) {
		error("open %s error\n", vm->devicemap);
		return RET_FAILURE;
	}

	char buf[BUFFERSIZE];
	sprintf(buf, "(hd0) %s\n", vm->disk);
	fputs(buf, fp);

	sprintf(buf, "(cd0) %s\n", vm->iso);
	fputs(buf, fp);

	fclose(fp);

	return RET_SUCCESS;
}

// 创建网络 (Bridged or NAT)
int create_networking(char *vm_name)
{
	vm_node *p;
        if ((p = find_vm_list(vm_name)) == NULL) return RET_FAILURE;

	for (int n=0; n<atoi(p->vm.nics); n++) {
	
		cur_nic_idx = n;
		cur_vm = &p->vm;

		//桥接 Bridged
		if (strcmp(p->vm.nic[n].netmode, "Bridged") == 0) {

			if (create_bridged(p->vm.nic[n].bind) == RET_FAILURE) return RET_FAILURE;
		}
			

		//NAT
		else if (strcmp(p->vm.nic[n].netmode, "NAT") == 0) {

			if (create_nat(p->vm.nic[n].nat) == RET_FAILURE) return RET_FAILURE;
			run_cmd("set bvm_nat_fw=`sysctl net.inet.ip.forwarding=1`");
		}

		//错误
		else {
			return RET_FAILURE;
		}
		
		strcpy(p->vm.nic[n].bridge, bridge);
		strcpy(p->vm.nic[n].tap, tap);

		save_vm_info(vm_name, &p->vm);

		free_vnet_list(ALL);
	}

	return RET_SUCCESS;

}


// 字符串替换函数
// 将str中的ostr替换成nstr
void str_replace(char *str, char *ostr, const char *nstr)
{
    char *p;
    while ((p = strstr(str, ostr)))
    {
        int olen = strlen(ostr);
        int nlen = strlen(nstr);

        if (nlen > olen)  //新串长，向后移动
        {
            char *tmp = p;
            while (*tmp) tmp++;
            while (tmp>=p+olen)
            {
                *(tmp+(nlen-olen)) = *tmp;
                --tmp;
            }

        }
        else if (nlen < olen)   //新串短，向前移动
        {
            char *tmp = p+nlen;
            while(*(tmp+olen-nlen))
            {
                *tmp = *(tmp+olen-nlen);
                ++tmp;
            }
            *tmp = '\0';

        }
        strncpy(p, nstr, nlen);
    }

}

// 检测vm名称的拼写
int  check_spell(char *vm_name)
{
	if (vm_name == NULL) return RET_FAILURE;
	if (strlen(vm_name) == 0) return RET_FAILURE;

	char *p = vm_name;
	char ch = *p;
	if (isalpha(ch++) == 0) return RET_FAILURE;
	while (ch) {
		if (isalpha(ch) || isdigit(ch) || ch == '_' || ch == '-') {
		       ch = *++p;
		}
		else		
			return RET_FAILURE;
	}
	return RET_SUCCESS;
}

// 获得某个进程id
int bvm_get_pid(char *name)
{
	int pid;
	char cmd[BUFFERSIZE];
	sprintf(cmd, "ps | grep \"%s\" | grep -v grep | awk '{print $1}'", name);
	char buf[16];
	FILE *fp = popen(cmd, "r");
	if (fgets(buf, 16, fp)) {
		buf[strlen(buf)-1] = '\0';
		pid = atoi(buf);
	}
	else
		pid = -1;

	pclose(fp);

	return pid;
}


// 获得vm的进程id
int get_vm_pid(vm_stru *vm)
{
	int pid;
	char cmd[BUFFERSIZE];
	//sprintf(cmd, "ps | grep \"bvmb %s\" | grep -v csh | grep -v grep | awk '{print $1}'", vm->name);
	sprintf(cmd, "ifconfig %s | grep Opened | awk '{print $4}'", vm->nic[0].tap);
	char buf[16];
	FILE *fp = popen(cmd, "r");
	if (fgets(buf, 16, fp)) {
		buf[strlen(buf)-1] = '\0';
		pid = atoi(buf);
	}
	else
		pid = -1;

	pclose(fp);

	return pid;
}

// 获取是否支持虚拟化
int get_vmx(vm_stru *vm)
{
	int value;
	char cmd[BUFFERSIZE];
	sprintf(cmd, "sysctl hw.vmm.vmx.initialized | awk -F: '{print $2}'");
	char buf[16];
	FILE *fp = popen(cmd, "r");
	if (fgets(buf, 16, fp)) {
		buf[strlen(buf)-1] = '\0';
		value = atoi(buf);
	}
	else
		value = -1;

	pclose(fp);

	return value;
}


// 获得bvm支持os的启动状态
void get_bvm_os(os_stru *os)
{
	//if (os->type == NULL) return;

	int n = 0;
	while (strlen(bvm_os[n].type) > 0) {
		if (strcmp(bvm_os[n].type, os->type) == 0) {
			os->uefi_boot = bvm_os[n].uefi_boot;
			os->grub_boot = bvm_os[n].grub_boot;
			os->grub_cmd  = bvm_os[n].grub_cmd;
			return;
		}
		++n;
	}
}

// 检测操作系统对uefi的支持
int support_uefi(char *os)
{
	int n = 0;
	while (strlen(bvm_os[n].type) > 0) {
		if (strcmp(bvm_os[n].type, os) == 0) {
			return bvm_os[n].uefi_boot;
		}
		++n;
	}
	return -1;
}

// 检测操作系统对grub的支持
int support_grub(char *os)
{
	int n = 0;
	while (strlen(bvm_os[n].type) > 0) {
		if (strcmp(bvm_os[n].type, os) == 0) {
			return bvm_os[n].grub_boot;
		}
		++n;
	}
	return -1;
}

/*
// 磁盘文件在conf中的偏移量
int disk_offset(vm_stru *vm)
{
	return &vm->img1size - &vm->imgsize;
}
*/

// 检查磁盘空间的有效性
int check_vm_disks(vm_stru *vm)
{
	//int offset = &vm->img1size - &vm->imgsize;
	int disks = atoi(vm->disks);
	if (disks == 0) return -1;
	for (int n=0; n<disks; n++) {
		//if (strlen((char*)(&vm->imgsize + n * offset)) == 0)
		if (strlen(vm->vdisk[n].size) == 0)
			return -1;
	}
	return 1;
}

// 发生错误时退出处理函数
void err_exit()
{
	//释放vm和vnet分配的内存
	vm_end();
	free_vnet_list(ALL);

	exit(1);
}

// 执行wait处理函数
// func为需等待完成的函数
// args为func的参数
// 如果多个参数，需要使用结构体进行强制转换
int wait_exec(fun func, void *args)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	pid_t pid;

	pid = fork();

	if (pid == 0) waitting();
	else if (pid < 0) error("fork error\n");
	else {
		int ret;
		//ret = (func)(args);
		ret = (int)(func)(args);
		kill(pid, SIGTERM);
		printf("\033[100D\033[K\033[?25h\033[0m");
		//printf("\n");
		return ret;
	}
	return 0;
}

// waitting
void waitting()
{
	char *msg = "\033[32m\033[?25l";
	char ch[4] = {'\\', '|', '/', '-'};

	printf(" %s", msg);

	int n = 0;
	while (1) {
		printf("%c", ch[n]);
		usleep(100000);
		printf("\033[1D");
		if (++n >= 4) n = 0;
	}
}

// 时间延迟
// 参数sec为延迟秒数
void delay(int sec)
{
	 clock_t start, finish;
         start = clock();
 	 while (1) {
		finish = clock();
		double pass = (double)(finish - start) / CLOCKS_PER_SEC;
		if ((int)pass > sec) {
			return;
		}
	}

}

//输出最新的地址池分配情况
void show_dhcp_pool()
{
	char fn[FN_MAX_LEN];
	sprintf(fn, "%s/%s", vmdir, dhcp_pool_file);

     	FILE *fp;
	if ((fp = fopen(fn, "r")) == NULL) return;

	char line[BUFFERSIZE];
	while (fgets(line , BUFFERSIZE, fp)) {
		printf("%s", line);
	}

	fclose(fp);

}

// 错误信息（红色高亮）
int error(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	//屏幕输出
	printf("\033[1;31m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	
	//日志输出
	write_log_time();
	if (logfp) {
		fprintf(logfp, "[error] ");
		va_start(argptr, fmt);
		cnt = vfprintf(logfp, fmt, argptr);
		va_end(argptr);
	
		if (lastch(fmt) != '\n') fprintf(logfp, "\n");

		fclose(logfp);
	}
	
	return cnt;
}

// 调试输出
int debug(unsigned color, char *fmt, ...)
{	
#ifdef BVM_DEBUG
	va_list argptr;
	int cnt;

	if (color == NOCOLOR)
		printf("\033[m");
	if (color == RED)
		printf("\033[1;31m");
	if (color == GREEN)
		printf("\033[32m");
	if (color == YELLOW)
		printf("\033[1;33m");

	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;
#else
	return 0;
#endif
}

// 严重警告信息（红色高亮闪烁）
int WARN(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	printf("\033[1;5;31m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;

}


// 警告信息（黄色高亮）
int warn(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	printf("\033[1;33m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;

}

// 成功信息（绿色高亮）
int success(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	printf("\033[1;32m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;

}

// 输出文字(绿色)
int green(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	printf("\033[32m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;

}

// 输出文字(红色高亮)
int red(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	printf("\033[1;31m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;

}

// 标题格式输出（下划线+高亮）
int title(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	printf("\033[4;1m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;

}
