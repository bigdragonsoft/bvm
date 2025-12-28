/*-----------------------------------------------------------------------------
   BVM Copyright (c) 2018-2026, Qiang Guo (bigdragonsoft@gmail.com)
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


#include "main.h"

pro_stru program = {
	"bvm", 
	"1.4.0", 
	"Qiang Guo",
	"bigdragonsoft@gmail.com",
	"https://github.com/bigdragonsoft/bvm",
};

// 版本
void version()
{
	printf("%s %s\n", program.name, program.version);
	printf("author: %s\n", program.author);
	printf("email: %s\n", program.email);
	printf("%s\n", program.website);
	printf("Copyright (C) 2017~2026 BigDragonSoft.com, ChinaFreeBSD.cn\n");
}

// 程序用法
void usage()
{
	char *help[] = {
		"Usage:	${name} <options> [args...]",
		"",
		"VM Management Options:",
		"	--create	Create new VM",
		"",
		"	        	Usage: ${name} --create <name> [from <template|vm> [options]]",
		"	        	Standard templates: freebsd, linux, windows",
		"	        	Or use an existing VM name as a template",
		"	        	Options: -s(grub), -U=cpus, -m=mem, -d=disk, -n=net, -i=bind_nic",
		"",
		"	--start		Start VM",
		"	--stop		Stop VM (ACPI shutdown)",
		"	--poweroff	Force power off VM",
		"	--restart	Restart VM",
		"	--reboot	Restart VM (alias for --restart)",
		"	--set-hd-boot	Set VM to boot from hard disk",
		"	--login		Log in to VM console (for grub boot)",
		"	--config	Configure VM settings (cpus, ram, disk, network, etc.)",
		"	--clone		Clone VM to a new one",
		"	--remove	Destroy VM(s) permanently",
		"	--rename	Rename VM",
		"	--vminfo	Display detailed VM configuration info",
		"	--ls		List VMs (short format)",
		"	--ll		List VMs (long format)",
		"	--showstats	Show VM resource usage statistics",
		"	--log		Show VM log entries",
		"",
		"	        	Usage: ${name} --log [vm_name] [-e] [-n=N] [-a]",
		"	        	-e: Show error logs only",
		"	        	-n=N: Show last N lines (default: 50)",
		"	        	-a: Show all logs (no line limit)",
		"",
		"	--os		List supported OS types",
		"",
		"VM Operation & Security:",
		"	--autoboot	Start all auto-boot enabled VMs",
		"	--abinfo	Show auto-boot configuration",
		"	--lock		Lock VM (prevent accidental deletion/modification)",
		"	--unlock	Unlock VM",
		"	--lockall	Lock all VMs",
		"	--unlockall	Unlock all VMs",
		"	--encrypt	Encrypt VM data",
		"	--decrypt	Decrypt VM data",
		"",
		"Storage & Snapshot Options:",
		"	--addisk	Add a new disk to VM",
		"	--deldisk	Delete a disk from VM",
		"	--snapshot	Create a snapshot of VM",
		"	--rollback	Rollback VM to a snapshot",
		"	--showsnap	Show snapshots of a VM",
		"	--showsnapall	Show snapshots of all VMs",
		"",
		"Network Management (NAT & Switch):",
		"	--netstats	Show VM network status",
		"	--natinfo	Show NAT configuration info",
		"	--addnat	Add a new NAT interface",
		"	--delnat	Delete a NAT interface",
		"	--setnat	Set NAT IP address",
		"	--reload-nat	Reload NAT port redirection rules",
		"	--swinfo	Show Switch configuration info",
		"	--addswitch	Add a new Switch",
		"	--delswitch	Delete a Switch",
		"	--setsw		Set Switch IP address",
		"	--unsetsw	Unset Switch IP address",
		"	--setpr		Set port redirection (dynamic)",
		"	--showpr	Show active port redirection rules",
		"	--showdhcp	Show DHCP client leases",
		"	--showdev	Show network device mapping",
		"	--showdevall	Show all network devices (class mode)",
		"	--showdevuse	Show all network devices (simple mode)",
		"",
		"Host & Hardware Options:",
		"	--passthru	Show PCI passthrough device list",
		"	--pci		Show all host PCI devices",
		"",
		"Example:",
		"	${name} --create vm1 from linux -U=4 -m=4g -d=20g",
		"	${name} --start vm1",
		"	${name} --ls",
		"	${name} --ll online",
		"	${name} --vminfo vm1",
		"",
		"For more details, please read 'man ${name}'",
		NULL};

	int n = 0;
	while (*(help+n)) {
		char str[BUFFERSIZE];
		strcpy(str, *(help+n++));
		str_replace(str, "${name}", program.name);
		printf("%s\n", str);
	}
}



int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage();
		return 0;
	}

	check_bre();
	set_vmdir();
	set_bvm_os();

	int opt;
	char *short_options = "hvl";

	//未使用的字母
	//q, x, y, z
	//J, M, Q, U, X, Y, Z
	struct option long_options[] = {
		{"help", 			0,	NULL, 	'h'},
		{"version", 		0, 	NULL, 	'v'},
		{"ls", 				0, 	NULL, 	'l'},
		{"ll", 				0, 	NULL, 	'('},
		{"netstats",		0,	NULL,	'j'},
		{"os", 				0, 	NULL, 	'o'},
		{"create", 			1, 	NULL, 	'C'},
		{"config", 			1, 	NULL, 	'e'},
		{"start", 			1, 	NULL, 	's'},
		{"autoboot", 		0, 	NULL, 	'B'},
		{"abinfo", 			0, 	NULL, 	'b'},
		{"login", 			1, 	NULL, 	'L'},
		{"stop", 			1, 	NULL, 	'S'},
		{"restart", 		1, 	NULL, 	'R'},
		{"reboot", 			1, 	NULL, 	'O'},
		{"poweroff", 		1, 	NULL, 	'p'},
		{"clone", 			1, 	NULL, 	'c'},
		{"rename", 			1, 	NULL, 	'r'},
		{"remove", 			1, 	NULL, 	'd'},
		{"addisk", 			1, 	NULL, 	'+'},
		{"deldisk", 		1, 	NULL, 	'-'},
		{"showstats", 		1, 	NULL, 	'k'},
		{"vminfo", 			1, 	NULL, 	'i'},
		{"vminfoall", 		1, 	NULL, 	'I'},
		{"natinfo", 		0, 	NULL, 	'n'},
		{"setnat", 			1, 	NULL, 	'N'},
		{"addnat", 			1, 	NULL, 	'A'},
		{"delnat", 			1, 	NULL, 	'D'},
		{"swinfo", 			0, 	NULL, 	'1'},
		{"setsw", 			1, 	NULL, 	'2'},
		{"addswitch", 		1, 	NULL, 	'3'},
		{"delswitch", 		1, 	NULL, 	'4'},
		{"unsetsw", 		1, 	NULL, 	'u'},
		{"reload-nat", 		0, 	NULL, 	'E'},
		{"lock", 			1, 	NULL, 	'5'},
		{"unlock", 			1, 	NULL, 	'6'},
		{"lockall", 		0, 	NULL, 	'7'},
		{"unlockall",		0, 	NULL, 	'8'},
		{"setpr", 			1, 	NULL, 	'a'},
		{"showpr", 			0, 	NULL, 	'f'},
		{"showdev",			0, 	NULL, 	'9'},
		{"showdevall",		0, 	NULL, 	'T'},
		{"showdevuse",		0, 	NULL, 	'm'},
		{"showdhcp",		0, 	NULL, 	'g'},
		{"showsnap",		1, 	NULL, 	'w'},
		{"showsnapall",		0, 	NULL, 	'V'},
		{"snapshot",		1, 	NULL, 	'W'},
		{"rollback",		1, 	NULL, 	'K'},
		{"set-hd-boot",		1, 	NULL, 	'H'},
		{"test", 			0, 	NULL, 	't'},
		{"destroy-bridge", 	0, 	NULL, 	0},
		{"destroy-tap", 	0, 	NULL, 	0},
		{"encrypt", 		1, 	NULL, 	0},
		{"decrypt", 		1, 	NULL, 	0},
		{"passthru",		0, 	NULL, 	'F'},
		{"pci",			0, 	NULL, 	'P'},
		{"log",			2, 	NULL, 	'G'},
		{NULL, 				0, 	NULL, 	0}
	};

	int option_index = 0;
	while ((opt=getopt_long(argc, argv, short_options, long_options, &option_index))!=-1) {
		// 不记录只读查询类命令的操作日志，避免污染日志文件
		if (strcmp(long_options[option_index].name, "log") != 0 &&
			strcmp(long_options[option_index].name, "ls") != 0 &&
			strcmp(long_options[option_index].name, "ll") != 0 &&
			strcmp(long_options[option_index].name, "help") != 0) {
			write_log("bvm --%s %s %s", long_options[option_index].name, optarg?optarg:"", argv[optind]?argv[optind]:"");
		}
		vm_init();
		switch (opt) {
		case 0:
			if (strcmp(long_options[option_index].name, "destroy-bridge") == 0) {
				destroy_all_bridge();
			}
			if (strcmp(long_options[option_index].name, "destroy-tap") == 0) {
				destroy_all_tap();
			}
			if (strcmp(long_options[option_index].name, "encrypt") == 0) {
				vm_crypt(optarg, 1);
			}
			if (strcmp(long_options[option_index].name, "decrypt") == 0) {
				vm_crypt(optarg, 0);
			}
			break;

		case 'C': //create
		{
			create_opts_stru opts = {0};
			char *template_name = NULL;
			int has_from = 0;

			// 检查是否有 "from" 关键字
			if (argv[optind] && strcmp(strtolower(argv[optind]), "from") == 0) {
				has_from = 1;
				if (argv[optind + 1]) {
					template_name = argv[optind + 1];
					optind += 2; // 跳过 "from" 和模板名称
				} else {
					error("Invalid parameters.\n");
					err_exit();
				}
			}

			// 如果使用模板创建，解析额外的配置参数
			if (has_from) {
				while (argv[optind] && argv[optind][0] == '-') {
					char *arg = argv[optind];
					
					// -s 启动类型为 grub
					if (strcmp(arg, "-s") == 0) {
						opts.use_grub = 1;
					}
					// -U=N CPU数量
					else if (strncmp(arg, "-U=", 3) == 0) {
						char *val = arg + 3;
						// 验证: 必须是正整数
						int cpu_num = atoi(val);
						if (cpu_num <= 0 || val[0] == '\0') {
							error("Invalid CPU count: %s (must be a positive integer)\n", arg);
							err_exit();
						}
						strcpy(opts.cpus, val);
					}
					// -m=SIZE 内存大小
					else if (strncmp(arg, "-m=", 3) == 0) {
						char *val = arg + 3;
						// 验证: 必须是数字+单位(m/g)
						int len = strlen(val);
						if (len < 2) {
							error("Invalid memory size: %s (e.g. 512m, 2g)\n", arg);
							err_exit();
						}
						char unit = tolower(val[len-1]);
						if (unit != 'm' && unit != 'g') {
							error("Invalid memory size: %s (unit must be m or g)\n", arg);
							err_exit();
						}
						// 验证数字部分
						for (int i = 0; i < len - 1; i++) {
							if (!isdigit(val[i])) {
								error("Invalid memory size: %s (must be number+unit)\n", arg);
								err_exit();
							}
						}
						strcpy(opts.ram, val);
					}
					// -d=SIZE 磁盘大小
					else if (strncmp(arg, "-d=", 3) == 0) {
						char *val = arg + 3;
						// 验证: 必须是数字+单位(m/g/t)
						int len = strlen(val);
						if (len < 2) {
							error("Invalid disk size: %s (e.g. 10g, 1t)\n", arg);
							err_exit();
						}
						char unit = tolower(val[len-1]);
						if (unit != 'm' && unit != 'g' && unit != 't') {
							error("Invalid disk size: %s (unit must be m, g or t)\n", arg);
							err_exit();
						}
						// 验证数字部分
						for (int i = 0; i < len - 1; i++) {
							if (!isdigit(val[i])) {
								error("Invalid disk size: %s (must be number+unit)\n", arg);
								err_exit();
							}
						}
						strcpy(opts.disk_size, val);
					}
					// -n=MODE 网络模式
					else if (strncmp(arg, "-n=", 3) == 0) {
						char *val = arg + 3;
						// 验证: 必须是 bridge 或 nat
						if (strcasecmp(val, "bridge") == 0) {
							strcpy(opts.netmode, "Bridged");
						} else if (strcasecmp(val, "nat") == 0) {
							strcpy(opts.netmode, "NAT");
						} else {
							error("Invalid network mode: %s (must be bridge or nat)\n", arg);
							err_exit();
						}
					}
					// -i=NIC 绑定网卡
					else if (strncmp(arg, "-i=", 3) == 0) {
						char *val = arg + 3;
						// 验证: 非空
						if (strlen(val) == 0) {
							error("Invalid bind NIC: %s (cannot be empty)\n", arg);
							err_exit();
						}
						strcpy(opts.bind_nic, val);
					}
					else {
						error("Unknown option: %s\n", arg);
						err_exit();
					}
					optind++;
				}
			}

			vm_create(optarg, template_name, has_from ? &opts : NULL);
		}
			break;

		case 'e': //config
			vm_config(optarg);
			break;

		case 's': //start
			vm_start(optarg);
			break;

		case 'B': //autoboot
			vm_autoboot();
			break;

		case 'b': //abinfo
			vm_autoboot_list();
			break;

		case 'L': //login
			vm_login(optarg);
			break;

		case 'S': //stop
			vm_stop(optarg);
			break;
		
		case 'R': //restart
		case 'O': //reboot
			vm_restart(optarg);
		
			//延迟1秒为防止tap被过早清理掉	
		    //执行 bvm --restart 后由于时间差误删除tap
			//当时在测试 dhcp 时发现非 freebsd 虚拟机，比如 openbsd 
			//在使用 bvm --restart 后 tap 丢失
			//最后才发现是清理 tap 模块的执行速度太快了
			//在虚拟机被复位后还没开始启动这个间隙里，清理 tap 就开始了
			//所以需要延迟一下，把这个间隙错开
			sleep(1);	
			break;
		
		case 'p': //poweroff
			vm_poweroff(optarg, 1);
			vm_killsession(optarg);
			break;
		
		case 'c': //clone
			vm_clone(optarg, argv[optind]);
			break;
		
		case 'd': //remove
        {
            char *vm_list[256];
            int vm_count = 0;
            vm_list[vm_count++] = optarg;
            
			while (optind < argc && argv[optind] && argv[optind][0] != '-') {
                if (vm_count < 256) {
				    vm_list[vm_count++] = argv[optind];
                }
				optind++;
			}
            
            fprintf(stderr, "\033[33mEnter 'YES' To remove the vm [");
            for(int i=0; i<vm_count; i++) {
                fprintf(stderr, "%s%s", vm_list[i], (i<vm_count-1)?", ":"");
            }
            fprintf(stderr, "]: \033[0m");

            char str[BUFFERSIZE];
            if (fgets(str, BUFFERSIZE, stdin)) {
                str[strcspn(str, "\n")] = 0;
                if (strcmp(str, "YES") == 0) {
                    printf("\033[1A\033[K");
                    for(int i=0; i<vm_count; i++) {
                        // 如果只有一个虚拟机，删除失败时显示列表，否则不显示
                        int show_list = (vm_count == 1) ? 1 : 0;
                        vm_remove(vm_list[i], 1, show_list);
                    }
                } else {
                    printf("\033[1A\033[K");
                    warn("cancelled\n");
                }
            }
        }
			break;
		
		case '+': //addisk
			vm_add_disk(optarg);
			break;
		
		case '-': //deldisk
			vm_del_disk(optarg);
			break;
		
		case 'r': //rename
			vm_rename(optarg, argv[optind]);
			break;
		
		case 'o': //os
			vm_os_list();
			break;
		
		case 'k': //showstats
			vm_show_stats(optarg);
			break;
		
		case 'i': //vminfo
			vm_info(optarg);
			break;
		
		case 'I': //vminfoall
			vm_info_all(optarg);
			break;
		
		case 'n': //natinfo
			nat_info();
			break;
		
		case 'N': //setnat
			set_nat(optarg, argv[optind]);
			break;
		
		case 'A': //addnat
			add_nat(optarg);
			break;
		
		case 'D': //delnat
			del_nat(optarg);
			break;
		
		case '1': //switchinfo
			switch_info();
			break;
		
		case '2': //setswitch
			set_switch(optarg, argv[optind]);
			break;
		
		case '3': //addswitch
			add_switch(optarg);
			break;
		
		case '4': //delswitch
			del_switch(optarg);
			break;
		
		case 'u': //unset
			unset_switch(optarg);
			break;
		
		case '5': //lock
			vm_lock(optarg, 1);
			break;
		
		case '6': //unlock
			vm_lock(optarg, 0);
			break;
		
		case '7': //lockall
			vm_lock_all(1);
			break;
		
		case '8': //unlockall
			vm_lock_all(0);
			break;
		
		case 'a': //setpr
			set_portlist(optarg);
			break;
		
		case 'f': //showpr
			vm_show_ports(SP_SHOW, NULL);
			break;
		
		case '9': //showdev
			vm_show_device(NULL, SD_CLASSICAL);
			break;
		
		case 'T': //showdevall(classical)
			vm_show_device_all(SD_CLASSICAL);
			break;
		
		case 'm': //showdevuse(simple)
			vm_show_device_all(SD_SIMPLE);
			break;
		
		case 'g': //showdhcp
			show_dhcp_pool();
			break;
		
		case 'F': //passthru
			show_passthru_devices();
			break;
		
	case 'P': //pci
			show_pci_devices();
			break;
		
		case 'G': //log
		{
			char *vm_name = optarg;
			
			// 如果 vm_name 为空，且下一个参数不是以 - 开头，则将其视为 vm_name
			if (vm_name == NULL && optind < argc && argv[optind] && argv[optind][0] != '-') {
				vm_name = argv[optind];
				optind++;
			}

			int error_only = 0;
			int lines = 50;  // 默认显示最后50行
			
			// 解析额外参数
			while (optind < argc && argv[optind] && argv[optind][0] == '-') {
				char *arg = argv[optind];
				
				// -e 只显示错误日志
				if (strcmp(arg, "-e") == 0) {
					error_only = 1;
				}
				// -n=N 显示行数
				else if (strncmp(arg, "-n=", 3) == 0) {
					char *val = arg + 3;
					int n = atoi(val);
					if (n <= 0) {
						error("Invalid line count: %s (must be a positive integer)\n", arg);
						err_exit();
					}
					lines = n;
				}
				// -a 显示所有日志（不限制行数）
				else if (strcmp(arg, "-a") == 0) {
					lines = 0;
				}
				else {
					error("Unknown option: %s\n", arg);
					err_exit();
				}
				optind++;
			}
			
			vm_show_log(vm_name, error_only, lines);
		}
			break;
		
		case 'w': //showsnap
			show_snapshot_list(optarg);
			break;
		
		case 'V': //showsnapall
			show_snapshot_list_all();
			break;
		
		case 'W': //snapshot
			vm_snapshot(optarg);
			break;
		
		case 'K': //rollback
			vm_rollback(optarg);
			break;
		
		case 'H': //set-hd-boot
			vm_boot_from_hd(optarg);
			break;
		
		case 'h': //help
			usage();
			break;
		
		case 'v': //version
			version();
			break;
		
		case 'l': //ls
			if (argv[optind])
				if (strcmp(argv[optind], "online") == 0)
					vm_list(VM_SHORT_LIST, "byname", 1);
				else
					vm_list(VM_SHORT_LIST, argv[optind], 0);
			else
				vm_list(VM_SHORT_LIST, "byname", 0);
			break;
		
		case '(': //ll
			if (argv[optind]) 
				if (strcmp(argv[optind], "online") == 0)
					vm_list(VM_LONG_LIST, "byname", 1);
				else
					vm_list(VM_LONG_LIST, argv[optind], 0);
			else 
				vm_list(VM_LONG_LIST, "byname", 0);
			break;
		
		case 'E': //reload-nat
			break;
		
		case 'j': //netstat
			print_vm_net_stat();
			break;
		
		case 't': //test
			break;
		
		default:
			//usage();
			break;
		}
		vm_end();
	}

	//清理无用的bridge、tap
	vm_init();
	vm_clean(); 
	redirect_port();
	vm_end();

	return 0;
}
