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


#include "main.h"

pro_stru program = {
	"bvm", 
	"1.3.5", 
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
	printf("Copyright (C) 2017~2025 BigDragonSoft.com, ChinaFreeBSD.cn\n");
}

// 程序用法
void usage()
{
	char *help[] = {
		"Usage:	${name} <options> [args...]",
		"Options:",
		"	--abinfo	Display information about auto-boot VMs",
		"	--addisk	Add a new disk to VM",
		"	--addnat	Add NAT",
		"	--addswitch	Add Switch",
		"	--autoboot	Auto-boot VMs",
		"	--clone		Clone VM",
		"	--config	Configure VM",
		"	--create	Create new VM",
		"	--deldisk	Delete a disk",
		"	--delnat	Delete NAT",
		"	--delswitch	Delete Switch",
		"	--swinfo	Output Switch info",
		"	--decrypt	Decrypt VM",
		"	--encrypt	Encrypt VM",	
		"	--login		Log in to VM",
		"	--ls		List VMs and status",
		"	--ll		List VMs and status in long format",
		"	--netstats	Show VM network status",
		"	--natinfo	Output NAT info",
		"	--lock		Lock VM",
		"	--lockall	Lock all VMs",
		"	--os		Output OS list",
		"	--poweroff	Force power off",
		"	--reload-nat	Reload NAT redirect port",
		"	--remove	Destroy VM",
		"	--rename	Rename VM",
		"	--restart	Restart VM",
		"	--reboot	Restart VM (alias for --restart)",
		"	--rollback	Roll back to snapshot point",
		"	--set-hd-boot	Set VM to boot from hard disk",
		"	--setnat	Set NAT IP address",
		"	--setsw		Set Switch IP address",
		"	--setpr		Set port redirection list",
		"	--showpr	Show port redirection list",
		"	--showdev	Show device",
		"	--showdevall	Show all devices in class mode",
		"	--showdevuse	Show all devices in simple mode",
		"	--showdhcp	Show all DHCP clients",
		"	--showsnap	Show snapshot list of VM",
		"	--showsnapall	Show snapshot list of all VMs",
		"	--showstats	Show VM stats",
		"	--snapshot	Generate snapshot for VM",
		"	--start		Start VM",
		"	--stop		Stop VM",
		"	--unlock	Unlock VM",
		"	--unlockall	Unlock all VMs",
		"	--unsetsw	Unset Switch IP address",
		"	--vminfo	Output VM info",
		"	",
		"Example:",
		"	${name} --start vmname",
		"	${name} --clone oldname newname",
		"	${name} --ls",
		"	${name} --ll online",
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
	//F, G, J, M, P, Q, U, X, Y, Z
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
		{NULL, 				0, 	NULL, 	0}
	};

	int option_index = 0;
	while ((opt=getopt_long(argc, argv, short_options, long_options, &option_index))!=-1) {
		write_log("bvm --%s %s %s", long_options[option_index].name, optarg?optarg:"", argv[optind]?argv[optind]:"");
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
			if (argv[optind]) {
				if (strcmp(strtolower(argv[optind]), "from") == 0)
					if (argv[optind + 1]) {
						vm_create(optarg, argv[optind + 1]);
						break;
					}
				error("Invalid parameters.\n");
				err_exit();
			}
			else
				vm_create(optarg, NULL);
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
