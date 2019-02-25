/*-----------------------------------------------------------------------------
   BVM Copyright (c) 2018-2019, Qiang Guo (guoqiang_cn@126.com)
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
	"1.2.3", 
	"Qiang Guo",
	"guoqiang_cn@126.com",
	"https://github.com/bigdragonsoft/bvm",
};

// 版本
void version()
{
	printf("%s %s\n", program.name, program.version);
	printf("author: %s\n", program.author);
	printf("email: %s\n", program.email);
	printf("%s\n", program.website);
	printf("Copyright (C) 2017~2019 ChinaFreeBSD.cn, BigDragonSoft.com\n");
}

// 程序用法
void usage()
{
	char *help[] = {
		"Usage:	${name} <options> [args...]",
		"Options:",
		"	--abinfo	Output autoboot vms info",
		"	--addisk	Add an new disk",
	//	"	--addnat	Add NAT",
	//	"	--addswitch	Add Switch",
		"	--autoboot	Auto booting vms",
		"	--clone		Vm cloning",
		"	--config	Configure for vm",
		"	--create	Create new vm",
		"	--deldisk	Delete a disk",
	//	"	--delnat	Delete NAT",
	//	"	--delswitch	Delete Switch",
	//	"	--swinfo	Output Switch info",
		"	--login		Login to vm",
		"	--ls		List vm and status",
		"	--ll		List vm and status in long format",
	//	"	--natinfo	Output NAT info",
		"	--os		Output os lists",
		"	--poweroff	Force poweroff",
		"	--lock		Lock vm",
		"	--lockall	Lock all vms",
		"	--reload-nat	Reload NAT redirect-port",
		"	--remove	Destroy vm",
		"	--rename	Rename vm",
		"	--restart	Restart vm",
		"	--rollback	Roll back to the snapshot point",
		"	--setnat	Setting NAT's IP-addr",
		"	--setport	Setting port redirect list and effective immediately",
		"	--setsw		Setting Switch's IP-addr",
		"	--showdev	Show device",
		"	--showdevall	Show all devices in class mode",
		"	--showdevuse	Show all devices in simple mode",
		"	--showsnap	Show snapshots list of the vm",
		"	--showsnapall	Show snapshots list of the all vm",
		"	--snapshot	Generating snapshots for vm",
		"	--start		Start vm",
		"	--stop		Stop vm",
		"	--unlock	Unlock vm",
		"	--unlockall	Unlock all vms",
		"	--unsetsw	Unset Switch's IP-addr",
		"	--vminfo	Output vm info",
		"	",
		"Example:",
		"	${name} --start vmname",
		"	${name} --clone oldname newname",
		"	${name} --ls",
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

	struct option long_options[] = {
		{"help", 		0,	NULL, 	'h'},
		{"version", 		0, 	NULL, 	'v'},
		{"ls", 			0, 	NULL, 	'l'},
		{"ll", 			0, 	NULL, 	'('},
		{"os", 			0, 	NULL, 	'o'},
		{"create", 		1, 	NULL, 	'C'},
		{"config", 		1, 	NULL, 	'e'},
		{"start", 		1, 	NULL, 	's'},
		{"autoboot", 		0, 	NULL, 	'B'},
		{"abinfo", 		0, 	NULL, 	'b'},
		{"login", 		1, 	NULL, 	'L'},
		{"stop", 		1, 	NULL, 	'S'},
		{"restart", 		1, 	NULL, 	'R'},
		{"poweroff", 		1, 	NULL, 	'p'},
		{"clone", 		1, 	NULL, 	'c'},
		{"rename", 		1, 	NULL, 	'r'},
		{"remove", 		1, 	NULL, 	'd'},
		{"addisk", 		1, 	NULL, 	'+'},
		{"deldisk", 		1, 	NULL, 	'-'},
		{"vminfo", 		1, 	NULL, 	'i'},
		{"vminfoall", 		1, 	NULL, 	'I'},
	//	{"natinfo", 		0, 	NULL, 	'n'},
		{"setnat", 		1, 	NULL, 	'N'},
		{"addnat", 		1, 	NULL, 	'A'},
	//	{"delnat", 		1, 	NULL, 	'D'},
	//	{"swinfo", 		0, 	NULL, 	'1'},
		{"setsw", 		1, 	NULL, 	'2'},
	//	{"addswitch", 		1, 	NULL, 	'3'},
	//	{"delswitch", 		1, 	NULL, 	'4'},
		{"unsetsw", 		1, 	NULL, 	'u'},
		{"reload-nat", 		0, 	NULL, 	'E'},
		{"lock", 		1, 	NULL, 	'5'},
		{"unlock", 		1, 	NULL, 	'6'},
		{"lockall", 		0, 	NULL, 	'7'},
		{"unlockall",		0, 	NULL, 	'8'},
		{"setport", 		1, 	NULL, 	'a'},
		{"showdev",		0, 	NULL, 	'9'},
		{"showdevall",		0, 	NULL, 	'T'},
		{"showdevuse",		0, 	NULL, 	'm'},
		{"showsnap",		1, 	NULL, 	'w'},
		{"showsnapall",		0, 	NULL, 	'V'},
		{"snapshot",		1, 	NULL, 	'W'},
		{"rollback",		1, 	NULL, 	'K'},
		{"hd-booting",		1, 	NULL, 	'H'},
		{"test", 		0, 	NULL, 	't'},
		{"destroy-bridge", 	0, 	NULL, 	0},
		{"destroy-tap", 	0, 	NULL, 	0},
		{NULL, 			0, 	NULL, 	0}
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
			break;
		case 'C': //create
			vm_create(optarg);
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
			vm_restart(optarg);
			break;
		case 'p': //poweroff
			vm_poweroff(optarg, 1);
			break;
		case 'c': //clone
			vm_clone(optarg, argv[optind]);
			break;
		case 'd': //remove
			vm_remove(optarg);
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
		case 'a': //setport
			set_portlist(optarg, argv[optind]);
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
		case 'H': //hd-booting
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
				vm_list(VM_SHORT_LIST, argv[optind]);
			else
				vm_list(VM_SHORT_LIST, "byname");
			break;
		case '(': //ll
			if (argv[optind])
				vm_list(VM_LONG_LIST, argv[optind]);
			else
				vm_list(VM_LONG_LIST, "byname");
			break;
		case 'E': //reload-nat
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
