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

#include "cnet.h"

const int nic_menu_item_num = 6;				//每块网卡所需的菜单项数量
const int nic_enter_items = NIC_NUM * nic_menu_item_num + 2;	//输入菜单数量
const int nic_submenu_items = 3;				//子菜单数量
const int nic_delete_item_pos = nic_enter_items + 1;		//delete菜单的偏移量

create_stru networkmenu[NM_MAX] = {0};
create_stru *network_sel[NM_MAX] = {0};
//void (*network_sel[NM_MAX])() = {0};

// 网络菜单初始化
void network_config_init()
{
	static int flag = 1;
	if (flag) {
		flag = 0;
		add_item(networkmenu, "NIC numbers",	(char*)&new_vm.nics,		enter_vm_nics,		0, 1, 0);
		for (int n=0; n<NIC_NUM; n++) {
			char desc[BUFFERSIZE];
			sprintf(desc, "nic-%d mode", n);
			add_item(networkmenu, desc,     (char*)&new_vm.nic[n].netmode, 	enter_vm_netmode_proc,  n, 1, 0);
			sprintf(desc, "nic-%d bind", n);
			add_item(networkmenu, desc,     (char*)&new_vm.nic[n].bind, 	enter_vm_bind_proc,  	n, 1, 0);
			sprintf(desc, "nic-%d gateway", n);
			add_item(networkmenu, desc,     (char*)&new_vm.nic[n].nat, 	enter_vm_nat_proc,  	n, 1, 0);
			sprintf(desc, "nic-%d redirect", n);
			add_item(networkmenu, desc,     (char*)&new_vm.nic[n].rpstatus,	enter_vm_rpstatus_proc,	n, 1, 0);
			sprintf(desc, "nic-%d ports", n);
			add_item(networkmenu, desc,     (char*)&new_vm.nic[n].rplist, 	enter_vm_rplist_proc,  	n, 1, 0);
			sprintf(desc, "nic-%d ip", n);
			add_item(networkmenu, desc,     (char*)&new_vm.nic[n].ip, 	enter_vm_ip_proc,  	n, 1, 0);
		}

		add_item(networkmenu, 	"interface",	
				  	(char*)&new_vm.network_interface, 
				  	enter_vm_network_interface,    	
				  	0, 1, 0);

		add_item(networkmenu, "add a nic",	NULL,			add_nic,		0, 1, 1);
		add_item(networkmenu, "delete a nic", 	NULL,			delete_nic,		0, 1, 1);
		add_item(networkmenu, "go back",	NULL,			goback_mainmenu,	0, 1, 1);
	}
}

// 建立网络配置
void create_network_config()
{
	if (atoi(new_vm.nics) == 0) {
		int n = 0;
		while (networkmenu[n].func && networkmenu[n].submenu == 0) {
			networkmenu[n].func(networkmenu[n].arg);
			n++;
		}
	}

	edit_network_config();
}

// 编辑网络配置
void edit_network_config()
{
	vm_node *p;
	if ((p = find_vm_list(new_vm.name)) != NULL) {
		set_network_edit(BVMNETWORK, 1);
		set_network_edit(BVMNETWORKFUNC, 1);
		networkmenu[0].edit = 0;
	}
	else {
		set_network_edit(BVMNETWORK, 1);
		set_network_edit(BVMNETWORKFUNC, 1);
	}

	char *msg = "Enter an number: ";
	show_network_config();

	int min = 0, max = 0;
	char answer[8];
	while (1) {
		while (network_sel[max]) ++max;
		--max;

		printf("%s", msg);
		fgets(answer, sizeof(answer), stdin);
		answer[strlen(answer)-1] = '\0';

		//int n = strtoint(answer);
		int n = check_options(min, max, answer);
		if (n < min || n > max) {
			printf("\033[1A\033[K"); 
			continue;
		}

		if (network_sel[n]->func == goback_mainmenu) {
			if (check_network_enter_valid() == -1) { 
				//printf("\033[1A\033[K"); 
				continue; 
			}
			break;
		}
		if (!is_edit_item(networkmenu, network_sel, n)) { 
			printf("\033[1A\033[K"); 
			continue; 
		}
		if (network_sel[n]) network_sel[n]->func(network_sel[n]->arg);
		show_network_config();

	}
}

// 设置网络菜单项的编辑属性
void set_network_edit(int type, int edit)
{
	int n = nic_enter_items;

	if (type == BVMNETWORK)
		for (int i=0; i<n; i++)
			networkmenu[i].edit = edit;

	if (type == BVMNETWORKFUNC)
		for (int i=n; i<n+nic_submenu_items; i++)
			networkmenu[i].edit = edit;
}

// 检测网络输入有效性
int check_network_enter_valid()
{
	for (int i=0; i<atoi(new_vm.nics); i++) {
		if (strlen(new_vm.nic[i].netmode) == 0) {
			warn("Netmode is invalid\n");
			return -1;
		}
		if (strlen(new_vm.nic[i].ip) == 0) {
			warn("IP is invalid\n");
			return -1;
		}
		
		if (strlen(new_vm.nic[i].bind) == 0) {
			warn("Bind is invalid\n");
			return -1;
		}
		if (strcmp(new_vm.nic[i].netmode, "NAT") == 0) {
			if (strlen(new_vm.nic[i].nat) == 0) {
				warn("NAT is invalid\n");
				return -1;
			}
			if (strlen(new_vm.nic[i].rpstatus) == 0) {
				warn("Port forwarding status is invalid\n");
				return -1;
			}
			if (strcmp(new_vm.nic[i].rpstatus, "enable") == 0) {
				if (strlen(new_vm.nic[i].rplist) == 0) {
					warn("Port forwarding list is invalid\n");
					return -1;
				}
				//if (strlen(new_vm.nic[i].bind) == 0) return -1;
			}
		}
		//if (strcmp(new_vm.nic[i].netmode, "Bridged") == 0 && strlen(new_vm.nic[i].bind) == 0) return -1;
	}

	if (strlen(new_vm.network_interface) == 0) {
		warn("Interface is invalid\n");
		return -1;
	}

	return 1;
}

// 显示网络配置
void show_network_config()
{
	//网卡数为1的时候屏蔽掉删除网卡的菜单选项
	if (atoi(new_vm.nics) <= 1)
		networkmenu[nic_delete_item_pos].edit = -1;
	else
		networkmenu[nic_delete_item_pos].edit = 1;

	int n = 0;
	int index = 0;
	while (networkmenu[n].func) {
		if ((networkmenu[n].func == enter_vm_netmode_proc && atoi(new_vm.nics) < networkmenu[n].arg + 1) ||
		    (networkmenu[n].func == enter_vm_rpstatus_proc && strcmp(new_vm.nic[networkmenu[n].arg].netmode, "NAT") != 0) ||
		    (networkmenu[n].func == enter_vm_rplist_proc && 
		     	(strcmp(new_vm.nic[networkmenu[n].arg].netmode, "NAT") != 0 || 
			(strcmp(new_vm.nic[networkmenu[n].arg].rpstatus, "enable") != 0))) ||
		    (networkmenu[n].func == enter_vm_bind_proc && atoi(new_vm.nics) < networkmenu[n].arg + 1) ||
		    /*(networkmenu[n].func == enter_vm_bind_proc && 
		     	strcmp(new_vm.nic[networkmenu[n].arg].netmode, "Bridged") != 0 && strcmp(new_vm.nic[networkmenu[n].arg].rpstatus, "enable") != 0) ||*/
		    (networkmenu[n].func == enter_vm_nat_proc && strcmp(new_vm.nic[networkmenu[n].arg].netmode, "NAT") != 0) ||
		    (networkmenu[n].func == enter_vm_ip_proc && strlen(new_vm.nic[networkmenu[n].arg].netmode) == 0) //atoi(new_vm.nics) < networkmenu[n].arg + 1)
		   );
		else {
			if (networkmenu[n].edit != -1) {
				network_sel[index] = &networkmenu[n];
				
				//根据网络模式的不同，变更对于bind的不同描述
				if (networkmenu[n-1].value && strcmp(networkmenu[n-1].value, "NAT") == 0) {
					str_replace(networkmenu[n].desc, "bind", "wan");
				}
				if (networkmenu[n-1].value && strcmp(networkmenu[n-1].value, "Bridged") == 0) {
					str_replace(networkmenu[n].desc, "wan", "bind");
				}

				printf("[%c]. %-14s", options[index], networkmenu[n].desc);
				if (networkmenu[n].value)
					printf(": %s", networkmenu[n].value);
				printf("\n");
				++index;
			}
		}
		++n;
	}
}

// 增加网卡
void add_nic(int not_use)
{
	warn("... add nic ...\n");
	if (atoi(new_vm.nics) == NIC_NUM) {
		error("The number of network cards reached the limit\n");
		err_exit();
	}
	sprintf(new_vm.nics, "%d", atoi(new_vm.nics) + 1);
}

// 删除网卡
void delete_nic(int not_use)
{
	warn("... delete nic ...\n");
	vm_del_nic();
}

// 删除一块网卡
void vm_del_nic()
{
	//选择网卡
	int n = select_nic();

	//修改vm配置文件
	for (int i=n+1; i<atoi(new_vm.nics); i++) {
		new_vm.nic[i-1] = new_vm.nic[i];
	}

	int num = atoi(new_vm.nics) - 1;
	
	strcpy(new_vm.nic[num].netmode, "");
	strcpy(new_vm.nic[num].nat, "");
	strcpy(new_vm.nic[num].bind, "");
	sprintf(new_vm.nics, "%d", num);

}


// 选择网卡
int select_nic()
{
	char *msg = "Which network card: ";
	char *opts[NIC_NUM] = {"0", "1", "2", "3", "4", "5", "6", "7"};
	char *desc[NIC_NUM] = {0};
	
	int nic_num = atoi(new_vm.nics);
	opts[nic_num] = NULL;
	
	for(int n=0; n<nic_num; n++) {
		desc[n] = (char*)malloc(BUFFERSIZE * sizeof(char));
		memset(desc[n], 0, BUFFERSIZE * sizeof(char)); 
		sprintf(desc[n], "nic_%d - %s", n, new_vm.nic[n].netmode);
	}

	char nic[32];
	enter_options(msg, opts, desc, (char*)&nic);

	int n = 0;
	while (desc[n]) {
		free(desc[n]);
		++n;
	}

	return atoi(nic);
}


