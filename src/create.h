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

#ifndef BVM_CREATE_H
#define BVM_CREATE_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <termios.h>
#include "vm.h"

#define MM_MAX	48	//Main Menu Max
#define DM_MAX	40	//Disk Menu Max
#define NM_MAX	64	//Network Menu Max

#define BVM_ECHO   0	//Echo
#define BVM_NOECHO 1	//No Echo

struct _create_stru {
	char desc[128];
	char *value;
	void (*func)(int);
	int  arg;
	int  edit;
	int  submenu;
};
typedef struct _create_stru create_stru;

extern vm_stru new_vm;
extern create_stru tbl[];
extern char *options;

void create_init();
void set_const_config();
void enter_vm(char *vm_name);
void edit_vm(char *vm_name);

void show_all_enter();
void enter_vm_name(int);
void enter_vm_ostype(int);
void enter_vm_version(int);
void enter_vm_cpus(int);
void enter_vm_ram(int);
void enter_vm_zfs(int);
void enter_vm_zpool(int);
void enter_vm_disks(int);
void enter_vm_vdisk_size(int disk_ord);
void enter_vm_cdstatus(int);
void enter_vm_cds(int);
void enter_vm_cd_iso(int);
void enter_vm_bootfrom(int);
void enter_vm_boot_type(int);
void enter_vm_vncstatus(int);
void enter_vm_vncport(int);
void enter_vm_vncwidth(int);
void enter_vm_vncheight(int);
void enter_vm_vncpassword(int);
void enter_vm_vncwait(int);
void enter_vm_vncbind(int);
void enter_vm_audiostatus(int);
void enter_vm_hostbridge(int);
void enter_vm_autoboot(int);
void enter_vm_bootindex(int);
void enter_vm_bootdelay(int);
void enter_vm_tpmstatus(int);
void enter_vm_sharestatus(int);
void enter_vm_sharename(int);
void enter_vm_sharepath(int);
void enter_vm_sharero(int);
void enter_vm_pptstatus(int);
void enter_vm_ppts(int);
void enter_vm_ppt_device(int);
void enter_vm_ppt_rom(int);
void enter_vm_nics(int);
void enter_vm_netmode(char *msg, char *value);
void enter_vm_rpstatus(char *netmode, char *value);
void enter_vm_rplist(char *netmode, char *value);
void enter_vm_nat(char *netmode, char *value);
//void enter_vm_bind(char *netmode, char *value);
void enter_vm_bind(char *netmode, char *rpstatus, char *value);
void enter_vm_ip(char *value);
void enter_vm_device(char *value);
void enter_vm_network_interface(int);
void enter_vm_storage_interface(int);

void enter_vm_disk_config(int);
void enter_vm_network_config(int);
//void enter_vm_driver_config(int);

void exit_the_menu(int);

void enter_vm_netmode_proc(int nic_idx);
void enter_vm_rpstatus_proc(int nic_idx);
void enter_vm_rplist_proc(int nic_idx);
void enter_vm_bind_proc(int nic_idx);
void enter_vm_nat_proc(int nic_idx);
void enter_vm_ip_proc(int nic_idx);
void enter_static_ipv4(char *value);

int  check_portlist(char *portlist, int nic_idx);
int  split_portlist(int *port, char *portlist, char sep);
int  get_proto(char *proto, char *portlist);
int  set_portlist(char *ip);

int  get_filelist(char *dir, char **opt, char **opt_desc);
int  check_numbers(char *value, char *unit);
int  bvm_gets(char *s, int len, char echo);
void enter_numbers(char *msg, char *unit, char *value);
int  check_version(char *value);
void enter_version(char *msg, char *value);
int  check_options(int min, int max, char *value);
void enter_options(char *msg, char **opt, char **opt_desc, char *value);
void add_item(create_stru *table, char *desc, char *value, void (*func)(), int arg, int edit, int submenu);
int  check_enter_valid();
int  strtoint(char *str);
int  is_edit_item(create_stru *tbl, create_stru *select[], int item);
int  is_non_show_item(int item);

void welcome();
void goback_mainmenu(int);

#endif	//BVM_CREATE_H
