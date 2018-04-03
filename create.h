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
#include "vm.h"

#define MM_MAX	32	//Main Menu Max
#define DM_MAX	40	//Disk Menu Max
#define NM_MAX	40	//Network Menu Max

struct _create_stru {
	char desc[128];
	char *value;
	void (*func)();
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
void enter_vm_iso(int);
void enter_vm_bootfrom(int);
void enter_vm_uefi(int);
void enter_vm_vncstatus(int);
void enter_vm_vncport(int);
void enter_vm_vncwidth(int);
void enter_vm_vncheight(int);
void enter_vm_hostbridge(int);
void enter_vm_autoboot(int);
void enter_vm_bootindex(int);
void enter_vm_bootdelay(int);
void enter_vm_nics(int);
void enter_vm_netmode(char *msg, char *value);
void enter_vm_nat(char *netmode, char *value);
void enter_vm_bind(char *netmode, char *value);
void enter_vm_ip(char *value);
void enter_vm_device(char *value);

void enter_vm_disk_config(int);
void enter_vm_network_config(int);

void enter_vm_netmode_proc(int nic_idx);
void enter_vm_bind_proc(int nic_idx);
void enter_vm_nat_proc(int nic_idx);
void enter_vm_ip_proc(int nic_idx);
void enter_static_ipv4(char *value);

int  get_filelist(char *dir, char **opt, char **opt_desc);
int  check_numbers(char *value, char *unit);
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
