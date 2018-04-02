#ifndef BVM_ZFS_H
#define BVM_ZFS_H

#include "vm.h"

#define ZPOOL_LISTSIZE		128
#define ZPOOL_BUFFERSIZE	128
#define SNAPSHOT_LISTSIZE	32
#define SNAPSHOT_BUFFERSIZE	128

enum SNAPSHOT_ENUM {
	SS_ALL = 0,
	SS_VM,
};

extern char zpool_list[][ZPOOL_BUFFERSIZE];
extern char snapshot_list[][SNAPSHOT_BUFFERSIZE];

int  support_zfs();
int  get_zpool_list();
int  exist_zvol(char *zvol);
int  exist_snapshot(char *zvol);
int  exist_parent_snapshot(char *zvol, char *ssname);
int  exist_clone_vm(char *ssname);
void create_zfs_disk(vm_stru *vm, int disk_ord);
void link_to_zvol(vm_stru *vm, int disk_ord, char *zvol);
void remove_zvol(vm_stru *vm, int disk_ord);
void rename_zvol(vm_stru *vm, char *oldname, char *newname);
int  clone_zvol(vm_stru *vm, char *src_vm_name, char *dst_vm_name, int link);
void show_snapshot_list(char *vm_name);
void show_snapshot_list_all();
void vm_snapshot(char *vm_name);
void vm_rollback(char *vm_name);
void enter_snapshot_name(vm_stru *vm, char *ssname);
void select_snapshot_name(vm_stru *vm, char *ssname);
int  check_ssname_spell(char *ssname);

#endif	//BVM_ZFS_H
