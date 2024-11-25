/*-----------------------------------------------------------------------------
   BVM Copyright (c) 2018-2024, Qiang Guo (bigdragonsoft@gmail.com)
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

int  is_zfs_supported_by_kldstat();
int  is_zfs_supported_by_config();
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
