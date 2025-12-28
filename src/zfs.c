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


#include "zfs.h"
#include "config.h"
#include "vm.h"
#include "create.h"
#include "vnet.h"

char zpool_list[ZPOOL_LISTSIZE][ZPOOL_BUFFERSIZE] = {0};
char snapshot_list[SNAPSHOT_LISTSIZE][SNAPSHOT_BUFFERSIZE] = {0};

// 是否支持zfs
int  support_zfs()
{
	return is_zfs_supported_by_kldstat();
}

// 检测宿主机是否支持zfs(通过配置文件)
// 1：支持
// 0：不支持
int is_zfs_supported_by_config()
{
	int f1 = 0;
	int f2 = 0;

	char *value;

	//zfs_enable="YES"
	init_config("/etc/rc.conf");
	if ((value = get_value_by_name("zfs_enable")) != NULL) {
		if (strcmp(strtolower(value), "yes") == 0) f1 = 1;
	}
	free_config();

	//zfs_load="YES"
	init_config("/boot/loader.conf");
	if ((value = get_value_by_name("zfs_load")) != NULL) {
		if (strcmp(strtolower(value), "yes") == 0) f2 = 1;
	}
	free_config();

	if (f1 && f2) return 1;
	else return 0;
}

// 检测宿主机是否支持zfs
// 1：支持
// 0：不支持
// -1：错误
int is_zfs_supported_by_kldstat() 
{
    FILE *fp;
    char line[BUFFERSIZE];
    int supported = 0;

    // 执行 kldstat 命令并读取输出
    fp = popen("kldstat", "r");
    if (fp == NULL) {
        error("Failed to execute the kldstat command\n");
        return -1;
    }

    // 检查输出中是否包含 zfs.ko 模块
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "zfs.ko") != NULL) {
            supported = 1;
            break;
        }
    }

    pclose(fp);
    return supported;
}

// 获取所有zpool存储池列表
int get_zpool_list()
{
	FILE *fp;
	fp = popen("df -Th | awk '{if ($2 == \"zfs\") print $1}'", "r");
	if (fp == NULL) {
		error("can't get zpool name\n");
		err_exit();
	}

	int n = 0;
	char buf[ZPOOL_BUFFERSIZE];
	while (fgets(buf, ZPOOL_BUFFERSIZE, fp)) {
		buf[strlen(buf)-1] = '\0';
		strcpy(zpool_list[n++], buf);
	}

	pclose(fp);
	return n;
}

// 是否存在卷
int exist_zvol(char *zvol)
{
	FILE *fp;
	fp = popen("zfs list | awk '{print $1}'", "r");
	if (fp == NULL) {
		error("can't get %s\n", zvol);
		err_exit();
	}

	int n = 0;
	char buf[ZPOOL_BUFFERSIZE];
	while (fgets(buf, ZPOOL_BUFFERSIZE, fp)) {
		buf[strlen(buf)-1] = '\0';
		if (strcmp(buf, zvol) == 0) {
			pclose(fp);
			return 1;
		}
	}
	pclose(fp);
	return 0;
}

// 卷是否存在子快照
int exist_snapshot(char *zvol)
{
	char cmd[BUFFERSIZE];
	sprintf(cmd, "zfs list -t snapshot | grep %s | awk '{print $1}'", zvol);

	FILE *fp;
	fp = popen(cmd, "r");
	if (fp == NULL) {
		error("can't get snapshot of %s", zvol);
		err_exit();
	}

	int n = 0;
	char buf[SNAPSHOT_BUFFERSIZE];
	while (fgets(buf, SNAPSHOT_BUFFERSIZE, fp)) {
		buf[strlen(buf)-1] = '\0';
		strcpy(snapshot_list[n++], buf);
	}

	pclose(fp);
	return n;
}

// 卷是否存在父快照
int exist_parent_snapshot(char *zvol, char *ssname)
{
	char cmd[BUFFERSIZE];
	sprintf(cmd, "zfs list -Ho origin %s 2> /dev/null", zvol);

	FILE *fp;
	fp = popen(cmd, "r");
	if (fp == NULL) {
		error("can't get parent snapshot of %s", zvol);
		err_exit();
	}

	int n = 0;
	char buf[SNAPSHOT_BUFFERSIZE];
	if (fgets(buf, SNAPSHOT_BUFFERSIZE, fp)) {
		buf[strlen(buf)-1] = '\0';
		strcpy(ssname, buf);
	}

	pclose(fp);
	if (strstr(ssname, "@")) return 1;
	else return 0;
}

// 快照是否存在克隆vm
int exist_clone_vm(char *ssname)
{
	vm_node *p = vms;
	while (p) {

		char zvol[BUFFERSIZE];
		sprintf(zvol, "%s/bvm_%s_disk", p->vm.zpool, p->vm.name);
		
		char parent[BUFFERSIZE];
		if (exist_parent_snapshot(zvol, parent) && strcmp(ssname, parent) == 0) return 1;
		
		p = p->next;
	}
	
	return 0;
}

// 创建zfs虚拟机磁盘文件
void create_zfs_disk(vm_stru *vm, int disk_ord)
{
	char zvol[FN_MAX_LEN];
	char cmd[BUFFERSIZE];
	char disk[32];

	int n = disk_ord;
	if (n == 0)
		strcpy(disk, "disk");
	else
		sprintf(disk, "disk%d", n);
	sprintf(zvol, "%s/bvm_%s_%s", vm->zpool, vm->name, disk);

	if (!exist_zvol(zvol)) {
		sprintf(cmd, "zfs create -V %s %s", vm->vdisk[n].size, zvol);
		run_cmd(cmd);
		link_to_zvol(vm, disk_ord, zvol);
	}
}

// 调整 ZFS 卷大小
// vm:虚拟机
// size:调整后的磁盘空间大小
// disk_ord:盘号
void resize_zfs_disk(vm_stru *vm, char *size, int disk_ord)
{
	char zvol[FN_MAX_LEN];
	char cmd[BUFFERSIZE];
	char disk[32];

	int n = disk_ord;
	if (n == 0)
		strcpy(disk, "disk");
	else
		sprintf(disk, "disk%d", n);
	sprintf(zvol, "%s/bvm_%s_%s", vm->zpool, vm->name, disk);

	if (exist_zvol(zvol)) {
		// zfs set volsize=SIZE poolname/dataset
		sprintf(cmd, "zfs set volsize=%s %s", size, zvol);
		run_cmd(cmd);
	}
}

// 磁盘文件链接到卷
void link_to_zvol(vm_stru *vm, int disk_ord, char *zvol)
{
	char fn[FN_MAX_LEN];
	char dev[BUFFERSIZE];
	char disk[32];
	int n = disk_ord;

	if (n == 0)
		strcpy(disk, "/disk.img");
	else
		sprintf(disk, "/disk%d.img", n);
	sprintf(fn, "%s%s%s", vmdir, vm->name, disk);
	
	if (access(fn, 0) == -1) {
		sprintf(dev, "/dev/zvol/%s", zvol);
		if (symlink(dev, fn) != 0) {
			error("create disk failure\n");
			err_exit();
		}
	}
}

// 删除卷
void remove_zvol(vm_stru *vm, int disk_ord)
{
	char zvol[ZPOOL_BUFFERSIZE];

	if (disk_ord == 0)
		sprintf(zvol, "%s/bvm_%s_disk", vm->zpool, vm->name);
	else
		sprintf(zvol, "%s/bvm_%s_disk%d", vm->zpool, vm->name, disk_ord);

	int fdel = 0;
	char cmd[BUFFERSIZE];

	//vm存在快照
	if (exist_snapshot(zvol)) {
		int n = 0;
		int ff = 0;
		while (strlen(snapshot_list[n]) > 0) {
			//存在快照的克隆
			if (exist_clone_vm(snapshot_list[n])) {
				fdel = 0;
				ff = 1;
				break;
			}
			n++;
		}
		//不存在快照的克隆
		if (ff != 1) {
			fdel = 1;
			int n = 0;
			while (strlen(snapshot_list[n]) > 0) {
				sprintf(cmd, "zfs destroy %s", snapshot_list[n]);
				run_cmd(cmd);
				++n;
			}
		}
	}
	//vm不存在快照
	else 
		fdel = 1;

	if (fdel) {
		sprintf(cmd, "zfs destroy %s", zvol);
		run_cmd(cmd);
	}
	else {
		error("can't remove \"%s\" with associated snapshots\n", vm->name);
		err_exit();
	}
}

// 卷更名
void rename_zvol(vm_stru *vm, char *oldname, char *newname)
{
	char zvol_old[ZPOOL_BUFFERSIZE];
	char zvol_new[ZPOOL_BUFFERSIZE];

	
	for (int n = 0; n < atoi(vm->disks); n++) {
		if (n == 0) {
			sprintf(zvol_old, "%s/bvm_%s_disk", vm->zpool, oldname);
			sprintf(zvol_new, "%s/bvm_%s_disk", vm->zpool, newname);
		}
		else {
			sprintf(zvol_old, "%s/bvm_%s_disk%d", vm->zpool, oldname, n);
			sprintf(zvol_new, "%s/bvm_%s_disk%d", vm->zpool, newname, n);
		}

		char cmd[BUFFERSIZE];
		sprintf(cmd, "zfs rename %s %s", zvol_old, zvol_new);
		run_cmd(cmd);

		if (n == 0)
			sprintf(cmd, "%s%s/disk.img", vmdir, newname);
		else
			sprintf(cmd, "%s%s/disk%d.img", vmdir, newname, n);

		if (remove(cmd) == -1) {
			error("%s can't remove\n", cmd);
			err_exit();
		}

		link_to_zvol(vm, n, zvol_new);
	}
}

// 克隆卷
int clone_zvol(vm_stru *vm, char *src_vm_name, char *dst_vm_name, int link)
{
	char zvol_src[ZPOOL_BUFFERSIZE];
	char zvol_dst[ZPOOL_BUFFERSIZE];

	
	for (int n = 0; n < atoi(vm->disks); n++) {
		if (n == 0) {
			sprintf(zvol_src, "%s/bvm_%s_disk", vm->zpool, src_vm_name);
			sprintf(zvol_dst, "%s/bvm_%s_disk", vm->zpool, dst_vm_name);
		}
		else {
			sprintf(zvol_src, "%s/bvm_%s_disk%d", vm->zpool, src_vm_name, n);
			sprintf(zvol_dst, "%s/bvm_%s_disk%d", vm->zpool, dst_vm_name, n);
		}

		char snapname[BUFFERSIZE];
		sprintf(snapname, "%ld", time(NULL));

		char cmd[BUFFERSIZE];
		sprintf(cmd, "zfs snapshot %s@%s", zvol_src, snapname);
		run_cmd(cmd);
		sprintf(cmd, "zfs clone %s@%s %s", zvol_src, snapname, zvol_dst);
		run_cmd(cmd);

		if (link) {
			link_to_zvol(vm, n, zvol_dst);
		}
	}

	return RET_SUCCESS;

}

// 显示快照列表
void show_snapshot_list(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
	}

	vm_stru *vm = &p->vm;
	if (!support_zfs() || strcmp(vm->zfs, "off") == 0) {
		warn("%s (non-zfs)\n", vm->name);
		return;
	}

	char zvol[BUFFERSIZE];
	sprintf(zvol, "%s/bvm_%s_disk@", vm->zpool, vm->name);

	int cnt = exist_snapshot(zvol);
	warn("%s (snapshots: %d)\n", vm->name, cnt);
	
	if (cnt) {
		int n = 0;
		while (strlen(snapshot_list[n]) > 0) {
			printf("|-%s\n", (char*)(strstr(snapshot_list[n], "@") + 1));
			//printf("|-%s\n", snapshot_list[n]);
			++n;
		}
	}
}

// 显示全部vm快照列表
void show_snapshot_list_all()
{
	vm_node *p = vms;
	while (p) {
		show_snapshot_list(p->vm.name);
		printf("\n");
		p = p->next;
	}
}

// vm快照处理
void vm_snapshot(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
	}

	if (!support_zfs() || strcmp(p->vm.zfs, "on") != 0) {
		error("%s is non zfs\n", vm_name);
		return;
	}

	if (get_vm_status(vm_name) == VM_ON) {
		error("can't snapshot, %s is running\n", vm_name);
		return;
	}

	char ssname[ZPOOL_BUFFERSIZE];
	enter_snapshot_name(&p->vm, (char*)ssname);

	for (int n=0; n<atoi(p->vm.disks); n++) {
		char zvol[ZPOOL_BUFFERSIZE];
		if (n == 0)
			sprintf(zvol, "%s/bvm_%s_disk", p->vm.zpool, p->vm.name);
		else
			sprintf(zvol, "%s/bvm_%s_disk%d", p->vm.zpool, p->vm.name, n);

		char cmd[BUFFERSIZE];
		sprintf(cmd, "zfs snapshot %s@%s", zvol, ssname);
		run_cmd(cmd);
	}


}

// vm回滚处理
void vm_rollback(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
	}

	if (!support_zfs() || strcmp(p->vm.zfs, "on") != 0) {
		error("%s is non zfs\n", vm_name);
		return;
	}

	if (get_vm_status(vm_name) == VM_ON) {
		error("can't rollback, %s is running\n", vm_name);
		return;
	}

	char ssname[ZPOOL_BUFFERSIZE];
	select_snapshot_name(&p->vm, ssname);

	for (int n=0; n<atoi(p->vm.disks); n++) {
		char zvol[ZPOOL_BUFFERSIZE];
		if (n == 0)
			sprintf(zvol, "%s/bvm_%s_disk", p->vm.zpool, p->vm.name);
		else
			sprintf(zvol, "%s/bvm_%s_disk%d", p->vm.zpool, p->vm.name, n);

		char cmd[BUFFERSIZE];
		sprintf(cmd, "zfs rollback %s@%s", zvol, ssname);
		run_cmd(cmd);
	}


}


// 检测快照名称的拼写
int check_ssname_spell(char *ssname)
{
	if (ssname == NULL) return 0;
	if (strlen(ssname) == 0) return 0;

	int n = 0;
	while (strlen(ssname) > n) {
		if (isalnum(ssname[n])) 
			++n;
		else 
			return 0;
	}
	return 1;
}

// 输入快照名称
void enter_snapshot_name(vm_stru *vm, char *ssname)
{
	char *msg = "Enter snapshot name: ";
	
	while (1) {
		printf("%s", msg);
		fgets(ssname, ZPOOL_BUFFERSIZE, stdin);
		ssname[strlen(ssname)-1] = '\0';
		if (check_ssname_spell(ssname) == 1) {
		//if (check_spell(ssname) == RET_SUCCESS) {
			char zvol[BUFFERSIZE];
			sprintf(zvol, "%s/bvm_%s_disk@", vm->zpool, vm->name);
			int cnt = exist_snapshot(zvol);
			int ff = 0;
			while (--cnt >= 0) {
				char *p = (char*)(strstr(snapshot_list[cnt], "@") + 1);
				if (strcmp(p, ssname) == 0) {
					ff = 1;
					break;
				}
			}

			if (ff)
				warn("%s already exist\n", ssname);
			else
				break;
		}
		else {
			warn("snapshot name invalid\n");
		}
	}
}

// 选择快照名称
void select_snapshot_name(vm_stru *vm, char *ssname)
{
	char *msg = "Enter snapshot name: ";
	char *opts[SNAPSHOT_LISTSIZE] = {0};
	char zvol[BUFFERSIZE];
	sprintf(zvol, "%s/bvm_%s_disk@", vm->zpool, vm->name);
	int cnt = exist_snapshot(zvol);

	if (cnt) {
		int n = 0;
		while (strlen(snapshot_list[n]) > 0) {
			opts[n] = (char*)malloc(BUFFERSIZE * sizeof(char));
			memset(opts[n], 0, BUFFERSIZE * sizeof(char));
			char *p = (char*)(strstr(snapshot_list[n], "@") + 1);
			strcpy(opts[n], p);
			++n;
		}
		enter_options(msg, opts, NULL, ssname);
	
		while (n >= 0) {
                	if (opts[n]) free(opts[n]);
                	--n;
       		}

	}
	else
		strcpy(ssname, "");
}


