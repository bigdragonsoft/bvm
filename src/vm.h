#ifndef BVM_VM_H
#define BVM_VM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <pwd.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <sys/wait.h>
#include <spawn.h>

#define TABSTOP		8
#define BUFFERSIZE 	512
#define FN_MAX_LEN 	512
#define CMD_MAX_LEN 	256
#define OS_NUM		32	//最大操作系统类型数量
#define DISK_NUM	8	//最大磁盘数量
#define NIC_NUM		8	//最大网卡数量
#define MAX_BOOT_NUM	32	//最大自动启动数量

extern char *osdir;
extern char vmdir[];

enum VM_LIST_ENUM {
	VM_SHORT_LIST = 0,
	VM_LONG_LIST  = 1,
};

enum VM_LIST_SORT_ENUM {
	LS_BY_NAME = 0,
	LS_BY_IP,
	LS_BY_GUEST,
	LS_BY_STATUS,
};

enum VM_ENUM {
	VM_OFF = 0,
	VM_ON,
	VM_ALL,
};

enum RETURN_ENUM {
	RET_FAILURE = -1,
	RET_SUCCESS = 0,
};

enum SHOW_DEVICE_ENUM {
	SD_CLASSICAL = 0,
	SD_SIMPLE,
};

struct _os_stru {
	char type[32];
	int  uefi_boot;
	int  grub_boot;
	int  grub_cmd;
};
typedef struct _os_stru os_stru;
extern os_stru bvm_os[];

struct _nic_stru {
	char name[32];		//网卡名称
	char netmode[32];	//网络模式
	char nat[32];		//NAT
	char bridge[32];	//网桥
	char tap[32];		//tap
	char ip[32];		//ip
	char bind[32];		//绑定宿主的网卡名称
};
typedef struct _nic_stru nic_stru;

struct _disk_stru {
	char name[32];		//磁盘名称
	char size[32];		//磁盘大小
	char path[256];		//磁盘路径
};
typedef struct _disk_stru disk_stru;

struct _vm_stru {
	char name[32];			//名称
	char profile[256];		//
	char zfs[8];			//是否使用zfs创建磁盘 (on/off)
	char zpool[32];			//zpool存储池
	char disks[8];			//磁盘数
	disk_stru vdisk[DISK_NUM];	//磁盘信息
	char ram[32];			//内存
	char cpus[8];			//cpu数量

	char ostype[32];		//操作系统类型
	char version[32];		//操作系统版本
	char cdstatus[8];		//是否使用CD (on/off)
	char iso[256];			//iso
	char bootfrom[32];		//启动介质 (cd0/hd0)
	char hostbridge[32];		//hostbridge
	char uefi[32];			//是否uefi启动 (none/uefi/uefi_csm)
	char disk[256];			//磁盘文件路径
	char devicemap[256];		//devicemap路径
	char grubcmd[512];		//grub启动命令
	char grubcd[512];		//grub-cd启动命令
	char grubhd[512];		//grub-hd启动命令

	char nics[8];			//网卡数量
	nic_stru nic[NIC_NUM];		//网卡信息

	char vncstatus[8];		//是否开启vnc (on/off)
	char vncport[8];		//vnc port
	char vncwidth[8];		//vnc 窗口宽度
	char vncheight[8];		//vnc 窗口高度

	char autoboot[8];		//是否随宿主机自动启动 (on/off)
	char bootindex[8];		//启动序号
	char bootdelay[8];		//启动延迟

	char status[16];		//虚拟机状态 (on/off)
	char lock[4];			//是否锁定 (0/1)
	char booter[16];		//启动器 (bvmb)
};
typedef struct _vm_stru vm_stru;

struct _vm_node {
	vm_stru vm;
	struct _vm_node *next;
};
typedef struct _vm_node vm_node;
extern vm_node *vms;
extern vm_node *boot[];

struct _copy_stru {
	char *src;
	char *dst;
	int  disks;
};
typedef struct _copy_stru copy_stru;

struct _autoboot_stru {
	char *vm_name;
	int  delay;
};
typedef struct _autoboot_stru autoboot_stru;
typedef void *(*fun)(void*);

char *bvm_strcpy(char *dst, const char *src);
int  write_log_time();
int  write_log(char *fmt, ...);
void set_vmdir();
void set_bvm_os();
void check_bre();
void vm_init();
void vm_end();

void vm_create(char *vm_name);
void vm_config(char *vm_name);
void vm_start(char *vm_name);
void vm_login(char *vm_name);
void vm_stop(char *vm_name);
void vm_restart(char *vm_name);
void vm_poweroff(char *vm_name, int flag_msg);
int  vm_clone(char *src_vm_name, char *dst_vm_name);
int  vm_rename(char *old_vm_name, char *new_vm_name);
int  vm_remove(char *vm_name);
void vm_add_disk(char *vm_name);
void vm_del_disk(char *vm_name);
void vm_list(int list_type, char *index_key);
void vm_show_device_all(int show_type);
void vm_show_nat(int show_type);
void vm_show_switch(int show_type);
void vm_show_device_name(char *device);
void vm_show_device(char *device, int show_type);
void vm_info(char *vm_name);
void vm_info_all(char *vm_name);
void vm_os_list();
void vm_lock_all(int flag);
void vm_lock(char *vm_name, int flag);
void vm_clean();
void vm_autoboot();
void vm_autoboot_list();
int  vm_booting(autoboot_stru *boot);
void vm_boot_from_hd(char *vm_name);

void create_vm_disk_all(vm_stru *vm);
void create_vm_disk(vm_stru *vm, int disk_ord);
void adjust_vm_disk_all(vm_stru *vm);
void adjust_vm_disk(vm_stru *vm, char *size, int disk_ord);
long imgsize_cmp(char *size1, char *size2);
long disk_size_to_kb(char *size);
double total_disk_size(vm_stru *vm);
void unit_convert(double n, int flag_int, char *save);
int  is_integer(double num);

int  write_vm_device_map(vm_stru *vm);
//int  copy_vm_disk(char *src_vm_name, char *dst_vm_name);
int  copy_vm_disk(copy_stru *name);

void create_vm_list();
void destroy_vm_list();
void add_to_vm_list(char *vm_name);
void sort_vm_list(int type);
void load_vm_info(char *vm_name, vm_stru *vm);
void save_vm_info(char *vm_name, vm_stru *vm);
void show_vm_name(int status);
void select_vm(char *vm_name, int status);
void print_vm_list(int show_ip);
vm_node* find_vm_list(char *vm_name);
int  del_from_vm_list(char *vm_name);
void get_vm_name(char *dir);
void update_vm_status(char *vm_name, int status);
int  get_vm_status(char *vm_name);
int  get_vm_count();
int  check_vm_files(char *vm_name);
void gen_uefi_boot_code(char **code, vm_node *p);
void gen_grub_boot_code(char **code, vm_node *p);
int  write_boot_code(char **code, vm_node *p);
int  gen_vm_start_code(char *vm_name);
int  create_networking(char *vm_name);
void set_grub_cmd(vm_node *p);
void str_replace(char *str, char *ostr, const char *nstr);
void get_bvm_os(os_stru *os);
int  support_uefi(char *os);
int  support_grub(char *os);
int  disk_offset(vm_stru *vm);
int  check_vm_disks(vm_stru *vm);
int  select_disk(vm_stru *vm);
int  get_vm_pid(vm_stru *vm);
int  get_vmx(vm_stru *vm);
void file_lock(char *file, int flag);
void clean_tap(char *tap_name);
void clean_bridge(char *bridge_name);
int  check_spell(char *vm_name);
int  check_shutdown(char *cmd);
int  is_nic(char *nic_name);
int  max_vm_name_len();
void gen_autoboot(int *count);
int  waitting_boot(char *vm_name);
void err_exit();
int  wait_exec(fun func, void *args);
void waitting();
void delay(int sec);
int  error(char *fmt, ...);
int  WARN(char *fmt, ...);
int  warn(char *fmt, ...);
int  success(char *fmt, ...);
int  red(char *fmt, ...);
int  green(char *fmt, ...);
int  title(char *fmt, ...);
#endif	//BVM_VM_H
