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

#ifndef BVM_VM_H
#define BVM_VM_H

#include <stdio.h>
#include <stdint.h>
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
#include <sys/types.h>
#include <sys/sysctl.h>
#include <spawn.h>


#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <pthread.h>

#define TABSTOP		8
#define BUFFERSIZE 	512
#define FN_MAX_LEN 	512
#define CMD_MAX_LEN 	256
#define PORT_LIST_LEN	256
#define PROTO_LEN	4		//协议字符最大长度 tcp/udp
#define OS_NUM		32		//最大操作系统类型数量
#define DISK_NUM	8		//最大磁盘数量
#define NIC_NUM		8		//最大网卡数量
#define PORT_NUM	16		//最大端口转发数量
#define MAX_BOOT_NUM	32		//最大自动启动数量
#define NAT_ORDER	1029		//防火墙规则中nat的序列号
#define CRYPT_BUFFER	1048576		//加密数据缓冲区大小为1M字节
#define CRYPT_LEN	100		//加密数据总长度为100M字节
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))

// 加密相关常量
#define MAGIC_MARK "AESMARK!"
#define HEADER_SIZE (8 + 16) // 8字节标记 + 16字节IV

//#define BVM_DEBUG

extern char *osdir;
extern char vmdir[];
extern char *dhcp_pool_file;

enum DEBUG_COLOR_ENUM {
	NOCOLOR = 0,
	RED,
	GREEN,
	YELLOW,
	RED_FLASH,
	GREEN_FLASH,
	YELLOW_FLASH,
};
		
enum VM_LIST_ENUM {
	VM_SHORT_LIST = 0,
	VM_LONG_LIST  = 1,
};

enum VM_LIST_SORT_ENUM {
	LS_BY_NAME = 0,
	LS_BY_IP,
	LS_BY_OS,
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

enum SCAN_PORT_ENUM {
	SP_SHOW = 0,
	SP_VALID,
};

struct _os_stru {
	char type[32];
	int  uefi_boot;
	int  grub_boot;
	int  grub_cmd;
};
typedef struct _os_stru os_stru;
extern os_stru bvm_os[];

struct _redirect_stru {
	char proto[PROTO_LEN];	//协议类型 protocol
	int vm_port;		//虚拟机端口 virtual machine port
	int host_port;		//宿主机端口 host machine port
};
typedef struct _redirect_stru redirect_stru;

struct _scan_redirect_port_stru {	//用于扫描端口
	char *vm_name;
	redirect_stru *port;
	int *ret;
};
typedef struct _scan_redirect_port_stru scan_redirect_port_stru;

struct _find_vm_stru {
	char *vm_name;
	int *nic_index;
};
typedef struct _find_vm_stru find_vm_stru;

struct _nic_stru {
	char name[32];			//网卡名称
	char netmode[32];		//网络模式
	char nat[32];			//NAT
	char rpstatus[32];		//是否端口转发
	int  rpnum;			//端口转发的数量
	redirect_stru ports[PORT_NUM];	//端口映射表
	char rplist[PORT_LIST_LEN];	//端口映射列表 (80:80,22:2224)
	char bridge[32];		//网桥
	char tap[32];			//tap
	char ip[32];			//ip
	char mac[32];			//mac
	char bind[32];			//绑定宿主的网卡名称
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
	char sockets[8];      	// CPU 插槽数，默认 1
	char cores[8];        	// 每插槽核心数，默认等于 cpus
	char threads[8];      	// 每核心线程数，默认 1

	char ostype[32];		//操作系统类型
	char version[32];		//操作系统版本
	char cdstatus[8];		//是否使用CD (on/off)
	char iso[256];			//iso
	char bootfrom[32];		//启动介质 (cd0/hd0)
	char hostbridge[32];		//hostbridge
	char uefi[32];			//是否uefi启动 (none/uefi/uefi_csm)
	char uefi_vars[256];		//UEFI变量文件路径 (用于持久化UEFI设置)
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
	char vncpassword[32];		//vnc 密码 (optional)
	char vncwait[8];		//vnc wait选项 (on/off)
	char vncbind[32];		//vnc 绑定地址 (default: 0.0.0.0)

	char audiostatus[8];		//是否开启音频 (on/off)

	char autoboot[8];		//是否随宿主机自动启动 (on/off)
	char bootindex[8];		//启动序号
	char bootdelay[8];		//启动延迟

	char status[16];		//虚拟机状态 (on/off)
	char lock[4];			//是否锁定 (0/1)
	char crypt[4];			//是否加密 (0/1)
	char booter[16];		//启动器 (bvmb)

	char tpmstatus[8];		//TPM状态 (on/off)
	char tpmversion[8];		//TPM版本 (2.0)
	char tpmpath[256];		//TPM socket路径

	char network_interface[16];	//网络接口驱动
	char storage_interface[16];	//存储接口驱动
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
void auto_fix_conf(char *conf_file, char *key, char *value);
void vm_init();
void vm_end();

void vm_create(char *vm_name, char *template_vm_name);
void vm_config(char *vm_name);
void vm_start(char *vm_name);
void vm_login(char *vm_name);
void vm_stop(char *vm_name);
void vm_restart(char *vm_name);
void vm_killsession(char *vm_name);
void vm_poweroff(char *vm_name, int flag_msg);
int  vm_clone(char *src_vm_name, char *dst_vm_name);
int  vm_rename(char *old_vm_name, char *new_vm_name);
int  vm_remove(char *vm_name, int skip_confirm, int show_list);
void vm_add_disk(char *vm_name);
void vm_del_disk(char *vm_name);
void vm_list(int list_type, char *index_key, int online_only);
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
void vm_crypt(char *vm_name, int flag);
void vm_clean();
void vm_show_ports(int show_type, scan_redirect_port_stru *check);
void vm_autoboot();
void vm_autoboot_list();
int  vm_booting(autoboot_stru *boot);
void vm_boot_from_hd(char *vm_name);

int  find_vm_by_ip(char *ip, find_vm_stru *result, vm_stru *self);
int  scan_port(int scan_type, vm_stru *vm, scan_redirect_port_stru *check);
void show_port(vm_stru *vm, int nic_index);
int  is_valid_port(vm_stru *vm, int nic_index, scan_redirect_port_stru *check);

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

void show_dhcp_pool();

void create_vm_list();
void destroy_vm_list();
void add_to_vm_list(char *vm_name);
void sort_vm_list(int type);
void load_vm_info(char *vm_name, vm_stru *vm);
void save_vm_info(char *vm_name, vm_stru *vm);
void show_vm_name(int status);
void select_vm(char *vm_name, int status);
void print_vm_list(int list_type, int online_only);
void print_vm_net_stat();
vm_node* find_vm_list(const char *vm_name);
int  del_from_vm_list(char *vm_name);
void get_vm_name(char *dir);
void update_vm_status(char *vm_name, int status);
int  get_vm_status(const char *vm_name);
int  get_vm_count();
int  vm_online_count();
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
int  get_mac_from_bridge(char *bridge, char *tap, char *mac);
void generate_mac(char *mac);
int  get_ip_from_dhcp_pool(char *mac, char *ip);
void get_display_ip(vm_stru *vm, char *ip_buf);
int  disk_offset(vm_stru *vm);
int  check_vm_disks(vm_stru *vm);
int  select_disk(vm_stru *vm);
int  bvm_get_pid(char *name);
int  get_vm_pid(vm_stru *vm);
int  get_bvmb_pid(vm_stru *vm);
int  exist_hw_vmm_vmx_initialized(vm_stru *vm);
int  get_vmx(vm_stru *vm);
void file_lock(char *file, int flag);
void crypt_write(char *file, unsigned char *s, int index, int size);
int  crypt_read(char *file, unsigned char *s, int index, int size);
void bvm_xor(unsigned char *s, char *passwd);
int  bvm_crypt_chunk(unsigned char *data, int len, unsigned char *key, unsigned char *iv, int encrypt);
void bvm_crypt(unsigned char *data, char *passwd);
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
int  debug(unsigned color, char *fmt, ...);
int  error(char *fmt, ...);
int  WARN(char *fmt, ...);
int  warn(char *fmt, ...);
int  success(char *fmt, ...);
int  red(char *fmt, ...);
int  green(char *fmt, ...);
int  title(char *fmt, ...);

unsigned long long get_cpu_frequency();
void format_cpu_time(unsigned long long ticks, char *buf, size_t bufsize, unsigned long long cpu_freq);	
void format_bytes(unsigned long long bytes, char *buf, size_t bufsize);
void vm_show_stats(const char *vm_name);
unsigned long long parse_size(const char *size_str);
void test();
#endif	//BVM_VM_H
