#ifndef BVM_VNET_H
#define BVM_VNET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "vm.h"

#define VNET_LISTSIZE   	128	
#define VNET_BUFFERSIZE 	32
#define VNET_DEFAULT_BRIDGE	"default-bridge"
#define VNET_BRIDGED_DESC 	"bvm-Bridged"
#define VNET_NAT_DESC     	"bvm-Nat"
#define VNET_SWITCH_DESC  	"bvm-Switch"
#define VNET_TRUE 		1
#define VNET_FALSE 		0
#define NAT_CONF_FN		"nat.conf"
#define SWITCH_CONF_FN		"switch.conf"

enum VNET_SWITCH_ENUM {
	BRIDGE = 0,	//网桥
	TAP,		//虚拟网卡
	LO,		//回环
	NIC,		//物理网卡
	NAT,
	SWITCH,
	ALL,
};

enum BRIDGE_ENUM {
	CREATE_BRIDGE = 0,
	CREATE_TAP,
	DESTROY_BRIDGE,
	DESTROY_TAP,
	SET_NAT_IP,
	SET_SWITCH_IP,
	SET_NAT_DESC,
	SET_SWITCH_DESC,
	SET_TAP_DESC,
	SET_DESC,
	UNSET_DESC,
	UP_TAP,
	UP_BRIDGE,
	ADD_TAP,
	ADD_NIC,
	ADD_TAP_NIC,
	DEL_TAP,
	DEL_NIC,
	CUSTOM,
};

enum TAP_LIST_TYPE {
	TL_NO_NIC = 0,
	TL_NIC,
};

struct _nat_stru {
	char name[16];
	char desc[32];
	char ip[16];
};
typedef struct _nat_stru nat_stru;

/* ----暂时不用----
struct _vnet_stru {
	char name[16];
	int  index;
	int  switch;
};
typedef struct _vnet_stru vnet_stru;

struct _vnet_node {
	vnet_stru card;
	struct _vnet_node *next;
};
typedef struct _vnet_node vnet_node;
------------------*/

extern char *bridge_list[];
extern char *tap_list[];
extern nat_stru *nat_list[];
extern nat_stru *switch_list[];
extern char bridge[];
extern char tap[];
extern char nic[];
extern char nic_list[][VNET_BUFFERSIZE];
extern nat_stru nat;
extern nat_stru Switch;
extern int cur_nic_idx;
extern vm_stru *cur_vm;

int  create_nat(char *nat_name);
int  create_bridged(char *bind);
int  create_switch(char *switch_name);
void run_bridge_command(int action);
void get_nic_name(int index, char *nic);
void get_new_bridge(char *bridge);
void get_new_tap(char *tap);
void unset_device(char *device);
void add_nat(char *ip);
void del_nat(char *nat_name);
void set_nat(char *nat_name, char *ip);
void unset_nat(char *nat_name);
void nat_info();
void print_nat_list();
void add_switch(char *ip);
void del_switch(char *switch_name);
void set_switch(char *switch_name, char *ip);
void unset_switch(char *switch_name);
void switch_info();
void free_vnet_list(int type);

void destroy_all_bridge();
void destroy_all_tap();
void get_bridge_desc(char *bridge, char *desc);
int  check_nic_in_bridge(char *bridge, char *nic);
void find_desc_in_all_bridges(char *mode, char *bridge);
void find_nic_in_all_bridges(char *bridge);
void get_new_vnet_name(int type, char *name);
int  check_ip(char *ip);
int  get_new_nat();
int  get_new_switch();

void load_vnet_list(nat_stru **vnet_list, char *file);
void save_vnet_list(nat_stru **vnet_list, char *file);
void del_ng(char *ng_name, char *file);
void set_ng(char *ng_name, char *ip, char *file);
void unset_ng(char *ng_name, char *file);
void add_ng(char *ip, char *file);
int  get_new_ng(char *file);
void ng_info(char *file);
char *get_ng_info(char *ng_name, char *file);

void load_nat_list();
void save_nat_list();
void load_switch_list();
void save_switch_list();
void load_ng_list();
void save_ng_list();
int  get_nic_list();
void get_lo_name(char *name);
void get_wlan_name(char *name);
char *get_nat_info(char *nat_name);
char *get_switch_info(char *switch_name);
void get_members_in_bridge(char *bridge_name);
void get_vnet_list(int type);
void get_buffer(FILE *fp, int type);
void sort_vnet_list(int type);
int  get_vnet_name_ord(char *name);
int  tap_list_count(int flag_nic);
void print_vnet_list(int type);
void free_vnet_list_proc(char **p);
void free_nat_list_proc(nat_stru **p);
char lastch(char *s);
char *strtolower(char *s);
char *rightstr(char *dst, char *src, int n);
char *leftstr(char *dst, char *src, int n);
void ltrim(char *s);
void rtrim(char *s);
void trim(char *s);

#endif  //BVM_VNET_H
