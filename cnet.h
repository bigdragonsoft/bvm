#ifndef BVM_CREATE_NETWORK_H
#define BVM_CREATE_NETWORK_H

#include "create.h"

enum {
	BVMNETWORK = 0,
	BVMNETWORKFUNC = 1,
};

void network_config_init();
void create_network_config();
void edit_network_config();
void show_network_config();
void add_nic(int);
void delete_nic(int);
void vm_del_nic();
int select_nic();
int check_network_enter_valid();
void set_network_edit(int type, int edit);

#endif	//BVM_CREATE_NETWORK_H
