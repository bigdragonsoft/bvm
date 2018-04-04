#ifndef BVM_CREATE_DISK_H
#define BVM_CREATE_DISK_H

#include "create.h"

enum {
	DISKETTE = 0,
	DISKFUNC = 1,
};

void disk_config_init();
void create_disk_config();
void edit_disk_config();
void show_disk_config();
void add_disk(int);
void delete_disk(int);
int check_disk_enter_valid();
void set_disk_edit(int type, int edit);

#endif	//BVM_CREATE_DISK_H
