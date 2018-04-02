#ifndef BVM_MAIN_H
#define BVM_MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "config.h"
#include "create.h"
#include "vnet.h"
#include "vm.h"
#include "zfs.h"

typedef struct {
	char name[8];
	char version[16];
	char author[32];
	char email[64];
	char website[256];
} pro_stru;

void usage();
void version();

#endif	//BVM_MAIN_H
