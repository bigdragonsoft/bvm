#ifndef BVM_BOOTER_H
#define BVM_BOOTER_H

#include "main.h"

#define EM0_VER 	11.1

float host_version();
void grub_booter(vm_node *p);
void uefi_booter(vm_node *p);
void convert(char *code, vm_node *p);

#endif //BVM_BOOTER_H
