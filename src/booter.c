/*-----------------------------------------------------------------------------
   BVM Copyright (c) 2018-2021, Qiang Guo (guoqiang_cn@126.com)
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

#include "booter.h"

int main(int argc, char **argv)
{
	char vm_name[32];
	if (argc > 1 )
		strcpy(vm_name, argv[1]);
	else {
		error("bvmb error\n");
		exit(1);
	}
	
	check_bre();
	set_vmdir();
	set_bvm_os();
	
	host_version();

	vm_init();
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) exit(0);

	if (strcmp(p->vm.uefi, "none") == 0) { 
		set_grub_cmd(p);
		grub_booter(p);
	}
	else {
		uefi_booter(p);
	}

	vm_end();

	return 0;
}

// 宿主机版本号
float host_version()
{
	float ver = 0;
	struct utsname name;
	if (uname(&name) == 0) { //success
		char *p1 = name.release;
		char *p2 = strstr(p1, "-");
		p1[p2-p1] = '\0';
		ver = atof(p1);
	}
	return ver;
}

// 执行代码
int run(char *cmd, vm_node *p)
{
	convert(cmd, p);
	//warn("%s\n", cmd);
	
	write_log(cmd);
	int ret = system(cmd);
	return WEXITSTATUS(ret);
}

// grub启动器
void grub_booter(vm_node *p)
{
	int ret;
	int boot;
	if (strcmp(p->vm.bootfrom, "cd0") == 0)
		boot = 0;
	else
		boot = 1;

	if (boot == 0 && strcmp(p->vm.cdstatus, "off") == 0) {
		error("can't start the vm from CD\n");
		exit(1);
	}

	char cmd[BUFFERSIZE];
	while (1) {

		//grub
		if (boot == 0)
			strcpy(cmd, "${vm_grubcd}");
		else
			strcpy(cmd, "${vm_grubhd}");

		run(cmd, p);

		//bhyve
		char t[BUFFERSIZE];
		strcpy(cmd, "bhyve -c ${vm_cpus} -m ${vm_ram} -HAPuw ");
		strcat(cmd, "-s 0:0,${vm_hostbridge} ");
		
		
		if (strcmp(p->vm.cdstatus, "on") == 0)
			strcat(cmd, "-s 2:0,ahci-cd,${vm_iso} ");

		int slot = 3;
		int id = 0;

		for (int n=0; n<atoi(p->vm.disks); n++) {
			if (strlen(p->vm.storage_interface) == 0)
				sprintf(t, "-s %d:%d,ahci-hd,${vm_disk%d} ", slot, id, n);
			else
				sprintf(t, "-s %d:%d,${vm_storage_interface},${vm_disk%d} ", slot, id, n);
			strcat(cmd, t);
			if (++id == 8) slot++;
		}
		
		
		for (int n=0; n<atoi(p->vm.nics); n++) {
			if (host_version() >= EM0_VER)
				if (strlen(p->vm.network_interface) == 0)
					sprintf(t, "-s 10:%d,e1000,${vm_tap%d} ", n, n);
				else
					sprintf(t, "-s 10:%d,${vm_network_interface},${vm_tap%d} ", n, n);
			else
				sprintf(t, "-s 10:%d,virtio-net,${vm_tap%d} ", n, n);
			strcat(cmd, t);
		}
		
		
		strcat(cmd, "-s 31,lpc -l com1,stdio ");
		strcat(cmd, "${vm_name}");

		ret = run(cmd, p);

		/*********** bhyve EXIT STATUS ***********
		  0	     rebooted
     		  1	     powered off
     		  2	     halted
     		  3	     triple fault
     		  4	     exited due	to an error
		*******************************************/
		if (ret > 0 && ret < 4) break;
		strcpy(cmd, "/usr/sbin/bhyvectl --destroy --vm=${vm_name}");
		run(cmd, p);
		boot = 1;
		vm_boot_from_hd(p->vm.name);
	}
	strcpy(cmd, "/usr/sbin/bhyvectl --destroy --vm=${vm_name}");
	run(cmd, p);
	for (int n=0; n<atoi(p->vm.nics); n++) {
		sprintf(cmd, "/sbin/ifconfig ${vm_tap%d} destroy", n);
		run(cmd, p);
	}
}

// uefi启动器
void uefi_booter(vm_node *p)
{
	int ret;
	int boot;
	if (strcmp(p->vm.bootfrom, "cd0") == 0)
		boot = 0;
	else
		boot = 1;

	if (boot == 0 && strcmp(p->vm.cdstatus, "off") == 0) {
		error("can't start the vm from CD\n");
		exit(1);
	}

	char cmd[BUFFERSIZE];
	while (1) {
		
		//bhyve
		char t[BUFFERSIZE];
		strcpy(cmd, "bhyve -c ${vm_cpus} -m ${vm_ram} -HAPuw ");

		strcat(cmd, "-s 0:0,${vm_hostbridge} ");
		
		
		if (strcmp(p->vm.cdstatus, "on") == 0) {
			strcat(cmd, "-s 2:0,ahci-cd,${vm_iso} ");
		}
		
		
		int slot = 3;
		int id = 0;
		for (int n=0; n<atoi(p->vm.disks); n++) {
			sprintf(t, "-s %d:%d,ahci-hd,${vm_disk%d} ", slot, id, n);
			strcat(cmd, t);
			if (++id == 8) slot++;
		}
		
		
		for (int n=0; n<atoi(p->vm.nics); n++) {
			//经测试 uefi 下 e1000 无效，只能使用 virtio-net
			//if (host_version() >= EM0_VER)
			//	sprintf(t, "-s 10:%d,e1000,${vm_tap%d} ", n, n);
			//else
				sprintf(t, "-s 10:%d,virtio-net,${vm_tap%d} ", n, n);
			strcat(cmd, t);
		}
		if (boot == 0) //cd
			strcat(cmd, "-s 29,fbuf,tcp=0.0.0.0:${vm_vncport},w=${vm_vncwidth},h=${vm_vncheight},wait ");
		else //hd
			if (strcmp(p->vm.vncstatus, "on") == 0)
					strcat(cmd, "-s 29,fbuf,tcp=0.0.0.0:${vm_vncport},w=${vm_vncwidth},h=${vm_vncheight} ");
		strcat(cmd, "-s 30,xhci,tablet ");
		strcat(cmd, "-s 31,lpc -l com1,stdio ");
		strcat(cmd, "-l bootrom,/usr/local/share/uefi-firmware/${vm_bhyve_uefi_fd} ");
		strcat(cmd, "${vm_name}");

		ret = run(cmd, p);

		/*********** bhyve EXIT STATUS ***********
		  0	     rebooted
     		  1	     powered off
     		  2	     halted
     		  3	     triple fault
     		  4	     exited due	to an error
		*******************************************/
		if (ret > 0 && ret < 4) break;
		strcpy(cmd, "/usr/sbin/bhyvectl --destroy --vm=${vm_name}");
		run(cmd, p);
		boot = 1;
		vm_boot_from_hd(p->vm.name);
	}
	strcpy(cmd, "/usr/sbin/bhyvectl --destroy --vm=${vm_name}");
	run(cmd, p);
	for (int n=0; n<atoi(p->vm.nics); n++) {
		sprintf(cmd, "/sbin/ifconfig ${vm_tap%d} destroy", n);
		run(cmd, p);
	}

}

// 代码转换
void convert(char *code, vm_node *p)
{
	char *str = code;
	char vm_disk[256];

	if (strlen(p->vm.grubcmd) > 0)
		str_replace(str, "${vm_grubcmd}", p->vm.grubcmd);
	str_replace(str, "${vm_grubcd}", 	p->vm.grubcd);
	str_replace(str, "${vm_grubhd}", 	p->vm.grubhd);
	str_replace(str, "${vm_name}", 		p->vm.name);
	str_replace(str, "${vm_version}", 	p->vm.version);
	str_replace(str, "${vm_bootfrom}", 	p->vm.bootfrom);
	str_replace(str, "${vm_uefi}", 		p->vm.uefi);
	str_replace(str, "${vm_devicemap}", 	p->vm.devicemap);
	str_replace(str, "${vm_ram}", 		p->vm.ram);
	str_replace(str, "${vm_cpus}", 		p->vm.cpus);
	str_replace(str, "${vm_hostbridge}", 	p->vm.hostbridge);
	str_replace(str, "${vm_disk}",		p->vm.disk);
	str_replace(str, "${vm_disk0}",		p->vm.disk);
	str_replace(str, "${vm_iso}", 		p->vm.iso);
	str_replace(str, "${vm_vncport}", 	p->vm.vncport);
	str_replace(str, "${vm_vncwidth}", 	p->vm.vncwidth);
	str_replace(str, "${vm_vncheight}", 	p->vm.vncheight);
	str_replace(str, "${vm_network_interface}", 	p->vm.network_interface);
	str_replace(str, "${vm_storage_interface}", 	p->vm.storage_interface);
	if (strcmp(p->vm.uefi, "uefi") == 0)
		str_replace(str, "${vm_bhyve_uefi_fd}", "BHYVE_UEFI.fd");
	if (strcmp(p->vm.uefi, "uefi_csm")== 0)
		str_replace(str, "${vm_bhyve_uefi_fd}", "BHYVE_UEFI_CSM.fd"); 

        for (int n=0; n<atoi(p->vm.nics); n++) {
                char buf[32];
                sprintf(buf, "${vm_tap%d}", n);
                str_replace(str, buf, p->vm.nic[n].tap);
        }

        for (int n=0; n<atoi(p->vm.disks); n++) {
                char buf[32];
                sprintf(buf, "${vm_disk%d}", n);
   		str_replace(str, buf, p->vm.vdisk[n].path);
        }

}
