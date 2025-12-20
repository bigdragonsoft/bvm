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

	if (strcmp(p->vm.boot_type, "grub") == 0) { 
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

// 获取 bhyve 退出码描述
const char* get_bhyve_exit_desc(int status)
{
	switch (status) {
		case 0:   return "rebooted";
		case 1:   return "powered off";
		case 2:   return "halted";
		case 3:   return "triple fault (guest system crash)";
		case 4:   return "config or boot error (check device/UEFI settings)";
		case 70:  return "internal software error (EX_SOFTWARE)";
		case 71:  return "operating system error (EX_OSERR)";
		case 100: return "suspended";
		case 134: return "aborted (SIGABRT), possible hardware config issue";
		case 137: return "killed (SIGKILL), host out of memory";
		default:  return "unknown error, see /var/log/bvm.log for details";
	}
}

// 添加 CD 参数
// 只添加有效的 CD（ISO 路径不为空的）
static void append_cd_args(char *cmd, vm_node *p, int slot_start) {
	if (strcmp(p->vm.cdstatus, "on") == 0) {
		char t[BUFFERSIZE];
		int slot_id = 0;  // 实际使用的槽位号
		for (int n=0; n<atoi(p->vm.cds); n++) {
			// 跳过 ISO 路径为空的 CD
			if (strlen(p->vm.cd_iso[n]) == 0) {
				continue;
			}
			sprintf(t, "-s %d:%d,ahci-cd,${vm_cd_iso_%d} ", slot_start, slot_id, n);
			strcat(cmd, t);
			slot_id++;
		}
	}
}

// 添加 HD 参数
static void append_hd_args(char *cmd, vm_node *p, int slot_start) {
	char t[BUFFERSIZE];
	int slot = slot_start;
	int id = 0;
	for (int n=0; n<atoi(p->vm.disks); n++) {
		if (strlen(p->vm.storage_interface) == 0)
			sprintf(t, "-s %d:%d,ahci-hd,${vm_disk%d} ", slot, id, n);
		else
			sprintf(t, "-s %d:%d,${vm_storage_interface},${vm_disk%d} ", slot, id, n);
		strcat(cmd, t);
		if (++id == 8) slot++;
	}
}

// 计算有效的 CD（ISO 路径不为空）
static int count_valid_cds(vm_node *p) {
	int count = 0;
	for (int n=0; n<atoi(p->vm.cds); n++) {
		if (strlen(p->vm.cd_iso[n]) > 0) {
			count++;
		}
	}
	return count;
}

// GRUB 启动器
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

	// 检查从 CD 启动时是否有有效的 ISO 文件
	if (boot == 0 && count_valid_cds(p) == 0) {
		error("can't start the vm from CD: no valid ISO file configured\n");
		exit(1);
	}

	char cmd[BUFFERSIZE];
	while (1) {

		// GRUB 启动
		if (boot == 0)
			strcpy(cmd, "${vm_grubcd}");
		else
			strcpy(cmd, "${vm_grubhd}");

		run(cmd, p);

		// bhyve
		char t[BUFFERSIZE];
		// 当启用 PCI 直通时，必须锁定内存 (-S)
		if (strcmp(p->vm.ppt_status, "on") == 0)
			strcpy(cmd, "bhyve -c cpus=${vm_cpus},sockets=${vm_sockets},cores=${vm_cores},threads=${vm_threads} -m ${vm_ram} -HAPuwS ");
		else
			strcpy(cmd, "bhyve -c cpus=${vm_cpus},sockets=${vm_sockets},cores=${vm_cores},threads=${vm_threads} -m ${vm_ram} -HAPuw ");
		strcat(cmd, "-s 0:0,${vm_hostbridge} ");
		
		

		// 固定 slot 分配：HD 始终在 slot 2，CD 始终在 HD 之后
		// 这样无论从哪里启动，设备路径保持一致，UEFI vars 中的启动项不会失效
		int disk_count = atoi(p->vm.disks);
		int hd_slots_needed = (disk_count + 7) / 8;
		if (hd_slots_needed == 0) hd_slots_needed = 1;
		int hd_slot_start = 2;
		int cd_slot = 2 + hd_slots_needed;

		// 按固定顺序追加参数：先 HD 后 CD
		append_hd_args(cmd, p, hd_slot_start);
		append_cd_args(cmd, p, cd_slot);

		
		for (int n=0; n<atoi(p->vm.nics); n++) {
			if (host_version() >= EM0_VER)
				if (strlen(p->vm.network_interface) == 0)
					sprintf(t, "-s 10:%d,e1000,${vm_tap%d},mac=${vm_mac%d} ", n, n, n);
				else
					sprintf(t, "-s 10:%d,${vm_network_interface},${vm_tap%d},mac=${vm_mac%d} ", n, n, n);
			else
				sprintf(t, "-s 10:%d,virtio-net,${vm_tap%d},mac=${vm_mac%d} ", n, n, n);
			strcat(cmd, t);
		}
		
		// VirtIO-9P 文件共享（grub 模式）
		if (strcmp(p->vm.share_status, "on") == 0 && strlen(p->vm.share_path) > 0) {
			char share_cmd[512];
			if (strcmp(p->vm.share_ro, "on") == 0)
				sprintf(share_cmd, "-s 20,virtio-9p,%s=%s,ro ", 
					p->vm.share_name, p->vm.share_path);
			else
				sprintf(share_cmd, "-s 20,virtio-9p,%s=%s ", 
					p->vm.share_name, p->vm.share_path);
			strcat(cmd, share_cmd);
		}

		// PCI 直通设备
		if (strcmp(p->vm.ppt_status, "on") == 0) {
			int ppt_slot = 0;
			for (int n=0; n<atoi(p->vm.ppts); n++) {
				// 跳过空的 ppt 设备配置
				if (strlen(p->vm.ppt[n].device) == 0) continue;
				
				char ppt_cmd[256];
				if (strlen(p->vm.ppt[n].rom) > 0)
					sprintf(ppt_cmd, "-s 21:%d,passthru,%s,rom=%s ", 
						ppt_slot, p->vm.ppt[n].device, p->vm.ppt[n].rom);
				else
					sprintf(ppt_cmd, "-s 21:%d,passthru,%s ", 
						ppt_slot, p->vm.ppt[n].device);
				strcat(cmd, ppt_cmd);
				ppt_slot++;
			}
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
		write_log("bhyve exited with status: %d (%s)", ret, get_bhyve_exit_desc(ret));
	
		if (ret > 0 && ret <=4) break;

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

	// 检查从 CD 启动时是否有有效的 ISO 文件
	if (boot == 0 && count_valid_cds(p) == 0) {
		error("can't start the vm from CD: no valid ISO file configured\n");
		exit(1);
	}

	// 自动迁移逻辑：如果 VM 使用 UEFI 但没有 vars 文件
	if (strcmp(p->vm.boot_type, "grub") != 0 && strlen(p->vm.uefi_vars) == 0) {
		// 尝试创建 vars 文件
		char template_vars[] = "/usr/local/share/uefi-firmware/BHYVE_UEFI_VARS.fd";
		char vm_vars[256];
		sprintf(vm_vars, "%s%s/efivars.fd", vmdir, p->vm.name);
		
		// 如果模板存在且 vars 文件不存在，则创建
		if (access(template_vars, R_OK) == 0 && access(vm_vars, F_OK) != 0) {
			// 复制模板
			char copy_cmd[512];
			sprintf(copy_cmd, "cp %s %s", template_vars, vm_vars);
			if (system(copy_cmd) == 0) {
				strcpy(p->vm.uefi_vars, vm_vars);
				save_vm_info(p->vm.name, &p->vm);
				write_log("Auto-migrated %s to UEFI vars persistence mode", p->vm.name);
			}
		}
	}

	// 如果设置为从光盘启动(boot=0)，强制重置 UEFI 变量以确保光盘启动优先
	// 这是一个必要的变通方案，因为无法直接修改 nvram 二进制文件中的启动顺序
	if (boot == 0 && strcmp(p->vm.boot_type, "grub") != 0 && strlen(p->vm.uefi_vars) > 0) {
		char template_vars[] = "/usr/local/share/uefi-firmware/BHYVE_UEFI_VARS.fd";
		char backup_vars[512];
		sprintf(backup_vars, "%s.orig", p->vm.uefi_vars);
		
		if (access(template_vars, R_OK) == 0 && access(p->vm.uefi_vars, F_OK) == 0) {
			// 只有当 .orig 不存在时才创建备份
			// 如果 .orig 已存在，说明之前的有效备份还在，不要覆盖它
			if (access(backup_vars, F_OK) != 0) {
				char backup_cmd[512];
				sprintf(backup_cmd, "cp %s %s", p->vm.uefi_vars, backup_vars);
				system(backup_cmd);
				write_log("Backed up UEFI vars for VM %s before CD boot", p->vm.name);
			} else {
				write_log("UEFI vars backup already exists for VM %s, keeping it", p->vm.name);
			}

			// 重置 vars
			char reset_cmd[512];
			sprintf(reset_cmd, "cp %s %s", template_vars, p->vm.uefi_vars);
			system(reset_cmd);
			
			write_log("Reset UEFI vars for VM %s to ensure CD boot", p->vm.name);
		}
	}

	// 如果设置为从硬盘启动(boot=1)，恢复之前备份的 .orig 文件
	// .orig 保存的是切换到 CD 启动之前的 vars 文件（包含正确的 HD 启动项）
	// 因为 CD 启动时用空模板覆盖了 vars，所以现在需要恢复
	if (boot == 1 && strcmp(p->vm.boot_type, "grub") != 0 && strlen(p->vm.uefi_vars) > 0) {
		char backup_vars[512];
		sprintf(backup_vars, "%s.orig", p->vm.uefi_vars);

		if (access(backup_vars, F_OK) == 0) {
			// 恢复备份到 vars
			char restore_cmd[512];
			sprintf(restore_cmd, "mv %s %s", backup_vars, p->vm.uefi_vars);
			system(restore_cmd);
			
			write_log("Restored UEFI vars backup for VM %s (contains HD boot entries)", p->vm.name);
		}
	}

	// TPM 启动逻辑
	if (strcmp(p->vm.tpmstatus, "on") == 0) {
		char tpm_sock[256];
		if (strlen(p->vm.tpmpath) > 0)
			strcpy(tpm_sock, p->vm.tpmpath);
		else
			sprintf(tpm_sock, "/tmp/%s/swtpm.sock", p->vm.name);

		char tpm_dir[256];
		sprintf(tpm_dir, "%s%s/tpm", vmdir, p->vm.name);

		// 检查 swtpm 是否需要初始化
		char tpm_permall[512];
		sprintf(tpm_permall, "%s/tpm2-00.permall", tpm_dir);
		
		if (access(tpm_permall, F_OK) != 0) {
			// 创建 swtpm 包装器以修复 FreeBSD 上的 --print-capabilities 问题
			// 使用 VM 目录而不是 /tmp 以避免 noexec 问题
			char wrapper_path[512];
			sprintf(wrapper_path, "%s%s/swtpm_wrapper.sh", vmdir, p->vm.name);
			
			FILE *fp = fopen(wrapper_path, "w");
			if (fp) {
				fprintf(fp, "#!/bin/sh\n");
				fprintf(fp, "# Check if first argument is one of the commands requiring socket mode\n");
				fprintf(fp, "case \"$1\" in\n");
				fprintf(fp, "    socket|cuse|-v|--version|--help|-h)\n");
				fprintf(fp, "        exec /usr/local/bin/swtpm \"$@\"\n");
				fprintf(fp, "        ;;\n");
				fprintf(fp, "    *)\n");
				fprintf(fp, "        # Default to socket mode for everything else\n");
				fprintf(fp, "        exec /usr/local/bin/swtpm socket \"$@\"\n");
				fprintf(fp, "        ;;\n");
				fprintf(fp, "esac\n");
				fclose(fp);
				chmod(wrapper_path, 0755);
			}

			write_log("Initializing TPM state for %s...", p->vm.name);
			char init_cmd[1024];
			// 使用 --tpmstate dir:///path 格式更安全
			sprintf(init_cmd, "mkdir -p %s; /usr/local/bin/swtpm_setup --tpm %s --tpmstate dir://%s --create-ek-cert --create-platform-cert --tpm2", tpm_dir, wrapper_path, tpm_dir);
			int ret = system(init_cmd);
			
			// 清理包装器
			unlink(wrapper_path);
			
			if (ret != 0) {
				write_log("Error: swtpm_setup failed with exit code %d", ret);
				// 继续进行，可能在没有证书的情况下工作，但 Windows 可能会抱怨
			}
		}

		char sock_dir[256];
		sprintf(sock_dir, "/tmp/%s", p->vm.name);
		
		char tpm_ctrl_sock[256];
		sprintf(tpm_ctrl_sock, "/tmp/%s/swtpm-ctrl.sock", p->vm.name);
		
		char start_swtpm[1024];
		char swtpm_log[256];
		sprintf(swtpm_log, "/tmp/swtpm-%s.log", p->vm.name);

		sprintf(start_swtpm, 
			"mkdir -p %s; "
			"mkdir -p %s; "
			"rm -f %s; " // 删除过期的 socket
			"rm -f %s; "
			"/usr/local/bin/swtpm socket --tpmstate dir=%s --ctrl type=unixio,path=%s --server type=unixio,path=%s --tpm2 --flags not-need-init,startup-clear -d --pid file=/var/run/swtpm-%s.pid > %s 2>&1",
			sock_dir, tpm_dir, tpm_sock, tpm_ctrl_sock, tpm_dir, tpm_ctrl_sock, tpm_sock, p->vm.name, swtpm_log);
		
		write_log("Starting swtpm: %s", start_swtpm);
		int ret = system(start_swtpm);

		if (ret != 0) {
			write_log("Error: swtpm command failed with exit code %d. Check %s for details.", ret, swtpm_log);
			
			// 将日志内容打印到 bvm 日志
			char log_content[1024] = {0};
			FILE *fp = fopen(swtpm_log, "r");
			if (fp) {
				size_t n = fread(log_content, 1, sizeof(log_content)-1, fp);
				if (n > 0) write_log("swtpm log output: %s", log_content);
				fclose(fp);
			}
			exit(1);
		}

		// 等待 socket 准备就绪（最多 10 秒）
		int wait_retries = 100;
		while (wait_retries-- > 0) {
			if (access(tpm_sock, F_OK) == 0) break;
			usleep(100000); // 100ms
		}
		
		if (access(tpm_sock, F_OK) != 0) {
			write_log("Error: swtpm socket %s not found after waiting 10s. Aborting boot. Check %s for details.", tpm_sock, swtpm_log);
			
			// 将日志内容打印到 bvm 日志
			char log_content[1024] = {0};
			FILE *fp = fopen(swtpm_log, "r");
			if (fp) {
				size_t n = fread(log_content, 1, sizeof(log_content)-1, fp);
				if (n > 0) write_log("swtpm log output: %s", log_content);
				fclose(fp);
			}

			// 清理任何部分进程
			char stop_swtpm[512];
			sprintf(stop_swtpm, 
				"if [ -f /var/run/swtpm-%s.pid ]; then "
				"kill $(cat /var/run/swtpm-%s.pid); "
				"rm /var/run/swtpm-%s.pid; "
				"fi",
				p->vm.name, p->vm.name, p->vm.name);
			system(stop_swtpm);
			exit(1); 
		}
	}


	char cmd[BUFFERSIZE];
	while (1) {
		
		//bhyve
		char t[BUFFERSIZE];
		// 当启用 PCI 直通时，必须锁定内存 (-S)
		if (strcmp(p->vm.ppt_status, "on") == 0)
			strcpy(cmd, "bhyve -c cpus=${vm_cpus},sockets=${vm_sockets},cores=${vm_cores},threads=${vm_threads} -m ${vm_ram} -HAPuwS ");
		else
			strcpy(cmd, "bhyve -c cpus=${vm_cpus},sockets=${vm_sockets},cores=${vm_cores},threads=${vm_threads} -m ${vm_ram} -HAPuw ");

		strcat(cmd, "-s 0:0,${vm_hostbridge} ");
		
		
		// 固定 slot 分配：HD 始终在 slot 2，CD 始终在 HD 之后
		// 这样无论从哪里启动，设备路径保持一致，UEFI vars 中的启动项不会失效
		int disk_count = atoi(p->vm.disks);
		int hd_slots_needed = (disk_count + 7) / 8;
		if (hd_slots_needed == 0) hd_slots_needed = 1;
		int hd_slot_start = 2;
		int cd_slot = 2 + hd_slots_needed;
		
		
		// 按固定顺序追加参数：先 HD 后 CD
		append_hd_args(cmd, p, hd_slot_start);
		append_cd_args(cmd, p, cd_slot);
		
		
		for (int n=0; n<atoi(p->vm.nics); n++) {
			//经测试 uefi 下 e1000 无效，只能使用 virtio-net
			//if (host_version() >= EM0_VER)
			//	sprintf(t, "-s 10:%d,e1000,${vm_tap%d} ", n, n);
			//else
				sprintf(t, "-s 10:%d,virtio-net,${vm_tap%d},mac=${vm_mac%d} ", n, n, n);
			strcat(cmd, t);
		}
		// VNC 配置
		if (boot == 0 || strcmp(p->vm.vncstatus, "on") == 0) {
			char vnc_cmd[256];
			sprintf(vnc_cmd, "-s 29,fbuf,tcp=${vm_vncbind}:${vm_vncport},w=${vm_vncwidth},h=${vm_vncheight}");
			
			// Add password if set
			if (strlen(p->vm.vncpassword) > 0) {
				strcat(vnc_cmd, ",password=${vm_vncpassword}");
			}
			
			// Add wait option
			if (boot == 0 || strcmp(p->vm.vncwait, "on") == 0) {
				strcat(vnc_cmd, ",wait");
			}
			
			strcat(vnc_cmd, " ");
			strcat(cmd, vnc_cmd);
		}
		// Audio 支持
		if (strcmp(p->vm.audiostatus, "on") == 0)
			strcat(cmd, "-s 6,hda,play=/dev/dsp0,rec=/dev/dsp0 ");

		// VirtIO-9P 文件共享
		if (strcmp(p->vm.share_status, "on") == 0 && strlen(p->vm.share_path) > 0) {
			char share_cmd[512];
			if (strcmp(p->vm.share_ro, "on") == 0)
				sprintf(share_cmd, "-s 20,virtio-9p,%s=%s,ro ", 
					p->vm.share_name, p->vm.share_path);
			else
				sprintf(share_cmd, "-s 20,virtio-9p,%s=%s ", 
					p->vm.share_name, p->vm.share_path);
			strcat(cmd, share_cmd);
		}

		// PCI 直通设备
		if (strcmp(p->vm.ppt_status, "on") == 0) {
			int ppt_slot = 0;
			for (int n=0; n<atoi(p->vm.ppts); n++) {
				// 跳过空的 ppt 设备配置
				if (strlen(p->vm.ppt[n].device) == 0) continue;
				
				char ppt_cmd[256];
				if (strlen(p->vm.ppt[n].rom) > 0)
					sprintf(ppt_cmd, "-s 21:%d,passthru,%s,rom=%s ", 
						ppt_slot, p->vm.ppt[n].device, p->vm.ppt[n].rom);
				else
					sprintf(ppt_cmd, "-s 21:%d,passthru,%s ", 
						ppt_slot, p->vm.ppt[n].device);
				strcat(cmd, ppt_cmd);
				ppt_slot++;
			}
		}

		strcat(cmd, "-s 30,xhci,tablet ");
		strcat(cmd, "${vm_tpm_param}");
		strcat(cmd, "-s 31,lpc -l com1,stdio ");
		
		// 智能选择 UEFI 固件模式
		if (strlen(p->vm.uefi_vars) > 0 && access(p->vm.uefi_vars, R_OK) == 0) {
			// 新方式：使用 CODE + VARS（优先）
			if (access("/usr/local/share/uefi-firmware/BHYVE_UEFI_CODE.fd", R_OK) == 0) {
				strcat(cmd, "-l bootrom,/usr/local/share/uefi-firmware/BHYVE_UEFI_CODE.fd,${vm_uefi_vars} ");
			} else {
				// CODE 文件不存在，回退到旧方式
				strcat(cmd, "-l bootrom,/usr/local/share/uefi-firmware/${vm_bhyve_uefi_fd} ");
			}
		} else {
			// 兼容旧方式（没有 vars 文件或 vars 文件不可读）
			strcat(cmd, "-l bootrom,/usr/local/share/uefi-firmware/${vm_bhyve_uefi_fd} ");
		}
		strcat(cmd, "${vm_name}");

		ret = run(cmd, p);

		/*********** bhyve EXIT STATUS ***********
		  0	     rebooted
		  1	     powered off
		  2	     halted
		  3	     triple fault
		  4	     exited due	to an error
		*******************************************/
		write_log("bhyve exited with status: %d (%s)", ret, get_bhyve_exit_desc(ret));
		
		if (ret > 0 && ret <= 4) break;

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

	// 清理 .orig 备份文件
	// 如果从 HD 启动后正常结束，删除 .orig 备份
	// 这样下次从 CD 启动时，会正确备份当前的 efivars（包含 HD 启动项）
	if (boot == 1 && strcmp(p->vm.boot_type, "grub") != 0 && strlen(p->vm.uefi_vars) > 0) {
		char backup_vars[512];
		sprintf(backup_vars, "%s.orig", p->vm.uefi_vars);
		if (access(backup_vars, F_OK) == 0) {
			unlink(backup_vars);
			write_log("Cleaned up UEFI vars backup for VM %s after HD boot", p->vm.name);
		}
	}

	// TPM 停止逻辑

	if (strcmp(p->vm.tpmstatus, "on") == 0) {
		char stop_swtpm[512];
		sprintf(stop_swtpm, 
			"if [ -f /var/run/swtpm-%s.pid ]; then "
			"kill -9 $(cat /var/run/swtpm-%s.pid) 2>/dev/null; "
			"rm -f /var/run/swtpm-%s.pid; "
			"fi",
			p->vm.name, p->vm.name, p->vm.name);
		
		write_log("Stopping swtpm: %s", stop_swtpm);
		system(stop_swtpm);
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
	str_replace(str, "${vm_boot_type}", 		p->vm.boot_type);
	str_replace(str, "${vm_devicemap}", 	p->vm.devicemap);
	str_replace(str, "${vm_ram}", 		p->vm.ram);
	str_replace(str, "${vm_cpus}", 		p->vm.cpus);
	str_replace(str, "${vm_sockets}", 	p->vm.sockets);
	str_replace(str, "${vm_cores}", 	p->vm.cores);
	str_replace(str, "${vm_threads}", 	p->vm.threads);
	str_replace(str, "${vm_hostbridge}", 	p->vm.hostbridge);
	str_replace(str, "${vm_disk}",		p->vm.disk);
	str_replace(str, "${vm_disk0}",		p->vm.disk);
	str_replace(str, "${vm_iso}", 		p->vm.iso);
	str_replace(str, "${vm_vncport}", 	p->vm.vncport);
	str_replace(str, "${vm_vncwidth}", 	p->vm.vncwidth);
	str_replace(str, "${vm_vncheight}", 	p->vm.vncheight);
	str_replace(str, "${vm_vncpassword}", 	p->vm.vncpassword);
	if (strlen(p->vm.vncbind) > 0)
		str_replace(str, "${vm_vncbind}", 	p->vm.vncbind);
	else
		str_replace(str, "${vm_vncbind}", "0.0.0.0");
	str_replace(str, "${vm_network_interface}", p->vm.network_interface);
	if (strlen(p->vm.storage_interface) > 0)
		str_replace(str, "${vm_storage_interface}", p->vm.storage_interface);
	else
		str_replace(str, "${vm_storage_interface}", "ahci-hd");
	str_replace(str, "${vm_uefi_vars}",	p->vm.uefi_vars);
	if (strcmp(p->vm.boot_type, "uefi") == 0)
		str_replace(str, "${vm_bhyve_uefi_fd}", "BHYVE_UEFI.fd");
	if (strcmp(p->vm.boot_type, "uefi_csm")== 0)
		str_replace(str, "${vm_bhyve_uefi_fd}", "BHYVE_UEFI_CSM.fd"); 

	// TPM
	char tpm_param[512] = "";
	if (strcmp(p->vm.tpmstatus, "on") == 0) {
		char tpm_sock[256];
		if (strlen(p->vm.tpmpath) > 0)
			strcpy(tpm_sock, p->vm.tpmpath);
		else
			sprintf(tpm_sock, "/tmp/%s/swtpm.sock", p->vm.name);
		
		sprintf(tpm_param, "-l tpm,swtpm,%s ", tpm_sock);
	}
	str_replace(str, "${vm_tpm_param}", tpm_param); 

        for (int n=0; n<atoi(p->vm.nics); n++) {
                char buf[32];
                sprintf(buf, "${vm_tap%d}", n);
                str_replace(str, buf, p->vm.nic[n].tap);

                sprintf(buf, "${vm_mac%d}", n);
                str_replace(str, buf, p->vm.nic[n].mac);
        }

        for (int n=0; n<atoi(p->vm.disks); n++) {
                char buf[32];
                sprintf(buf, "${vm_disk%d}", n);
   		str_replace(str, buf, p->vm.vdisk[n].path);
        }

	// 多 CD ISO 路径替换
        for (int n=0; n<atoi(p->vm.cds); n++) {
                char buf[32];
                sprintf(buf, "${vm_cd_iso_%d}", n);
   		str_replace(str, buf, p->vm.cd_iso[n]);
        }

}
