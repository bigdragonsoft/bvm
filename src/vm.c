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

/**************************************************************************************************
 *
 *
 *   ____  _                      __      __          __  __                                   
 *   |  _ \| |                     \ \    / /         |  \/  |                                  
 *   | |_) | |__  _   ___   _____   \ \  / / __ ___   | \  / | __ _ _ __   __ _  __ _  ___ _ __ 
 *   |  _ <| '_ \| | | \ \ / / _ \   \ \/ / '_ ` _ \  | |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ '__|
 *   | |_) | | | | |_| |\ V /  __/    \  /| | | | | | | |  | | (_| | | | | (_| | (_| |  __/ |   
 *   |____/|_| |_|\__, | \_/ \___|     \/ |_| |_| |_| |_|  |_|\__,_|_| |_|\__,_|\__, |\___|_|   
 *                 __/ |                                                         __/ |          
 *                |___/                                                         |___/           
 *
 *
 *
 *                                                           __   __      __           __   __ 
 *                                                            _) /  \ /| (__)    /|     _) |_  
 *                                                           /__ \__/  | (__).    |.   /__ __)
 *
 **************************************************************************************************/
#include "vm.h"
#include "vnet.h"
#include "create.h"
#include "config.h"
#include "zfs.h"

char *osdir = "/usr/local/etc/bvm/";
char *logfile = "/var/log/bvm";
char *dhcp_pool_file = ".dhcp_pool";
FILE *logfp = NULL;
char vmdir[FN_MAX_LEN];
vm_node *vms;
vm_node *boot[MAX_BOOT_NUM] = {0};
os_stru bvm_os[OS_NUM] = {0};
	/* type		   uefi_boot 	   grub_boot 	     grub_cmd*/
	/*-----------------------------------------------------------*/
/*	{"FreeBSD", 		1, 		1,		1},
	{"OpenBSD", 		0, 		1,		1},
	{"NetBSD", 		0, 		1,		1},
	{"Debian", 		1, 		1,		0},
	{"Ubuntu", 		1, 		1,		0},
	NULL,
};*/

// strcpy 函数
char *bvm_strcpy(char *dst, const char *src)
{
	if (src == NULL || dst == NULL) return NULL;

	char *addr = dst;

	while ((*dst++ = *src++));

	return addr;
}

// 写入日志文件(时间部分)
int write_log_time()
{
	logfp = fopen(logfile, "a+");
	if (logfp == NULL) return -1;

	time_t t;
	struct tm *p;
	time(&t);
	p = localtime(&t);

	struct passwd *pwd;
	pwd = getpwuid(getuid());

	/*
	char *month[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", 
			 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", 
			 NULL}; 
	fprintf(logfp, "%s %d %02d:%02d:%02d %s: ", 
			month[p->tm_mon],
			p->tm_mday, 
			p->tm_hour, 
			p->tm_min, 
			p->tm_sec,
			pwd->pw_name);
	*/
	fprintf(logfp, "%d/%02d/%02d %02d:%02d:%02d %s: ",
			p->tm_year + 1900,
			p->tm_mon + 1,
			p->tm_mday,
			p->tm_hour,
			p->tm_min,
			p->tm_sec,
			pwd->pw_name);
	return 0;
}

// 写入日志文件
int write_log(char *fmt, ...)
{
	write_log_time();
	if (logfp == NULL) return -1;


	va_list argptr;
	int cnt;

	va_start(argptr, fmt);
	cnt = vfprintf(logfp, fmt, argptr);
	va_end(argptr);
	
	if (lastch(fmt) != '\n') fprintf(logfp, "\n");

	fclose(logfp);
	return cnt;
}

// 对所有vm进行保护处理
void vm_lock_all(int flag)
{
	if (vms == NULL) return;
	vm_node *p = vms;

	while (p) {
		vm_lock(p->vm.name, flag);
		p = p->next;
	}
}

// 对vm进行保护
void vm_lock(char *vm_name, int flag)
{	
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
	}

	if (get_vm_status(vm_name) == VM_ON) {
		error("cannot process, %s is running\n", vm_name);
		return;
	}
	
	if (flag > 0) {
		if (strcmp(p->vm.lock, "1") == 0) return;
		strcpy(p->vm.lock, "1");
		save_vm_info(vm_name, &p->vm);
	}

	char fn[BUFFERSIZE];
	sprintf(fn, "%s%s/device.map", vmdir, p->vm.name);
	file_lock(fn, flag);

	sprintf(fn, "%s%s/%s.conf", vmdir, p->vm.name, p->vm.name);
	file_lock(fn, flag);

	for (int n=0; n<atoi(p->vm.disks); n++) {
		if (n == 0)
			sprintf(fn, "%s%s/disk.img", vmdir, p->vm.name);
		else
			sprintf(fn, "%s%s/disk%d.img", vmdir, p->vm.name, n);

		file_lock(fn, flag);
	}

	if (flag <= 0) {
		strcpy(p->vm.lock, "0");
		save_vm_info(vm_name, &p->vm);
	}
}

// 保护/解除保护某一个文件
// flag=1开启保护
// flag=0解除保护
void file_lock(char *file, int flag)
{
	if (flag > 0) 
		flag = SF_IMMUTABLE;
	else
		flag = 0;

	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		error("locking %s failed\n", file);
		err_exit();
	}
	fchflags(fd, flag);
	close(fd);
}


// 获取网桥中tap接口对应的mac地址
int get_mac_from_bridge(char *bridge, char *tap, char *mac)
{
	char cmd[BUFFERSIZE];
	sprintf(cmd, "ifconfig %s addr | grep %s | awk '{print $1}'", bridge, tap);

	FILE *fp = popen(cmd, "r");
	if (fp == NULL) return RET_FAILURE;

	char buf[64];
	if (fgets(buf, 64, fp)) {
		buf[strlen(buf)-1] = '\0';
		strcpy(mac, buf);
		pclose(fp);
		return RET_SUCCESS;
	}
	pclose(fp);
	return RET_FAILURE;
}

// 生成MAC地址
void generate_mac(char *mac)
{
	// 58:9c:fc is bhyve default OUI
    // Use arc4random for BSD systems
	sprintf(mac, "58:9c:fc:%02x:%02x:%02x", 
		arc4random() % 256,
		arc4random() % 256,
		arc4random() % 256);
}

// 从dhcp地址池中获取指定mac对应的ip
// 返回 RET_SUCCESS 找到
// 返回 RET_FAILURE 未找到
int get_ip_from_dhcp_pool(char *mac, char *ip)
{
	char fn[FN_MAX_LEN];
	sprintf(fn, "%s/%s", vmdir, dhcp_pool_file);

	FILE *fp = fopen(fn, "r");
	if (fp == NULL) return RET_FAILURE;

	char line[BUFFERSIZE];
	while(fgets(line, BUFFERSIZE, fp)) {
		if (strstr(line, mac)) {
			//found
            // format: IP <tab> MAC <tab> ...
            // e.g. 192.168.1.100	58:9c:fc:00:00:01 ...
			char *p = strtok(line, "\t");
			if (p) {
				strcpy(ip, p);
				fclose(fp);
				return RET_SUCCESS;
			}
		}
	}
	fclose(fp);
	return RET_FAILURE;
}

// 对虚拟机进行加密处理
void vm_crypt(char *vm_name, int flag)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
	}

	if (get_vm_status(vm_name) == VM_ON) {
		error("cannot encrypt, %s is running\n", vm_name);
		return;
	}

	char succ_msg[128]; 
	if (flag > 0) {
		if (strcmp(p->vm.crypt, "1") == 0) {
			warn("cannot encrypt\n");
			return;
		}
		strcpy(p->vm.crypt, "1");
		strcpy(succ_msg, "encryption completed, losing the key will make decryption impossible");
	}
	else {
		if (strcmp(p->vm.crypt, "1") != 0) {
			warn("cannot decrypt\n");
			return;
		}
		strcpy(p->vm.crypt, "0");
		strcpy(succ_msg, "complete the decryption");
	}

	if (strcmp(p->vm.lock, "1") == 0) {
		warn("%s locked, cannot %s\n", vm_name, flag?"encrypt":"decrypt");
		return;
	}

    // 警告
    if (flag > 0) { 
        printf("\n");
        warn("IMPORTANT SECURITY WARNING:\n");
        printf("Incompatible with old images (version <= 1.3.5).\n");
        printf("DO NOT decrypt old images with this version, or data will be corrupted.\n");
        printf("Please decrypt with the old version first, then re-encrypt with this one.\n\n");
    } else {
        // For decryption, it's even more critical to warn.
        printf("\n");
        warn("IMPORTANT SECURITY WARNING:\n");
        printf("Incompatible with old images (version <= 1.3.5).\n");
        printf("Ensure this image was encrypted with version > 1.3.5.\n");
        printf("Decrypting an old image with this version will CORRUPT your data.\n\n");
    }

	//输入一个key
	char key[256] = {0};
	char *msg = "Enter key: ";
	printf("%s", msg);
	bvm_gets(key, sizeof(key), '*');

	if (strlen(key) < 6) {
		warn("password length must be greater than 6 characters\n");
		return;
	}

	//生成盐值
	char salt[3] = {0};
	salt[0] = toupper(key[0]);
	salt[1] = key[strlen(key) - 1];

	//根据key生成passwd
	char passwd[256];
	strcpy(passwd, crypt(key, salt));

    // 生成密钥和基础IV
    unsigned char aes_key[32];
    unsigned char base_iv[16];

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx) {
        unsigned int key_len = 0;
        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) == 1 &&
            EVP_DigestUpdate(mdctx, passwd, strlen(passwd)) == 1 &&
            EVP_DigestFinal_ex(mdctx, aes_key, &key_len) == 1) {
            // Success
        }
        EVP_MD_CTX_free(mdctx);
    }
    
    // 根据密钥生成基础 IV（如前所述）
    memcpy(base_iv, aes_key, 16);

	unsigned char data[CRYPT_BUFFER];
	char file[FN_MAX_LEN];
	sprintf(file, "%s%s/disk.img", vmdir, p->vm.name);

	//获取文件大小
	struct stat st;
	if (stat(file, &st) != 0) {
		error("get %s size failed\n", file);
		return;
	}

	//计算总块数
    long long total_size = st.st_size;
	int total_blocks = (total_size + CRYPT_BUFFER - 1) / CRYPT_BUFFER;
	
	// 在开始处打印初始进度
	printf("Processing: 0%%");
	fflush(stdout);
	
	for (int i=0; i<total_blocks; i++) {
        int len = CRYPT_BUFFER;
        if (i == total_blocks - 1) {
            len = total_size % CRYPT_BUFFER;
            if (len == 0) len = CRYPT_BUFFER;
        }
        
        // Ensure 16-byte alignment for CBC
        int aligned_len = len;
        if (len % 16 != 0) {
            aligned_len = len - (len % 16);
        }
        
        if (aligned_len > 0) {
            //读取数据
            crypt_read(file, data, i, aligned_len);

            // 计算当前块IV
            unsigned char iv[16];
            memcpy(iv, base_iv, 16);
            *(uint32_t*)iv ^= (uint32_t)i; // Mix block index

            //AES-256加密/解密
            bvm_crypt_chunk(data, aligned_len, aes_key, iv, flag);
        
            //写回文件
            crypt_write(file, data, i, aligned_len);
        }
		
		// 更新百分比
		printf("\r"); // 回到行首
		printf("Processing: %d%%", (i * 100) / total_blocks);
		fflush(stdout);
	}
	
	// 完成后清除进度显示
	printf("\r"); // 回到行首
	printf("\033[K"); // 清除该行

	save_vm_info(vm_name, &p->vm);
	printf("\033[1A\033[K");
	printf("%s\n", succ_msg);
}

// 将加密后的数据写入虚拟机磁盘
void crypt_write(char *file, unsigned char *s, int index, int size)
{
	FILE *fp = fopen(file, "rb+");

	if (fp) {
	
		fseek(fp, (long)index * CRYPT_BUFFER, SEEK_SET);
		fwrite(s, 1, size, fp);

		fclose(fp);
	}
	else {
		error("write disk-image error\n");
		err_exit();
	}
}

// 读取虚拟机磁盘部分数据
int crypt_read(char *file, unsigned char *s, int index, int size)
{
	FILE *fp = fopen(file, "rb");
    int ret = 0;

	if (fp) {

		fseek(fp, (long)index * CRYPT_BUFFER, SEEK_SET);
		ret = fread(s, 1, size, fp);

		fclose(fp);
	}
	else {
		error("read disk-image error\n");
		err_exit();
	}
    return ret;
}

// 对数据进行异或运算
void bvm_xor(unsigned char *s, char *passwd)
{
	int len = strlen(passwd);
	int j = 0;
	for (int i=0; i<CRYPT_BUFFER; i++) {
		if (j >= len)
			j = 0;
		s[i] ^= passwd[j++];
	}
}

// 使用AES-256加密/解密数据
// data: 要加密/解密的数据
// passwd: 密码
// encrypt: 1表示加密,0表示解密
// 返回: 成功返回1,失败返回0
// 使用AES-256加密/解密数据块
int bvm_crypt_chunk(unsigned char *data, int len, unsigned char *key, unsigned char *iv, int encrypt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    unsigned char *outbuf = malloc(len);
    if (!outbuf) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int outlen = 0;
    int ret = 1;

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, encrypt) != 1) {
        ret = 0;
        goto end;
    }

    // 禁用padding以匹配AES_cbc_encrypt的行为
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // 执行加密/解密
    if (EVP_CipherUpdate(ctx, outbuf, &outlen, data, len) != 1) {
        ret = 0;
        goto end;
    }

    // Finalize
    int final_len = 0;
    if (EVP_CipherFinal_ex(ctx, outbuf + outlen, &final_len) != 1) {
        ret = 0;
        goto end;
    }

    // 复制结果回原缓冲区
    memcpy(data, outbuf, len);

end:
    free(outbuf);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

// 使用AES-256加密/解密数据
void bvm_crypt(unsigned char *data, char *passwd)
{
    // 使用SHA-256生成256位密钥
    unsigned char key[32];
    unsigned char iv[16];
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return;

    unsigned int key_len = 0;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, passwd, strlen(passwd)) != 1 ||
        EVP_DigestFinal_ex(mdctx, key, &key_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return;
    }
    EVP_MD_CTX_free(mdctx);

    // 生成IV (对第一个块使用密码hash的前16字节作为IV)
    memcpy(iv, key, 16);

    // 初始化加密上下文
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        return;
    }

    // 根据数据的前8字节判断是加密还是解密
    // 如果前8字节是特定标记，则进行解密，否则加密
    int is_encrypt = memcmp(data, "AESMARK!", 8) != 0;

    int len = 0;
    int ciphertext_len = 0;
    unsigned char *temp_buf = malloc(CRYPT_BUFFER + EVP_MAX_BLOCK_LENGTH);
    if(!temp_buf) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if(is_encrypt) {
        // 加密操作
        // 初始化加密
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

        // 添加标记
        memcpy(temp_buf, "AESMARK!", 8);

        // 加密数据
        EVP_EncryptUpdate(ctx, temp_buf + 8, &len, data, CRYPT_BUFFER - 8);
        ciphertext_len = len;

        // 加密最后的块
        EVP_EncryptFinal_ex(ctx, temp_buf + 8 + len, &len);
        ciphertext_len += len;

    } else {
        // 解密操作
        // 初始化解密
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

        // 解密数据
        EVP_DecryptUpdate(ctx, temp_buf, &len, data + 8, CRYPT_BUFFER - 8);
        ciphertext_len = len;

        // 解密最后的块
        EVP_DecryptFinal_ex(ctx, temp_buf + len, &len);
        ciphertext_len += len;
    }

    // 复制结果回原缓冲区
    if(is_encrypt) {
        memcpy(data, temp_buf, CRYPT_BUFFER);
    } else {
        memcpy(data, temp_buf, ciphertext_len);
        // 如果解密后数据长度小于原缓冲区，填充0
        if(ciphertext_len < CRYPT_BUFFER) {
            memset(data + ciphertext_len, 0, CRYPT_BUFFER - ciphertext_len);
        }
    }

    // 清理
    EVP_CIPHER_CTX_free(ctx);
    free(temp_buf);
    // 清除敏感数据
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
}

// 测试AES-256加密/解密
void test()
{
	printf("test AES-256 encryption and decryption\n");
	int len = 160;
    unsigned char data[len];
    unsigned char key[32] = "12345678901234567890123456789012";
    unsigned char iv[16] = "1234567890123456";


    // 初始化测试数据
    	for (int i = 0; i < len; i++) {
        data[i] = i;
    }

    printf("original data:\n");
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");


    // 加密
    if (!bvm_crypt_chunk(data, len, key, iv, 1)) {
        printf("encryption failed\n");
        return;
    }

    printf("encrypted data:\n");
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");


    // 解密
    if (!bvm_crypt_chunk(data, len, key, iv, 0)) {
        printf("decryption failed\n");
        return;
    }

    printf("decrypted data:\n");
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");

}
	

// 监测bvm运行环境
// bvm runtime environment 
void check_bre()
{
	/**************************
	 * virtualization detection
	 **************************/

	if (!exist_hw_vmm_vmx_initialized(NULL) || get_vmx(NULL) != 1) {
		error("This machine does not support virtualization.\n");
		return;
	}

	/********************************
	 * Dependency package detection 
	 * 1. bhyve-firmware
	 * 2. tmux
	 * 3. grub-bhyve
	 * 4. swtpm
	 ********************************/
	
	// 检查新版 UEFI 固件文件（支持 vars 持久化）
	int has_new_uefi = 0;
	if (access("/usr/local/share/uefi-firmware/BHYVE_UEFI_CODE.fd", 0) == 0 &&
	    access("/usr/local/share/uefi-firmware/BHYVE_UEFI_VARS.fd", 0) == 0) {
		has_new_uefi = 1;
	}
	
	// 检查旧版 UEFI 固件文件（兼容模式）
	int has_old_uefi = 0;
	if (access("/usr/local/share/uefi-firmware/BHYVE_UEFI.fd", 0) == 0) {
		has_old_uefi = 1;
	}
	
	// 如果都没有，警告无法支持 UEFI
	if (!has_new_uefi && !has_old_uefi) {
		warn("unable to support UEFI\n");
		warn("please use 'pkg install bhyve-firmware' to install first\n\n");
	} else if (!has_new_uefi && has_old_uefi) {
		// 只有旧版，警告建议更新
		warn("Old UEFI firmware detected (legacy mode)\n");
		warn("Recommend upgrading bhyve-firmware package for UEFI vars persistence support\n\n");
	}

	//tmux
	if (access("/usr/local/bin/tmux", 0) == -1) {
		error("tmux is not installed, use 'pkg install tmux' to install it\n");
		exit(0);
	}

	//grub-bhyve
	if (access("/usr/local/sbin/grub-bhyve", 0) == -1) {
		error("grub2-bhyve is not installed, use 'pkg install grub2-bhyve' to install it\n");
		exit(0);
	}

	//swtpm
	if (access("/usr/local/bin/swtpm", 0) == -1) {
		error("swtpm is not installed, use 'pkg install swtpm' to install it\n");
		exit(0);
	}

	/**************************
	 * bhyve module detection
	 **************************/

	//vmm_load="YES"
	//if_bridge_load="YES"
	//if_tap_load="YES"
	init_config("/boot/loader.conf");

	int fvmm = 0;
	int fbridge = 0;
	int ftap = 0;
	int ftuoo = 0;

	char key[200];
	char *value;
	
	strcpy(key, "vmm_load");
	if ((value = get_value_by_name(key)) == NULL || strcmp(strtolower(value), "yes") != 0) fvmm = 1;
	strcpy(key, "if_bridge_load");
	if ((value = get_value_by_name(key)) == NULL || strcmp(strtolower(value), "yes") != 0) fbridge = 1; 
	strcpy(key, "if_tap_load");
	if ((value = get_value_by_name(key)) == NULL || strcmp(strtolower(value), "yes") != 0) ftap = 1;

	free_config();

	//net.link.tap.up_on_open=1
	init_config("/etc/sysctl.conf");

	strcpy(key, "net.link.tap.up_on_open");
	if ((value = get_value_by_name(key)) == NULL || strcmp(value, "1") != 0) ftuoo = 1;

	free_config();
	
	if (fvmm + fbridge + ftap > 0) {
		//error("bvm cannot run, you need to add the following lines to /boot/loader.conf\n");
		//if (fvmm) 	warn("vmm_load=\"YES\"\n");
		//if (fbridge) 	warn("if_bridge_load=\"YES\"\n");
		//if (ftap)	warn("if_tap_load=\"YES\"\n");
		if (fvmm) 		auto_fix_conf("/boot/loader.conf", "vmm_load", "\"YES\"");
		if (fbridge) 	auto_fix_conf("/boot/loader.conf", "if_bridge_load", "\"YES\"");
		if (ftap)		auto_fix_conf("/boot/loader.conf", "if_tap_load", "\"YES\"");
	}

	if (ftuoo > 0) {
		//error("bvm cannot run, you need to add the following lines to /etc/sysctl.conf\n");
		//warn("net.link.tap.up_on_open=1\n");
		auto_fix_conf("/etc/sysctl.conf", "net.link.tap.up_on_open", "1");

		//exit(0);
	}

	/**************************
	 * IPFW module detection 
	 **************************/
	
	//ipfw_load="YES"
	//ipfw_nat_load="YES"
	//libalias_load="YES"
	//net.inet.ip.fw.default_to_accept=1
	init_config("/boot/loader.conf");

	int fipfw = 0;
	int fnat = 0;
	int flib = 0;
	int faccept = 0;

	strcpy(key, "ipfw_load");
	if ((value = get_value_by_name(key)) == NULL || strcmp(strtolower(value), "yes") != 0) fipfw = 1;
	strcpy(key, "ipfw_nat_load");
	if ((value = get_value_by_name(key)) == NULL || strcmp(strtolower(value), "yes") != 0) fnat = 1; 
	strcpy(key, "libalias_load");
	if ((value = get_value_by_name(key)) == NULL || strcmp(strtolower(value), "yes") != 0) flib = 1; 
	strcpy(key, "net.inet.ip.fw.default_to_accept");
	if ((value = get_value_by_name(key)) == NULL || strcmp(value, "1") != 0) faccept = 1;

	free_config();

	if (fipfw + fnat + flib + faccept > 0) {
		//error("In order to help you solve the NAT reflow problem, \nyou need to add the following line to /boot/loader.conf\n");
		//if (fipfw) 	warn("ipfw_load=\"YES\"\n");
		//if (fnat) 	warn("ipfw_nat_load=\"YES\"\n");
		//if (flib) 	warn("libalias_load=\"YES\"\n");
		//if (faccept)	warn("net.inet.ip.fw.default_to_accept=1\n");
		if (fipfw) 		auto_fix_conf("/boot/loader.conf", "ipfw_load", "\"YES\"");
		if (fnat) 		auto_fix_conf("/boot/loader.conf", "ipfw_nat_load", "\"YES\"");
		if (flib) 		auto_fix_conf("/boot/loader.conf", "libalias_load", "\"YES\"");
		if (faccept)	auto_fix_conf("/boot/loader.conf", "net.inet.ip.fw.default_to_accept", "1");
	}

}

// 自动修复配置文件
void auto_fix_conf(char *conf_file, char *key, char *value)	
{
	FILE *fp = fopen(conf_file, "a");
	if (fp == NULL) {
		error("cannot open %s\n", conf_file);
		return;
	}

	fprintf(fp, "\n%s=%s\n", key, value);
	fclose(fp);

	success("Configuration auto-fixed: %s=%s ==> %s\n", key, value, conf_file);
}

// 设置vm工作目录
void set_vmdir()
{
	char fn[FN_MAX_LEN];
	sprintf(fn, "%s%s", osdir, "bvm.conf");
	init_config(fn);
	char *value = get_value_by_name("vmdir");
	if (value == NULL || strlen(value) == 0) {
		error("please edit '/usr/local/etc/bvm/bvm.conf' first\n");
		warn("vmdir=/your/vm/dir/path/\n");
		err_exit();
	}
	else
		strcpy(vmdir, value);
	
	if (lastch(vmdir) != '/') strcat(vmdir, "/");

	free_config();

	if (access(vmdir, 0) == -1) {
		if (mkdir(vmdir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1)
			error("cannot set vmdir\n");
	}
}

// 设置bvm_os
void set_bvm_os()
{
	char fn[FN_MAX_LEN]; 
	sprintf(fn, "%s%s", osdir, "bvm.conf");
	init_config(fn);
	
	char *value;
	char item[BUFFERSIZE];
	
	for (int n=0; n<OS_NUM; n++) {
		sprintf(item, "os%d", n+1);
		if ((value = get_value_by_name(item)) == NULL) {
			break;
		}
		strcpy(bvm_os[n].type, value);

		sprintf(item, "%s_uefi_boot_enable", bvm_os[n].type);
		if (get_value_by_name(item) != NULL)
			bvm_os[n].uefi_boot = atoi(get_value_by_name(item));
		else {
			error("bvm.conf error\n");
			err_exit();
		}
		
		sprintf(item, "%s_grub_boot_enable", bvm_os[n].type);
		if (get_value_by_name(item) != NULL)
			bvm_os[n].grub_boot = atoi(get_value_by_name(item));
		else {
			error("bvm.conf error\n");
			err_exit();
		}

		sprintf(item, "%s_grub_cmd_enable", bvm_os[n].type);
		if (get_value_by_name(item) != NULL)
			bvm_os[n].grub_cmd = atoi(get_value_by_name(item));
		else {
			error("bvm.conf error\n");
			err_exit();
		}

	}

	free_config();
}

// 输出支持的os
void vm_os_list()
{
	printf("-----------------------------------------------\n");
	printf("idx\tos\t\tgrub\t\tuefi\n");
	printf("-----------------------------------------------\n");
	int n = 0;
	while (*bvm_os[n].type) {
		
		printf("%3d\t", n+1);
		printf("%s", bvm_os[n].type);
		
		for (int i=0; i<2-strlen(bvm_os[n].type)/TABSTOP; i++) printf("\t");

		if (bvm_os[n].grub_boot)
			printf("yes\t\t");
		else
			warn("no\t\t");
		if (bvm_os[n].uefi_boot)
			printf("yes\n");
		else
			warn("no\n");

		++n;
	}
}

// 虚拟机列表初始化
void vm_init()
{
	create_vm_list();
	get_vm_name(vmdir);
	//sort_vm_list(LS_BY_NAME);
}

// 虚拟机列表销毁
void vm_end()
{
	destroy_vm_list();
}

// 返回在线的虚拟机数量
int vm_online_count()
{
	int count = 0;
	vm_node *p = vms;
	while (p) {
		if (get_vm_status(p->vm.name) == VM_ON)
			count++;
		p = p->next;
	}
	return count;
}

/*
 * 输出虚拟机列表
 * Output virtual machine list
 */
void vm_list(int list_type, char *index_key, int online_only)
{
	//先将虚拟机列表按键值排序
	if (strcmp(index_key, "byname") == 0)
		sort_vm_list(LS_BY_NAME);
	else if (strcmp(index_key, "byip") == 0 && list_type == VM_LONG_LIST)
		sort_vm_list(LS_BY_IP);
	else if (strcmp(index_key, "byos") == 0)
		sort_vm_list(LS_BY_OS);
	else if (strcmp(index_key, "bystatus") == 0)
		sort_vm_list(LS_BY_STATUS);
	else {
		error("Invalid parameters.\n");
		err_exit();
	}

	//再开始输出列表
	print_vm_list(list_type, online_only);
}

// 获的vm最长的名字长度
int max_vm_name_len()
{
	int len = 0;
	vm_node *p = vms;
	while (p) {
		int m = strlen(p->vm.name);
		if (m > len) len = m;
		p = p->next;
	}
	return len;
}

// 显示所有设备关系
void vm_show_device_all(int show_type)
{
	vm_show_device(VNET_DEFAULT_BRIDGE, show_type);
	vm_show_nat(show_type);
	vm_show_switch(show_type);
}

// 显示NAT设备
void vm_show_nat(int show_type)
{
	load_nat_list();
	int n = 0;
	while (nat_list[n]) {
		vm_show_device(nat_list[n]->name, show_type);
		++n;
	}	
}

// 显示Switch设备
void vm_show_switch(int show_type)
{
	load_switch_list();
	int n = 0;
	while (switch_list[n]) {
		vm_show_device(switch_list[n]->name, show_type);
		++n;
	}	
}

// 显示设备名称
void vm_show_device_name(char *device)
{
	warn("%s ", device);
	if (strstr(device, "switch")) {
		get_switch_info(device);	
		if (strlen(Switch.ip) > 0)
			warn("[%s]", Switch.ip);
	}
	else if (strstr(device, "nat")) {
		get_nat_info(device);
		warn("[%s]", nat.ip);
	}
	printf("\n");

}

// 显示设备的关联
void vm_show_device(char *dev, int show_type)
{
	if (vms == NULL) return;

	char device[32];
	if (dev == NULL)
		enter_vm_device(device);
	else
		strcpy(device, dev);

	if (show_type == SD_CLASSICAL)
		vm_show_device_name(device);

	int len = max_vm_name_len();
	int tab = len / TABSTOP + 1;

	int flag = 0;	
	vm_node *p = vms;
	while (p) {
		int num = atoi(p->vm.nics);
		for (int n = 0; n < num; n++) {

			if ((strcmp(p->vm.nic[n].bind, device) == 0) || (strcmp(p->vm.nic[n].nat, device) == 0) || 
			    (strcmp(VNET_DEFAULT_BRIDGE, device) == 0 && (strcmp(p->vm.nic[n].netmode, "NAT") != 0) 
			     					       && is_nic(p->vm.nic[n].bind))) {
				
				if (show_type == SD_SIMPLE && !flag) vm_show_device_name(device);
				{
					if (strcmp(VNET_DEFAULT_BRIDGE, device) == 0 && strlen(p->vm.nic[n].bind) > 0) {
						static int em0 = 1;
						if (em0) {
							printf("  |-%s\n", p->vm.nic[n].bind);
							em0 = 0;
							//continue;
						}
					}
				}

				flag = 1;
				printf("  |-");
				if (get_vm_status(p->vm.name) == VM_ON) {
					success("%s ", p->vm.name);
					for (int i=0; i<(len-strlen(p->vm.name)); i++) printf(" ");
					success("(nic%d)\n", n);
				}
				else {
					printf("%s ", p->vm.name);
					for (int i=0; i<(len-strlen(p->vm.name)); i++) printf(" ");
					printf("(nic%d)\n", n);
				}

			}

		}
		
		p = p->next;
	}
	if (show_type == SD_CLASSICAL && !flag) { printf("  |-"); red("null\n");}
}

// 是否为物理网卡
// 1 是
// 0 否
int is_nic(char *nic_name)
{
	get_nic_list(CABLE_AND_WIRELESS);

	int n = 0;
	while (strlen(nic_list[n]) > 0) {
		if (strcmp(nic_list[n], nic_name) == 0) return 1;
		++n;
	}
	return 0;
}

// 清理vm网桥、tap等
void vm_clean()
{
	get_vnet_list(BRIDGE);
	int n = 0;
	char desc[VNET_BUFFERSIZE] = {0};
	char **p = bridge_list;
	while (*(p+n)) {
		//依次获取网桥的desc字段
		get_bridge_desc(*(p+n), desc);

		//确定bvm使用的网桥
		if (strstr(desc, "bvm")) {
			//清理tap
			get_members_in_bridge(*(p+n));
			if (*tap_list) {
				//printf("%s+\n", *(p+n));	
				int m = 0;
				while (tap_list[m]) {
					//warn("%s\n", tap_list[m]);
					clean_tap(tap_list[m]);
					++m;
				}
			}
			//清理bridge
			clean_bridge(*(p+n));
		}
		++n;
	}
}

// 检测并销毁指定bridge
void clean_bridge(char *bridge_name)
{
	get_members_in_bridge(bridge_name);
	if (tap_list_count(TL_NO_NIC) == 0) {
		strcpy(bridge, bridge_name);
		//error("clean %s\n", bridge);
		run_bridge_command(DESTROY_BRIDGE);
	}
}

// 检测并销毁指定tap
void clean_tap(char *tap_name)
{
	if (strstr(tap_name, "vmnet") == NULL) return;

	strcpy(tap, tap_name);
	vm_node *p = vms;
	while (p) {
		//error("vm.status=%s\n", p->vm.status);
		//error("get_vm_status=%s\n", get_vm_status(p->vm.name)==VM_ON?"on":"off");
		if (get_vm_status(p->vm.name) == VM_ON) {
		//if (strcmp(p->vm.status, "on") == 0) {
			for (int n=0; n<atoi(p->vm.nics); n++)
				if (strcmp(tap, p->vm.nic[n].tap) == 0) return;
		}
		p = p->next;
	}
	//error("clean %s\n", tap);
	run_bridge_command(DESTROY_TAP);
}

// 搜索ip地址来确定虚拟机
// 参数: ip不包含掩码
// 	 self所搜中需要排除的自己
int find_vm_by_ip(char *ip, find_vm_stru *result, vm_stru *self)
{
	vm_node *p = vms;
	while (p) {
		if (self == NULL || strcmp(p->vm.name, self->name) != 0) {
			for (int n = 0; n < atoi(p->vm.nics); n++) {
				char vm_ip[32];
				strcpy(vm_ip, p->vm.nic[n].ip);
				get_ip(vm_ip);

				if (strcmp(ip, vm_ip) == 0) {
					if (result) {
						strcpy(result->vm_name, p->vm.name);
						*result->nic_index = n;
					}
					return RET_SUCCESS;
				}
			}
		}
		p = p->next;
	}
	return RET_FAILURE;
}

// 显示所有虚拟机的端口转向列表
void vm_show_ports(int show_type, scan_redirect_port_stru *check)
{
	vm_node *p = vms;
	while(p) {
		scan_port(show_type, &p->vm, check);
		if (show_type == SP_VALID && *check->ret == RET_FAILURE)
			return;
		else
			p = p->next;
	}

}

// 扫描端口
int scan_port(int scan_type, vm_stru *vm, scan_redirect_port_stru *check)
{
	//对所有网卡进行扫描
	for (int n = 0; n < atoi(vm->nics); n++) {
		if (strcmp(vm->nic[n].netmode, "NAT") == 0 && strcmp(vm->nic[n].rpstatus, "enable") == 0) {

			switch (scan_type) {

			case SP_SHOW:
				show_port(vm, n);
				break;

			case SP_VALID:
				if (is_valid_port(vm, n, check) == RET_FAILURE) 
					return RET_FAILURE;
				break;

			default:
				break;

			}
		}
	}
	return RET_SUCCESS;
}

// 显示vm的端口转向
// tcp 172.16.1.3:80	-> 80
// udp 172.16.1.3:1194	-> 1194
void show_port(vm_stru *vm, int nic_index)
{
    static int header_printed = 0;
    int n = nic_index;
    char ip[32];
    char proto[PROTO_LEN];

    // 只打印一次表头
    if (!header_printed) {
        //printf("--------------------------------------------------------------\n");
        title("%-6s  %-20s  %-10s  %-s\n", "PROTO", "VM IP:PORT", "HOST PORT", "VM NAME");
        //printf("--------------------------------------------------------------\n");
        header_printed = 1;
    }

    for (int r = 0; r < vm->nic[n].rpnum; r++) {
        strcpy(ip, vm->nic[n].ip);
        get_ip(ip);
        strcpy(proto, vm->nic[n].ports[r].proto);
        
        // 构建 IP:PORT 字符串
        char ip_port[32];
        sprintf(ip_port, "%s:%d", ip, vm->nic[n].ports[r].vm_port);

        printf("%-6s  %-20s  %-10d  %-s\n",
            (strlen(proto) > 0) ? proto : "tcp",
            ip_port,
            vm->nic[n].ports[r].host_port,
            vm->name);
    }
}

// 端口号是否有效
// 检测端口号是否存在重复
int is_valid_port(vm_stru *vm, int nic_index, scan_redirect_port_stru *check)
{
	int n = nic_index;

	//排除本机，只对其他vm进行检测
	if (strcmp(vm->name, check->vm_name) == 0)
		return RET_SUCCESS;

	for (int r = 0; r < vm->nic[n].rpnum; r++) {
		if (strlen(vm->nic[n].ports[r].proto) == 0) 
			strcpy(vm->nic[n].ports[r].proto, "tcp");
		int f1 = (strcmp(check->port->proto, vm->nic[n].ports[r].proto) == 0);
		int f2 = (check->port->host_port == vm->nic[n].ports[r].host_port);

		if (f1 && f2) return *check->ret = RET_FAILURE;
	}

	return *check->ret = RET_SUCCESS;
}

// 启动vm
int vm_booting(autoboot_stru *boot)
{
	clock_t start, finish;
	start = clock();
	printf("%s booting...", boot->vm_name);
	vm_start(boot->vm_name);

	while (1) {
		finish = clock();
		double pass = (double)(finish - start) / CLOCKS_PER_SEC;
		if ((int)pass > boot->delay) {
			return 1;
		}
	}
}

// 自动启动vm
void vm_autoboot()
{
	int n = 0;
	gen_autoboot(&n);

	//按顺序依次启动
	for (int i=0; i<n; i++) {
		printf("%s, idx=%s, time=%s\n", boot[i]->vm.name, boot[i]->vm.bootindex, boot[i]->vm.bootdelay);
		autoboot_stru ab;
		ab.vm_name = boot[i]->vm.name;
		ab.delay = atoi(boot[i]->vm.bootdelay);
		//wait_exec((int*)vm_booting, (autoboot_stru*)&ab);
		wait_exec((fun)(int*)vm_booting, (autoboot_stru*)&ab);
	}
}

// 生成vm自动启动数组
void gen_autoboot(int *count)
{
	//vm_node *boot[MAX_BOOT_NUM] = {0};

	//生成autoboot数组
	int n = 0;
	vm_node *p = vms;
	while (p) {
		if (strcmp(p->vm.autoboot, "yes") == 0) {
			//printf("%s, idx=%s, time=%s\n", p->vm.name, p->vm.bootindex, p->vm.bootdelay);
			if (atoi(p->vm.bootindex) == 0) strcpy(p->vm.bootindex, "1");
			if (atoi(p->vm.bootdelay) == 0) strcpy(p->vm.bootdelay, "1");
			boot[n++] = p;
		}
		p = p->next;
	}

	//对启动vm按bootindex排序
	for (int i=0; i<n-1; i++) {
		if (strcmp(boot[i]->vm.autoboot, "no") == 0) continue;
		for (int j=i+1; j<n; j++) {
			if (strcmp(boot[j]->vm.autoboot, "no") == 0) continue;
			if (atoi(boot[i]->vm.bootindex) > atoi(boot[j]->vm.bootindex)) {
				vm_node *t;
				t = boot[i];
				boot[i] = boot[j];
				boot[j] = t;
			}
		}
	}
	
	*count = n;
}


// 输出自动启动vm列表
void vm_autoboot_list()
{
	int n = 0;
	gen_autoboot(&n);
	if (n == 0) return;

	printf("---------------------------------\n");
	printf("idx\tvm\t\ttime(sec)\n");
	printf("---------------------------------\n");
	
	for (int i=0; i<n; i++) {
		//printf("%s\t%s\t%s\n", boot[i]->vm.bootindex, boot[i]->vm.name, boot[i]->vm.bootdelay);
		printf("%s\t%s", boot[i]->vm.bootindex, boot[i]->vm.name);
		for (int t=0; t<(2-strlen(boot[i]->vm.name) / TABSTOP); t++) printf("\t");
		printf("%s\n", boot[i]->vm.bootdelay);
	}
}

// 新建vm
// template_vm_name为模板虚拟机名称
// opts为命令行配置选项(仅用于--create from场景)
void vm_create(char *vm_name, char *template_vm_name, create_opts_stru *opts)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) != NULL) {
		error("%s already exist\n", vm_name);
		return;
	}

	char template_path[FN_MAX_LEN] = {0};

	if (template_vm_name) {
		if (find_vm_list(template_vm_name) == NULL) {
			// Check if it is a template in /usr/local/etc/bvm/templates/
			sprintf(template_path, "/usr/local/etc/bvm/templates/%s.conf", template_vm_name);
			if (access(template_path, R_OK) != 0) {
				error("Template or VM '%s' does not exist\n", template_vm_name);
				return;
			}
		}
	}

	create_init();
	welcome();

	if (template_vm_name) {
		if (strlen(template_path) > 0)
			load_vm_config_from_path(template_path, &new_vm);
		else
			load_vm_info(template_vm_name, &new_vm);
		strcpy(new_vm.name, vm_name);
		// 清空模板的 UEFI vars 路径，让新 VM 首次启动时自动创建
		if (strlen(new_vm.uefi_vars) > 0) {
			strcpy(new_vm.uefi_vars, "");
		}
		// 清空所有网卡的 MAC 地址，让首次启动时自动生成
		// 避免从模板创建的 VM 与模板有相同的 MAC 地址
		for (int i = 0; i < atoi(new_vm.nics); i++) {
			strcpy(new_vm.nic[i].mac, "");
		}
		// 设置 CD-ROM 状态为 on
		strcpy(new_vm.cdstatus,"on");
		// 自动设置 boot from 为 cd0
		strcpy(new_vm.bootfrom, "cd0");
		// 自动设置 vncwait 为 on
		strcpy(new_vm.vncwait, "on");

		// 应用命令行参数覆盖模板配置
		if (opts) {
			// -s 启动类型为 grub
			if (opts->use_grub) {
				strcpy(new_vm.boot_type, "grub");
			}
			// -U=N CPU数量
			if (strlen(opts->cpus) > 0) {
				strcpy(new_vm.cpus, opts->cpus);
				// 同时更新 CPU 拓扑为默认值
				strcpy(new_vm.sockets, "1");
				strcpy(new_vm.cores, opts->cpus);
				strcpy(new_vm.threads, "1");
			}
			// -m=SIZE 内存大小
			if (strlen(opts->ram) > 0) {
				strcpy(new_vm.ram, opts->ram);
			}
			// -d=SIZE 第一块磁盘大小
			if (strlen(opts->disk_size) > 0) {
				strcpy(new_vm.vdisk[0].size, opts->disk_size);
			}
			// -n=MODE 网络模式
			if (strlen(opts->netmode) > 0) {
				strcpy(new_vm.nic[0].netmode, opts->netmode);
				// 如果是 Bridged 模式，清空 NAT 设置
				if (strcmp(opts->netmode, "Bridged") == 0) {
					strcpy(new_vm.nic[0].nat, "");
				}
			}
			// -i=NIC 绑定网卡
			if (strlen(opts->bind_nic) > 0) {
				strcpy(new_vm.nic[0].bind, opts->bind_nic);
			}
		}

		edit_vm(NULL);
	}
	else
		enter_vm(vm_name);

	//新建vm文件夹
	char dir[FN_MAX_LEN];
	sprintf(dir, "%s%s", vmdir, new_vm.name);
	if (mkdir(dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1) {
		error("%s already exist\n", dir);
		err_exit();
	}

	//生成vm配置文件
	save_vm_info(new_vm.name, &new_vm);

	//生成device.map
	if (write_vm_device_map(&new_vm) == RET_FAILURE) {
		error("creating device_map failure\n");
		err_exit();
	}

	//生成disk.img
	create_vm_disk_all(&new_vm);

	//为 UEFI VM 创建 vars 文件
	if (strcmp(new_vm.boot_type, "grub") != 0) {
		char template_vars[] = "/usr/local/share/uefi-firmware/BHYVE_UEFI_VARS.fd";
		char vm_vars[256];
		sprintf(vm_vars, "%s%s/efivars.fd", vmdir, new_vm.name);
		
		// 检查模板文件是否存在
		if (access(template_vars, R_OK) == 0) {
			// 复制模板文件到 VM 目录
			char cmd[512];
			sprintf(cmd, "cp %s %s", template_vars, vm_vars);
			if (system(cmd) == 0) {
				strcpy(new_vm.uefi_vars, vm_vars);
				save_vm_info(new_vm.name, &new_vm);
				write_log("Created UEFI vars file for %s", new_vm.name);
			} else {
				warn("Failed to create UEFI vars file, will use legacy mode\n");
			}
		} else {
			warn("UEFI vars template not found, will use legacy mode\n");
		}
	}
}

// 创建虚拟机中所有磁盘
// 根据虚拟机中磁盘数量而确定
void create_vm_disk_all(vm_stru *vm)
{
	int zfs = 0;
	if (support_zfs() && strcmp(vm->zfs, "on") == 0) zfs = 1;

	for (int n=0; n<atoi(vm->disks); n++) {
		if (zfs)
			create_zfs_disk(vm, n);
		else
			create_vm_disk(vm, n);
	}
}

// 创建vm磁盘文件
// vm:虚拟机
// disk_ord:盘号
void create_vm_disk(vm_stru *vm, int disk_ord)
{
	char fn[FN_MAX_LEN];
	char cmd[BUFFERSIZE];
	char disk[32];
	//int offset = &vm->img1size - &vm->imgsize;
	int n = disk_ord;

	if (n == 0)
		strcpy(disk, "/disk.img");
	else
		sprintf(disk, "/disk%d.img", n);
	sprintf(fn, "%s%s%s", vmdir, vm->name, disk);
	
	if (access(fn, 0) == -1) {
		//truncate -s [+|-]size[K|k|M|m|G|g|T|t] file
		//sprintf(cmd, "truncate -s %s %s", (char*)(&vm->imgsize + n * offset), fn);
		sprintf(cmd, "truncate -s %s %s", vm->vdisk[n].size, fn);
		run_cmd(cmd);
	}
}

// 调整虚拟机中全部磁盘大小
// 调整的依据是new_vm中的参数
void adjust_vm_disk_all(vm_stru *vm)
{
	//int offset = &vm->img1size - &vm->imgsize;
	for (int n=0; n<atoi(vm->disks); n++) {
		//adjust_vm_disk(vm, (char*)(&new_vm.imgsize + n * offset), n);
		adjust_vm_disk(vm, new_vm.vdisk[n].size, n);
	}
	
}


// 调整vm磁盘大小
// vm:虚拟机
// size:调整后的磁盘空间大小
// disk_ord:盘号
void adjust_vm_disk(vm_stru *vm, char *size, int disk_ord)
{
	int n = disk_ord;
	/*
	int step = &vm->img1size - &vm->imgsize; 
	char *p = (char*)(&vm->imgsize + n * step);
	char *newp = (char*)(&new_vm.imgsize + n * step);
	*/
	char *p = vm->vdisk[n].size;
	char *newp = new_vm.vdisk[n].size;
	long offset;
	offset = imgsize_cmp(size, p);//vm->imgsize);	
	if (offset == 0) return;

	// 如果是 ZFS 磁盘，使用 ZFS 命令调整
	if (support_zfs() && strcmp(vm->zfs, "on") == 0) {
		if (offset > 0) {
			// ZFS 扩容确认
			warn("NOTE: After expanding the disk, you need to:\n");
			warn("  1. Fix the partition table (e.g., GPT backup header)\n");
			warn("  2. Resize the partition to use the new space\n");
			warn("  3. Extend the filesystem\n");
			warn("Refer to your guest OS documentation for specific commands.\n");
			WARN("Enter 'YES' to confirm expanding disk(%d) from %s to %s: ", n, p, newp);
			
			char confirm[16];
			fgets(confirm, sizeof(confirm), stdin);
			confirm[strlen(confirm)-1] = '\0';
			
			if (strcmp(confirm, "YES") != 0) {
				warn("Disk expand cancelled\n");
				strcpy(newp, p);  // 恢复原始大小
				return;
			}
		}
		if (offset < 0) {
			// ZFS 压缩需要警告
			warn("WARNING: Reducing ZFS volume size may cause data loss!\n");
			warn("Make sure you have shrunk the partition inside the VM first.\n");
			WARN("Enter 'YES' to confirm shrinking disk(%d) from %s to %s: ", n, p, newp);
			
			char confirm[16];
			fgets(confirm, sizeof(confirm), stdin);
			confirm[strlen(confirm)-1] = '\0';
			
			if (strcmp(confirm, "YES") != 0) {
				warn("Disk shrink cancelled\n");
				strcpy(newp, p);  // 恢复原始大小
				return;
			}
		}
		resize_zfs_disk(vm, newp, n);
		return;
	}

	char disk[32];
	if (n == 0)
		strcpy(disk, "/disk.img");
	else
		sprintf(disk, "/disk%d.img", n);

	char fn[FN_MAX_LEN]; 
	sprintf(fn, "%s%s%s", vmdir, vm->name, disk);

//	char fn[FN_MAX_LEN];
//	sprintf(fn, "%s%s%s", vmdir, vm->name, "/disk.img");
	if (access(fn, 0) == 0) {
		char cmd[BUFFERSIZE];
		if (offset > 0) {
			// 磁盘扩容 - 确认
			warn("\n");
			warn("NOTE: After expanding the disk, you need to:\n");
			warn("  1. Fix the partition table (e.g., GPT backup header)\n");
			warn("  2. Resize the partition to use the new space\n");
			warn("  3. Extend the filesystem\n");
			warn("Refer to your guest OS documentation for specific commands.\n");
			WARN("Enter 'YES' to confirm expanding disk(%d) from %s to %s: ", n, p, newp);
			
			char confirm[16];
			fgets(confirm, sizeof(confirm), stdin);
			confirm[strlen(confirm)-1] = '\0';
			
			if (strcmp(confirm, "YES") == 0) {
				sprintf(cmd, "truncate -s %s%ld%s %s", "+", offset, "K", fn);
				run_cmd(cmd);
			} else {
				warn("Disk expand cancelled\n");
				strcpy(newp, p);  // 恢复原始大小
			}
		}
		if (offset < 0) {
			// 磁盘压缩 - 需要确认
			warn("\n");
			warn("WARNING: Reducing disk size may cause data loss!\n");
			warn("Make sure you have shrunk the partition inside the VM first.\n");
			WARN("Enter 'YES' to confirm shrinking disk(%d) from %s to %s: ", n, p, newp);
			
			char confirm[16];
			fgets(confirm, sizeof(confirm), stdin);
			confirm[strlen(confirm)-1] = '\0';
			
			if (strcmp(confirm, "YES") == 0) {
				// 使用绝对大小
				sprintf(cmd, "truncate -s %s %s", newp, fn);
				run_cmd(cmd);
			} else {
				warn("Disk shrink cancelled\n");
				strcpy(newp, p);  // 恢复原始大小
			}
		}
	}


}



// 比较两个磁盘文件的大小
// 以k为计算单位
long imgsize_cmp(char *size1, char *size2)
{
	long sz1 = disk_size_to_kb(size1);
	long sz2 = disk_size_to_kb(size2);

	return (sz1 - sz2);
}

// 转换磁盘文件容量为单位K
long disk_size_to_kb(char *size)
{
	long base;
	switch (tolower(lastch(size))) {
	case 'k':
		base = 1;
		break;
	case 'm':
		base = 1024;
		break;
	case 'g':
		base = 1024 * 1024;
		break;
	case 't':
		base = 1024 * 1024 * 1024;
		break;
	default:
		break;
	}
	int n = 0;
	int vol = 0;
	char ch;
	while ((ch = size[n])) {
		if (ch >= '0' && ch <= '9') {
			vol = vol * 10 + ch - '0';
			++n;
		}
		else 
			break;
	}
	return base * vol;
}

// 所有磁盘容量合计
double total_disk_size(vm_stru *vm)
{
	long total = 0;
	for (int n=0; n<atoi(vm->disks); n++) {
		//total += disk_size_to_kb(&vm->imgsize + n * disk_offset(vm));
		total += disk_size_to_kb(vm->vdisk[n].size);
	}
	return (double)total;
}

// 存储单位转换
// n:输入KB
// flag_int:是否需要整数
// save:输出最适合的单位
void unit_convert(double n, int flag_int, char *save)
{
	char *unit = "kmgt";
	static int base = 0;

	if (n >= 1024) {
		++base;
		unit_convert(n / 1024, flag_int, save);
	}
	else {
		if (save)
			if (flag_int && is_integer(n))
				sprintf(save, "%d%c", (int)n, *(unit+base));
			else
				sprintf(save, "%.1f%c", n, *(unit+base));
		else
			if (flag_int && is_integer(n))
				printf("%d%c", (int)n, *(unit+base));
			else
				printf("%.1f%c", n, *(unit+base));
		base = 0;
	}
}

// 判断浮点数是否为整数
// 返回1 是整数
// 返回0 不是整数
int is_integer(double num)
{
	const double delta = 1e-5;
	int x = num;
	double diff = num - x;

	if (diff > -delta && diff < delta)
		return 1;
	else
		return 0;
}

// 编辑vm
void vm_config(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
		select_vm(vm_name, VM_OFF);
		p = find_vm_list(vm_name);
	}
	if (get_vm_status(vm_name) == VM_ON) {
		error("%s is running, cannot edit\n", vm_name);
		return;
	}
	if (atoi(p->vm.lock)) {
		error("%s has been locked up\n", vm_name);
		return;
	}

	create_init();
	welcome();

	load_vm_info(vm_name, &new_vm);
	edit_vm(vm_name);


	//保存device.map
	if (write_vm_device_map(&new_vm) == RET_FAILURE) {
		error("creating device_map failure\n");
		err_exit();
	}

	//调整disk.img
	adjust_vm_disk_all(&p->vm);//, new_vm.imgsize);
	create_vm_disk_all(&new_vm);
	
	//保存vm配置文件
	save_vm_info(new_vm.name, &new_vm);
}

// 检查VNC端口冲突
// 返回值: 0 无冲突, -1 有冲突
int check_vnc_port_conflict(char *vm_name, vm_stru *vm)
{
	// 如果VNC未开启，无需检查
	if (strcmp(vm->vncstatus, "on") != 0) 
		return 0;
	
	vm_node *p = vms;
	while (p) {
		// 跳过自己
		if (strcmp(p->vm.name, vm_name) == 0) {
			p = p->next;
			continue;
		}
		
		// 检查是否正在运行且VNC已开启
		if (get_vm_status(p->vm.name) == VM_ON && 
			strcmp(p->vm.vncstatus, "on") == 0) {
			// 比较端口号
			if (strcmp(p->vm.vncport, vm->vncport) == 0) {
				// 端口相同，进一步检查绑定地址
				char *bind1 = strlen(vm->vncbind) > 0 ? vm->vncbind : "0.0.0.0";
				char *bind2 = strlen(p->vm.vncbind) > 0 ? p->vm.vncbind : "0.0.0.0";
				
				// 如果绑定地址相同，或者其中一个绑定到 0.0.0.0（所有接口），则冲突
				if (strcmp(bind1, bind2) == 0 || 
					strcmp(bind1, "0.0.0.0") == 0 || 
					strcmp(bind2, "0.0.0.0") == 0) {
					error("VNC port %s on %s conflicts with running VM '%s' on %s\n", 
						vm->vncport, bind1, p->vm.name, bind2);
					return -1;
				}
			}
		}
		p = p->next;
	}
	return 0;
}

// 启动vm
void vm_start(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
		select_vm(vm_name, VM_OFF);
		p = find_vm_list(vm_name);
	}

	if (get_vmx(&p->vm) != 1) {
		error("This machine does not support virtualization.\n");
		return;
	}

	if (get_vm_status(vm_name) == VM_ON) {
		error("%s is running\n", vm_name);
		return;
	}

	if (atoi(p->vm.lock)) {
		error("%s has been locked up, cannot run\n", vm_name);
		return;
	}

	if (atoi(p->vm.crypt)) {
		error("%s has been encrypted, cannot run\n", vm_name);
		return;
	}

	// 检查VNC端口冲突
	if (check_vnc_port_conflict(vm_name, &p->vm) != 0) {
		return;
	}

	if (strcmp(p->vm.cdstatus, "on") == 0 && access(p->vm.iso, 0) == -1) {
		error("%s not found, cannot run\n", p->vm.iso);
		return;
	}

	int ret = create_networking(vm_name) == RET_SUCCESS && 
		  gen_vm_start_code(vm_name) == RET_SUCCESS;

	if (ret) {
		char shell[FN_MAX_LEN];
		sprintf(shell, "/usr/local/bin/tmux -2 -u new -d -s %s \"bvmb %s\"", vm_name, vm_name);
		run_cmd(shell);

		//等待虚拟机启动成功
		waitting_boot(vm_name);

		//开启dhcp服务
		if (bvm_get_pid("bvmdhcp") == -1) {
			char *fn = "/usr/local/bin/bvmdhcp";
			char *arg = "9250b212ea95c6897aeef888c0b6611c18682957";
			sprintf(shell, "/usr/local/bin/tmux -2 -u new -d -s bvmdhcp %s %s", fn, arg);
			run_cmd(shell);
		}

	}
	else  {
		error("failed to start %s\n", vm_name);
	}
}

// 登陆vm
void vm_login(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ON);
		return;
		select_vm(vm_name, VM_ON);
		p = find_vm_list(vm_name);
	}

	// bhyve 现在虽已经支持 uefi 控制台登录，但还是用vnc登录比较稳定，
	// 有的系统是完全可以控制台登录，但有的系统则不行
	// 这里做一个警告不保证控制台登录能成功,windows禁止登录
	if (strcmp(p->vm.boot_type, "grub") != 0) {
		char ostype_temp[32];
		strncpy(ostype_temp, p->vm.ostype, sizeof(ostype_temp) - 1);
		ostype_temp[sizeof(ostype_temp) - 1] = '\0';

		if (strstr(strtolower(ostype_temp), "win") != NULL) {
			warn("Windows does not support console login.\n");
			warn("Please use VNC to login.\n");
		}
		else {
			warn("UEFI mode may not support console login.\n");
			warn("If login fails, please use VNC or SSH to login.\n");
			sleep(1);
		}
	}

	if (get_vm_status(vm_name) == VM_ON) { 
		char cmd[CMD_MAX_LEN];
		sprintf(cmd, "tmux attach-session -t %s", vm_name);
		run_cmd(cmd);
	}
	else {
		error("%s is not running\n", vm_name);
	}
}

// vm关机处理
void vm_stop(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ON);
		return;
		select_vm(vm_name, VM_ON);
		p = find_vm_list(vm_name);
	}

	if (get_vm_status(vm_name) == VM_ON) {
		
		setvbuf(stdout, NULL, _IONBF, 0);
		printf("shutting down ...");

		// 向vm发送信号15，vm做出关机处理
		// Shutting down ...
		char cmd[CMD_MAX_LEN];
		int pid = get_vm_pid(&p->vm);	
		//warn("pid=%d\n", pid);

		if (pid < 0) {
			warn("\nVM '%s' cannot be stopped. Please try again later or use 'bvm --poweroff %s' to force stop.\n", vm_name, vm_name);
			return;
		}
		sprintf(cmd, "kill 15 %d", pid);
		run_cmd(cmd);

		//等待vm进程消失
		sprintf(cmd, "ps | grep %d | grep -v grep", pid);
		//printf("wait=%s\n", cmd);
		//int ret = wait_exec((int*)check_shutdown, cmd);
		int ret = wait_exec((fun)(int*)check_shutdown, cmd);
		printf("\033[1A");
		if (ret == 0) { //成功
			delay(1);
			if (get_vm_status(vm_name) == VM_ON) {
				//warn("run poweroff\n");
				vm_poweroff(vm_name, 0);
			}
			//update_vm_status(vm_name, VM_OFF);
		}
		if (ret == -1) { //超时
			warn("\nit's out of time, use 'bvm --poweroff %s' to stop", vm_name);
		}
		printf("\n");
	}
	else {
		error("%s is not running\n", vm_name);
	}
}

// 检查关机
int check_shutdown(char *cmd)
{
	clock_t start, finish;
	start = clock();
	while (1) {
		char buf[16];
		FILE *fp = popen(cmd, "r");
		if (fgets(buf, 16, fp)) {
			pclose(fp);
		}
		else {
			pclose(fp);
			return 0;
		}

		finish = clock();
		//long pass = finish - start;
		double pass = (double)(finish - start) / CLOCKS_PER_SEC;
		//printf("%lf\n", pass);
		if ((int)pass > 10) {
			return -1;
		}
	}

}

// 等待启动成功
int waitting_boot(char *vm_name)
{
	while (1) {
		if (get_vm_status(vm_name) == VM_ON) return 1;
	}
}

// 删除tmux session
// 仅用于vm无法正常启动后，执行 --poweroff 后的清理
void vm_killsession(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		// 静默返回，因为 vm_poweroff 已经输出过错误信息了
		//error("%s does not exist\n", vm_name);
		//show_vm_name(VM_ON);
		return;
	}

	if (get_vm_status(vm_name) == VM_ON) {
		error("%s is running...\n", vm_name);
		return;
	}

	char cmd[CMD_MAX_LEN];
	//删除tmux窗口
	if (strcmp(p->vm.boot_type, "grub") == 0) {
		sprintf(cmd, "tmux kill-session -t %s >> /dev/null 2>&1", vm_name);
		run_cmd(cmd);
	}
	
	//杀掉bvmb进程
	sprintf(cmd, "ps | grep -w \"bvmb %s\" | grep -v \"c bvmb %s\" | grep -v grep | awk '{print $1}' | xargs kill", vm_name, vm_name);
	run_cmd(cmd);
}

// 关闭电源
void vm_poweroff(char *vm_name,int flag_msg)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ON);
		return;
		select_vm(vm_name, VM_ON);
		p = find_vm_list(vm_name);
	}

	char cmd[CMD_MAX_LEN];
	if (get_vm_status(vm_name) == VM_ON) {
		sprintf(cmd, "/usr/sbin/bhyvectl --force-poweroff --vm=%s", vm_name);
		run_cmd(cmd);

		//给 --force-poweroff 一秒钟的处理时间
		//避免下面执行 --destroy 时发生错误
		//Give --force-poweroff a one-second processing time 
		//to avoid an error when executing --destroy below
		delay(1);
		
		if (get_vm_status(vm_name) == VM_ON) {
			sprintf(cmd, "/usr/sbin/bhyvectl --destroy --vm=%s", vm_name);
			run_cmd(cmd);
		}
		//删除tmux窗口
		if (strcmp(p->vm.boot_type, "grub") == 0) {
			sprintf(cmd, "tmux kill-session -t %s", vm_name);
			//run_cmd(cmd);
		}
		//删除tap
		/*
		for (int n=0; n<atoi(p->vm.nics); n++) {
			sprintf(cmd, "ifconfig %s destroy", p->vm.nic[n].tap);
			run_cmd(cmd);
		}
		*/
	}
	else {
		if (flag_msg) 
			error("%s is not running\n", vm_name);
	}
}


// 重启vm
void vm_restart(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ON);
		return;
		select_vm(vm_name, VM_ON);
		p = find_vm_list(vm_name);
	}

	if (get_vm_status(vm_name) == VM_ON) {
		char cmd[CMD_MAX_LEN];
		sprintf(cmd, "/usr/sbin/bhyvectl --force-reset --vm=%s", vm_name);
		run_cmd(cmd);
	}
	else {
		error("%s is not running\n", vm_name);
	}
}

// 输出vm配置文件信息(完整版)
void vm_info_all(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ALL);
		return;
		select_vm(vm_name, VM_ALL);
		p = find_vm_list(vm_name);
	}

	welcome();

	char str[BUFFERSIZE];
	printf("%-13s = %s\n", 	"vm_name", 	p->vm.name);
	printf("%-13s = %s\n", 	"vm_profile", 	p->vm.profile);
	printf("%-13s = %s\n",	"vm_disks", 	p->vm.disks);
	for (int n=0; n<atoi(p->vm.disks); n++) {
		sprintf(str, "vm_disk%d_name", n);
		printf("%-13s = %s\n", str,	p->vm.vdisk[n].name);
		sprintf(str, "vm_disk%d_size", n);
		printf("%-13s = %s\n", str,	p->vm.vdisk[n].size);
		sprintf(str, "vm_disk%d_path", n);
		printf("%-13s = %s\n", str,	p->vm.vdisk[n].path);
	}
	printf("%-13s = %s\n",	"vm_zfs", 	p->vm.zfs);
	printf("%-13s = %s\n",	"vm_zpool", 	p->vm.zpool);
	printf("%-13s = %s\n",	"vm_ram", 	p->vm.ram);
	printf("%-13s = %s\n",	"vm_cpus", 	p->vm.cpus);
	printf("%-13s = %s\n",	"vm_sockets", 	p->vm.sockets);
	printf("%-13s = %s\n",	"vm_cores", 	p->vm.cores);
	printf("%-13s = %s\n",	"vm_threads", 	p->vm.threads);
	printf("\n");
	printf("%-13s = %s\n",	"vm_ostype", 	p->vm.ostype);
	printf("%-13s = %s\n",	"vm_version", 	p->vm.version);
	printf("%-13s = %s\n",	"vm_cdstatus", 	p->vm.cdstatus);
	printf("%-13s = %s\n",	"vm_cds", 	p->vm.cds);
	for (int n=0; n<atoi(p->vm.cds); n++) {
		char t[32];
		sprintf(t, "vm_cd%d_iso", n);
		printf("%-13s = %s\n", t, p->vm.cd_iso[n]);
	}
	printf("%-13s = %s\n",	"vm_bootfrom", 	p->vm.bootfrom);
	printf("%-13s = %s\n",	"vm_hostbridge",p->vm.hostbridge);
	printf("%-13s = %s\n",	"vm_boot_type",	p->vm.boot_type);
	printf("%-13s = %s\n",	"vm_tpmstatus",p->vm.tpmstatus);
	printf("%-13s = %s\n",	"vm_tpmversion",p->vm.tpmversion);
	printf("%-13s = %s\n",	"vm_tpmpath",p->vm.tpmpath);

	printf("%-13s = %s\n",	"vm_share_status",p->vm.share_status);
	printf("%-13s = %s\n",	"vm_share_name",p->vm.share_name);
	printf("%-13s = %s\n",	"vm_share_path",p->vm.share_path);
	printf("%-13s = %s\n",	"vm_share_ro",p->vm.share_ro);

	printf("%-13s = %s\n",	"vm_audiostatus",p->vm.audiostatus);
	printf("%-13s = %s\n",	"vm_disk",	p->vm.disk);
	printf("%-13s = %s\n",	"vm_devicemap",	p->vm.devicemap);
	printf("%-13s = %s\n",	"vm_grubcmd",	p->vm.grubcmd);
	printf("\n");
	printf("%-13s = %s\n",	"vm_nics",	p->vm.nics);
	for (int n=0; n<atoi(p->vm.nics); n++) {
		sprintf(str, "vm_nic%d_netmode", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].netmode);
		sprintf(str, "vm_nic%d_nat", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].nat);
		sprintf(str, "vm_nic%d_rpstatus", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].rpstatus);
		sprintf(str, "vm_nic%d_rplist", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].rplist);
		sprintf(str, "vm_nic%d_bind", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].bind);
		sprintf(str, "vm_nic%d_bridge", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].bridge);
		sprintf(str, "vm_nic%d_tap", n);
		printf("%-13s = %s\n",	str,	p->vm.nic[n].tap);
		sprintf(str, "vm_nic%d_ip", n);
		printf("%-13s = %s",	str,	p->vm.nic[n].ip);
		// 显示 DHCP 分配的 IP（如果是 NAT 模式且 VM 正在运行）
		if (strcmp(p->vm.nic[n].netmode, "NAT") == 0 && get_vm_status(p->vm.name) == VM_ON) {
			char dhcp_ip[32];
			if (get_ip_from_dhcp_pool(p->vm.nic[n].mac, dhcp_ip) == RET_SUCCESS) {
				printf(" (DHCP: \033[96m%s\033[0m)", dhcp_ip);
			}
		}
		printf("\n");
	}
	

	printf("\n");
	printf("%-13s = %s\n",	"vm_vncstatus",	p->vm.vncstatus);
	printf("%-13s = %s\n",	"vm_vncbind",	p->vm.vncbind);
	printf("%-13s = %s\n",	"vm_vncport",	p->vm.vncport);
	printf("%-13s = %s\n",	"vm_vncwidth",	p->vm.vncwidth);
	printf("%-13s = %s\n",	"vm_vncheight",	p->vm.vncheight);
	printf("%-13s = %s\n",	"vm_vncwait",	p->vm.vncwait);
	printf("%-13s = %s\n",	"vm_vncpassword",	p->vm.vncpassword);
	printf("\n");
	printf("%-13s = %s\n",	"vm_autoboot",	p->vm.autoboot);
	printf("%-13s = %s\n",	"vm_bootindex",	p->vm.bootindex);
	printf("%-13s = %s\n",	"vm_bootdelay",	p->vm.bootdelay);
	printf("\n");
	printf("%-13s = ",	"vm_status");
	if (get_vm_status(p->vm.name) == VM_ON)  printf("on\n");
	if (get_vm_status(p->vm.name) == VM_OFF) printf("off\n");
	printf("%-13s = %s\n",	"vm_lock",	p->vm.lock);

}


// 输出vm配置资料
void vm_info(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ALL);
		return;
		select_vm(vm_name, VM_ALL);
		p = find_vm_list(vm_name);
	}

	welcome();
	printf("%-14s : \033[4m%s\n\033[0m", "name", 	p->vm.name);
	printf("%-14s : %s\n", "os type", p->vm.ostype);
	if (strlen(p->vm.version) > 0)
		printf("%-14s : %s\n", "version", 	p->vm.version);	
	printf("%-14s : %s\n", "ram", 			p->vm.ram);
	printf("%-14s : %s\n", "cpus", 			p->vm.cpus);
	printf("|-%-12s : %s\n", "sockets", 	p->vm.sockets);
	printf("|-%-12s : %s\n", "cores", 		p->vm.cores);
	printf("|-%-12s : %s\n", "threads", 	p->vm.threads);
	printf("%-14s : %s\n", "disk interface",	p->vm.storage_interface);
	printf("%-14s : %s\n", "disk numbers",		p->vm.disks);

	if (support_zfs()) {
		printf("|-%-12s : %s\n", "ZFS support",	p->vm.zfs);
		if( strcmp(p->vm.zfs, "on") == 0) {
			printf("|-%-12s : %s\n", "zpool",	p->vm.zpool);
		}
	}
	for (int n=0; n<atoi(p->vm.disks); n++) {
		char t[32];
		sprintf(t, "disk(%d) size", n);
		printf("|-%-12s : %s\n", t,              p->vm.vdisk[n].size);
	}

	/*
	//------------
	int offset = &p->vm.img1size - &p->vm.imgsize;
	for (int n=0; n<atoi(p->vm.disks); n++) {
		char t[32];
		sprintf(t, "disk(%d) size", n);
		printf("|-%-11s: %s\n", t, 		(char*)(&p->vm.imgsize + n * offset));
	}
	//------------
	*/

	printf("%-14s : %s\n", "cd status", 		p->vm.cdstatus);
	if (strcmp(p->vm.cdstatus, "on") == 0) {
		printf("|-%-12s : %s\n", "cd numbers",	p->vm.cds);
		for (int n=0; n<atoi(p->vm.cds); n++) {
			char t[32];
			sprintf(t, "cd(%d) iso", n);
			printf("|-%-12s : %s\n", t, p->vm.cd_iso[n]);
		}
	}
	printf("%-14s : %s\n", "boot from", 		p->vm.bootfrom);
	printf("%-14s : %s\n", "hostbridge", 		p->vm.hostbridge);
	printf("%-14s : %s\n", "boot type", 			p->vm.boot_type);
	if (support_uefi(p->vm.ostype) && strcmp(p->vm.boot_type, "grub") != 0) {
		printf("|-%-12s : %s\n", "vnc status", 	p->vm.vncstatus);
		printf("|-%-12s : %s\n", "vnc bind", 	p->vm.vncbind);
		printf("|-%-12s : %s\n", "vnc port", 	p->vm.vncport);
		printf("|-%-12s : %s\n", "width", 	p->vm.vncwidth);
		printf("|-%-12s : %s\n", "height", 	p->vm.vncheight);
		printf("|-%-12s : %s\n", "wait", 	p->vm.vncwait);
		printf("|-%-12s : %s\n", "password", 	p->vm.vncpassword);
		printf("|-%-12s : %s\n", "audio", 	p->vm.audiostatus);
		printf("|-%-12s : %s\n", "tpm status", 	p->vm.tpmstatus);
		if (strcmp(p->vm.tpmstatus, "on") == 0) {
			printf("|-%-12s : %s\n", "tpm version", 	p->vm.tpmversion);
		}
	}

	printf("%-14s : %s\n", "shared folder", 		p->vm.share_status);
	if (strcmp(p->vm.share_status, "on") == 0) {
		printf("|-%-12s : %s\n", "share name", 	p->vm.share_name);
		printf("|-%-12s : %s\n", "share path", 	p->vm.share_path);
		printf("|-%-12s : %s\n", "read-only", 	p->vm.share_ro);
	}

	printf("%-14s : %s\n", "auto boot",		p->vm.autoboot);
	if (strcmp(p->vm.autoboot, "yes") == 0) {
		printf("|-%-12s : %s\n", "index",	p->vm.bootindex);
		printf("|-%-12s : %s sec.\n", "time",	p->vm.bootdelay);
	}

	printf("%-14s : %s\n", "nic interface",		p->vm.network_interface);
	printf("%-14s : %s\n", "nic numbers", 		p->vm.nics);
	for (int n=0; n<atoi(p->vm.nics); n++) {
		printf("%s\n", p->vm.nic[n].name);
		printf("|-%-12s : %s\n", "network mode",		p->vm.nic[n].netmode);
		if (strcmp(p->vm.nic[n].netmode, "NAT") == 0) {
			printf("|-%-12s : %s\n", "wan",		p->vm.nic[n].bind);
			printf("|-%-12s : %s", "gateway", 		p->vm.nic[n].nat);
			get_nat_info(p->vm.nic[n].nat);
			printf(" [GW %s]\n", nat.ip);
			printf("|-%-12s : %s\n", "redirect",	p->vm.nic[n].rpstatus);
			if (strcmp(p->vm.nic[n].rpstatus, "enable") == 0) {
				for (int m=0; m<p->vm.nic[n].rpnum; m++) {
					char t[16];
					sprintf(t, "port(%d)", m);
					printf("  |-%-10s : %s %d:%d\n", t, 	p->vm.nic[n].ports[m].proto,	
										p->vm.nic[n].ports[m].vm_port, 
									      	p->vm.nic[n].ports[m].host_port);
				}
				//printf("  |-%-9s : %s\n", "ports",	p->vm.nic[n].rplist);
				//printf("  |-%-9s : %s\n", "bind",	p->vm.nic[n].bind);
			}
		}
		if (strcmp(p->vm.nic[n].netmode, "Bridged") == 0) {	
			//printf("|-%-11s : %s", "bind",        p->vm.nic[n].bind);
			get_switch_info(p->vm.nic[n].bind);
			if (strstr(p->vm.nic[n].bind, "switch") && strlen(Switch.ip) > 0)
				printf(" [GW %s]\n", Switch.ip);
			//printf("\n");
		}
		if (strlen(p->vm.nic[n].bridge) > 0)
			printf("|-%-12s : %s\n", "switch",	p->vm.nic[n].bridge);
		if (strlen(p->vm.nic[n].tap) > 0)
			printf("|-%-12s : %s\n", "device",	p->vm.nic[n].tap);
		printf("|-%-12s : %s", "ip", 		p->vm.nic[n].ip);
		// 显示 DHCP 分配的 IP（如果是 NAT 模式且 VM 正在运行）
		if (strcmp(p->vm.nic[n].netmode, "NAT") == 0 && get_vm_status(p->vm.name) == VM_ON) {
			char dhcp_ip[32];
			if (get_ip_from_dhcp_pool(p->vm.nic[n].mac, dhcp_ip) == RET_SUCCESS) {
				printf(" (DHCP: \033[96m%s\033[0m)", dhcp_ip);
			}
		}
		printf("\n");
		printf("|-%-12s : %s\n", "mac", 		p->vm.nic[n].mac);
	}



	printf("%-14s : ",     "status");
	if (get_vm_status(p->vm.name) == VM_ON)  printf("on\n");
	if (get_vm_status(p->vm.name) == VM_OFF) printf("off\n");
	printf("%-14s : %s\n", "lock", !strcmp(p->vm.lock, "1")?"yes":"no");
	printf("%-14s : %s\n", "crypt", !strcmp(p->vm.crypt, "1")?"yes":"no");
	
}

// 设置vm从hd启动
void vm_boot_from_hd(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s does not exist\n", vm_name);
		show_vm_name(VM_ALL);
		return;
		select_vm(vm_name, VM_ALL);
		p = find_vm_list(vm_name);
	}

	// 设置从hd启动
	strcpy(p->vm.bootfrom, "hd0");
	// 多 CD 模式：保持光驱有效，仅切换启动介质到硬盘
	// 用户可以随时挂载资料 ISO 使用

	// 如果是 UEFI 模式，安装完成后通常无需等待 VNC 连接
	if (strcmp(p->vm.boot_type, "grub") != 0) {
		strcpy(p->vm.vncwait, "off");
	}

	save_vm_info(vm_name, &p->vm);
}

void get_vm_name(char *dir)
{
	DIR *dp;
	struct dirent *dirp;

	if ((dp = opendir(dir)) == NULL) {
		error("cannot open %s\n", dir);
		return;
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (dirp->d_type == DT_DIR)
			if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0)
				continue;
		
		//printf("%s\n", dirp->d_name);
		if (check_vm_files(dirp->d_name) == RET_SUCCESS)
			add_to_vm_list(dirp->d_name);
    }

    closedir(dp);
}

// 克隆vm
int vm_clone(char *src_vm_name, char *dst_vm_name)
{
	vm_node *p_src;	
	vm_node *p_dst;
	if ((p_src = find_vm_list(src_vm_name)) == NULL) {
		error("%s not exist\n", src_vm_name);
		show_vm_name(VM_OFF);
		return RET_FAILURE;
	}
	if ((p_dst = find_vm_list(dst_vm_name)) != NULL) {
		error("%s already existed\n", dst_vm_name);
		return RET_FAILURE;
	}
	if (get_vm_status(src_vm_name) == VM_ON) {
		error("%s is running, cannot clone\n", src_vm_name);
		return RET_FAILURE;
	}
	if (atoi(p_src->vm.lock)) {
		error("%s has been locked up\n", src_vm_name);
		return RET_FAILURE;
	}

	printf("cloning ... ");

	//新建vm文件夹
	char dir[FN_MAX_LEN];
	sprintf(dir, "%s%s", vmdir, dst_vm_name);
	if (mkdir(dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1)
		return RET_FAILURE;

	//生成vm配置文件
	vm_stru vm;
	load_vm_info(src_vm_name, &vm);
	
	strcpy(vm.name, dst_vm_name);

	char str[FN_MAX_LEN];
	sprintf(str, "%s%s%s", vmdir, dst_vm_name, "/disk.img");
	strcpy(vm.disk, str);

	sprintf(str, "%s%s%s", vmdir, dst_vm_name, "/device.map");
	strcpy(vm.devicemap, str);

	// 克隆源 VM 的 UEFI vars 文件
	// 由于 booter.c 中设备 slot 固定（HD 在 slot 2，CD 在 HD 之后），
	// 克隆后的 VM 设备路径与源 VM 相同，因此可以直接复制 efivars.fd
	if (strlen(vm.uefi_vars) > 0) {
		char src_vars[FN_MAX_LEN];
		char dst_vars[FN_MAX_LEN];
		sprintf(src_vars, "%s", p_src->vm.uefi_vars);
		sprintf(dst_vars, "%s%s/efivars.fd", vmdir, dst_vm_name);
		
		// 尝试复制源 VM 的 efivars.fd
		if (access(src_vars, R_OK) == 0) {
			char cp_cmd[1024];
			sprintf(cp_cmd, "cp %s %s", src_vars, dst_vars);
			if (system(cp_cmd) == 0) {
				strcpy(vm.uefi_vars, dst_vars);
				write_log("Cloned UEFI vars from %s to %s", src_vm_name, dst_vm_name);
			} else {
				// 复制失败，回退到使用空模板
				char template_vars[] = "/usr/local/share/uefi-firmware/BHYVE_UEFI_VARS.fd";
				if (access(template_vars, R_OK) == 0) {
					sprintf(cp_cmd, "cp %s %s", template_vars, dst_vars);
					if (system(cp_cmd) == 0) {
						strcpy(vm.uefi_vars, dst_vars);
						write_log("Created new UEFI vars for cloned VM %s from template (fallback)", dst_vm_name);
					} else {
						strcpy(vm.uefi_vars, "");
					}
				} else {
					strcpy(vm.uefi_vars, "");
				}
			}
		} else {
			// 源 vars 不存在，使用空模板
			char template_vars[] = "/usr/local/share/uefi-firmware/BHYVE_UEFI_VARS.fd";
			if (access(template_vars, R_OK) == 0) {
				char cp_cmd[1024];
				sprintf(cp_cmd, "cp %s %s", template_vars, dst_vars);
				if (system(cp_cmd) == 0) {
					strcpy(vm.uefi_vars, dst_vars);
					write_log("Created new UEFI vars for cloned VM %s from template", dst_vm_name);
				} else {
					strcpy(vm.uefi_vars, "");
				}
			} else {
				strcpy(vm.uefi_vars, "");
			}
		}
	}

	// 清空所有网卡的 MAC 地址，让首次启动时自动生成
	// 避免克隆后的 VM 与源 VM 有相同的 MAC 地址
	for (int i = 0; i < atoi(vm.nics); i++) {
		strcpy(vm.nic[i].mac, "");
	}
	write_log("Cleared MAC addresses for cloned VM %s, will auto-generate on first boot", dst_vm_name);

	// TPM 状态复制逻辑
	if (strcmp(vm.tpmstatus, "on") == 0) {
		char src_tpm[FN_MAX_LEN];
		char dst_tpm[FN_MAX_LEN];
		sprintf(src_tpm, "%s%s/tpm", vmdir, src_vm_name);
		sprintf(dst_tpm, "%s%s/tpm", vmdir, dst_vm_name);

		// 检查源 TPM 目录是否存在
		if (access(src_tpm, F_OK) == 0) {
			write_log("Cloning TPM state from %s to %s", src_vm_name, dst_vm_name);
			
			// 使用 cp -r 递归复制
			char cp_cmd[1024];
			// 确保目标父目录存在(已在上面创建)，这里直接复制目录内容
			// 注意：为了避免权限问题或 socket 文件干扰，我们应该尽量只复制标准文件
			// 但 swtpm 的状态主要在 .permall 文件。简单起见，复制整个目录然后清理。
			sprintf(cp_cmd, "cp -R %s %s", src_tpm, dst_tpm);
			system(cp_cmd);

			// 清理目标目录中的运行时文件 (.lock, .sock 等)
			// 这些文件在新 VM 启动时会由 swtpm 重新创建，保留旧的可能导致冲突
			char clean_cmd[1024];
			sprintf(clean_cmd, "rm -f %s/*.lock %s/*.sock %s/*.pid", dst_tpm, dst_tpm, dst_tpm);
			system(clean_cmd);
		}
	}

	save_vm_info(dst_vm_name, &vm);

	//生成device.map
	if (write_vm_device_map(&vm) == RET_FAILURE) {
		error("cloning device_map failure\n");
		return RET_FAILURE;
	}

	int ret;
	//克隆卷
	if (support_zfs() && strcmp(vm.zfs, "on") == 0) {
		ret = clone_zvol(&vm, src_vm_name, dst_vm_name, 1);
		printf("\033[100D\033[K\033[?25h\033[0m");
	}
	else {

		//复制disk.img
		copy_stru name;
		name.src = src_vm_name;
		name.dst = dst_vm_name;
		name.disks = atoi(p_src->vm.disks);
		//ret = wait_exec((int*)copy_vm_disk, (copy_stru*)&name);
		ret = wait_exec((fun)(int*)copy_vm_disk, (copy_stru*)&name);
	}

	printf("\033[1A");
	if (ret == RET_FAILURE) {
		error("cloning disk failure\n");
		return RET_FAILURE;
	}
	else {
		success("Complete cloning\n");
		return RET_SUCCESS;
	}
}

// vm更名
int  vm_rename(char *old_vm_name, char *new_vm_name)
{
	char old_dir[FN_MAX_LEN];
	char new_dir[FN_MAX_LEN];
	sprintf(old_dir, "%s%s", vmdir, old_vm_name);
	sprintf(new_dir, "%s%s", vmdir, new_vm_name);

	if (access(old_dir, 0) == -1) {
		error("%s not exist\n", old_vm_name);
		show_vm_name(VM_OFF);
		return RET_FAILURE;
	}

	if (access(new_dir, 0) == 0) {
		error("%s already existed\n", new_vm_name);
		return RET_FAILURE;
	}

	if (get_vm_status(old_vm_name) == VM_ON) {
		error("%s is running, cannot rename\n", old_vm_name);
		return RET_FAILURE;
	}

	vm_node *p = find_vm_list(old_vm_name);
	if (atoi(p->vm.lock)) {
		error("%s has been locked up\n", old_vm_name);
		return RET_FAILURE;
	}

	//修改vm配置文件
	vm_stru vm;
	load_vm_info(old_vm_name, &vm);
	
	strcpy(vm.name, new_vm_name);

	char str[FN_MAX_LEN];
	sprintf(str, "%s%s", new_dir, "/disk.img");
	strcpy(vm.disk, str);

	sprintf(str, "%s%s", new_dir, "/device.map");
	strcpy(vm.devicemap, str);

	// 更新 UEFI vars 文件路径（如果存在）
	if (strlen(vm.uefi_vars) > 0) {
		sprintf(str, "%s/efivars.fd", new_dir);
		strcpy(vm.uefi_vars, str);
	}

	save_vm_info(old_vm_name, &vm);

	//vm文件夹更名
	if (rename(old_dir, new_dir) == -1) {
		error("failed to rename directory\n");
		return RET_FAILURE;
	}

	//vm配置文件更名
	char old[FN_MAX_LEN];
	char new[FN_MAX_LEN];
	sprintf(old, "%s/%s.conf", new_dir, old_vm_name);
	sprintf(new, "%s/%s.conf", new_dir, new_vm_name);

	if (rename(old, new) == -1) {
		error("failed to rename config file\n");
		return RET_FAILURE;
	}

	//修改device.map
	if (write_vm_device_map(&vm) == RET_FAILURE) {
		error("device_map file\n");
		return RET_FAILURE;
	}

	//卷更名
	if (support_zfs() && strcmp(p->vm.zfs, "on") == 0)
		rename_zvol(&vm, old_vm_name, new_vm_name);

	success("Rename success\n");
	return RET_SUCCESS;
}

// 删除vm
int vm_remove(char *vm_name, int skip_confirm, int show_list)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s not exist\n", vm_name);
		if (show_list)
			show_vm_name(VM_OFF);
		return RET_FAILURE;
	}
	
	if (atoi(p->vm.lock)) {
		error("%s has been locked up\n", vm_name);
		return RET_FAILURE;
	}

	if (!skip_confirm) {
		WARN("Enter 'YES' To remove the vm [%s]: ", vm_name);
		char str[BUFFERSIZE];
		fgets(str, BUFFERSIZE, stdin);
		str[strlen(str)-1] = '\0';
		if (strcmp(str, "YES") == 0) {
			printf("\033[1A\033[K");
		}
		else {
			printf("\033[1A\033[K");
			warn("cancelled\n");
			return RET_FAILURE;
		}
	}

	char filename[FN_MAX_LEN];

	//disk
	for (int n=0; n<atoi(p->vm.disks); n++) {
		char disk[32];
		if (n == 0)
			strcpy(disk, "/disk.img");
		else
			sprintf(disk, "/disk%d.img", n);
		sprintf(filename, "%s%s%s", vmdir, vm_name, disk);

		if (support_zfs() && strcmp(p->vm.zfs, "on") == 0) 
			remove_zvol(&p->vm, n);
		
		if (remove(filename) == -1) {
			error("failed to remove %s\n", filename);
			return RET_FAILURE;
		}

	}
	
	//device.map
	sprintf(filename, "%s%s/device.map", vmdir, vm_name);
	if (remove(filename) == -1) {
	       	error("failed to remove %s\n", filename);
		return RET_FAILURE;
	}

	//config file
	sprintf(filename, "%s%s/%s.conf", vmdir, vm_name, vm_name);
	if (remove(filename) == -1) {
		error("failed to remove %s\n", filename);
		return RET_FAILURE;
	}

	//directory
	sprintf(filename, "%s%s", vmdir, vm_name);
	// 递归删除目录及其内容
	char cmd[CMD_MAX_LEN];
	sprintf(cmd, "rm -rf %s", filename);
	if (run_cmd(cmd) != 0) {
		error("Failed to remove directory %s\n", filename);
		return RET_FAILURE;
	}
	else {
		success("%s Remove success\n", vm_name);
		return RET_SUCCESS;
	}
	/*
	if (remove(filename) == 0) {
		success("Remove success\n");
		return RET_SUCCESS;
	}
	else {
		error("%s cannot remove\n", filename);
		return RET_FAILURE;
	}*/
}

// 增加一块新磁盘
void vm_add_disk(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
	}

	if (get_vm_status(vm_name) == VM_ON) {
		error("%s is running, cannot add an new disk\n", vm_name);
		return;
	}

	if (atoi(p->vm.lock)) {
		error("%s has been locked up\n", vm_name);
		return;
	}

	int new_disk_ord = atoi(p->vm.disks);
	if (new_disk_ord == DISK_NUM) {
		error("The number of disks reached the limit\n");
		err_exit();
	}
	char msg[BUFFERSIZE];
	sprintf(msg, "Enter new vm disk(%d) size (e.g. 5g): ", new_disk_ord);
	char disk_size[32] = {0};  // 初始化为空字符串，避免乱码
	enter_numbers(msg, "mMgGtT", (char*)&disk_size);

	//char *img = &p->vm.imgsize + new_disk_ord * disk_offset(&p->vm);
	char *img = (char*)&p->vm.vdisk[new_disk_ord].size;
	strcpy(img, disk_size);

	create_vm_disk(&p->vm, new_disk_ord);

	sprintf(p->vm.disks, "%d", new_disk_ord + 1);
	save_vm_info(vm_name, &p->vm);
}

// 删除一块磁盘
void vm_del_disk(char *vm_name)
{
	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) {
		error("%s not exist\n", vm_name);
		show_vm_name(VM_OFF);
		return;
	}

	if (get_vm_status(vm_name) == VM_ON) {
		error("%s is running, cannot del disk\n", vm_name);
		return;
	}

	if (atoi(p->vm.lock)) {
		error("%s has been locked up\n", vm_name);
		return;
	}

	//选择盘号
	int n = select_disk(&p->vm);
	if (n == 0) {
		error("cannot delete disk(0)\n");
		err_exit();
	}

	
	//删除选中的磁盘
	char filename[FN_MAX_LEN];
	char disk[32];
	if (n == 0)
		strcpy(disk, "/disk.img");
	else
		sprintf(disk, "/disk%d.img", n);
	sprintf(filename, "%s%s%s", vmdir, vm_name, disk);
	if (remove(filename) == -1) {
		error("%s cannot remove\n", filename);
		err_exit();
	}

	//修改受影响的磁盘文件名
	for (int i=n+1; i<atoi(p->vm.disks); i++) {
		char old[FN_MAX_LEN];
		char new[FN_MAX_LEN];
		sprintf(old, "%s%s/disk%d.img", vmdir, vm_name, i); 
		sprintf(new, "%s%s/disk%d.img", vmdir, vm_name, i - 1); 
		if (rename(old, new) == -1) {
			error("reanme %s error\n");
			err_exit();
		}
		//printf("old=%s ==> new=%s\n", old, new);
	}

	//修改vm配置文件
	for (int i=n+1; i<atoi(p->vm.disks); i++) {
		char *old;
		char *new;
		//old = &p->vm.imgsize + i * disk_offset(&p->vm);
		//new = &p->vm.imgsize + (i - 1) * disk_offset(&p->vm);
		old = p->vm.vdisk[i].size;
		new = p->vm.vdisk[i-1].size;
		strcpy(new, old);
		//printf("old=%s ==> new=%s\n", old, new);
	}
	//strcpy(&p->vm.imgsize + (atoi(p->vm.disks) - 1) * disk_offset(&p->vm), "");
	strcpy(p->vm.vdisk[atoi(p->vm.disks) - 1].size, "");
	sprintf(p->vm.disks, "%d", atoi(p->vm.disks) - 1);

	//写入配置文件
	save_vm_info(vm_name, &p->vm);

}

// 选择磁盘
int select_disk(vm_stru *vm)
{
	char *msg = "Which disk: ";
	char *opts[DISK_NUM] = {"0", "1", "2", "3", "4", "5", "6", "7"};
	char *desc[DISK_NUM] = {0};
	int disk_num = atoi(vm->disks);
	opts[disk_num] = NULL;
	for(int n=0; n<disk_num; n++) {
		desc[n] = (char*)malloc(BUFFERSIZE * sizeof(char));
		memset(desc[n], 0, BUFFERSIZE * sizeof(char)); 
		//sprintf(desc[n], "disk(%d) - %s", n, (char*)(&vm->imgsize + n * disk_offset(vm)));
		sprintf(desc[n], "disk(%d) - %s", n, vm->vdisk[n].size);
	}

	char disk[32];
	enter_options(msg, opts, desc, (char*)&disk);

	int n = 0;
	while (desc[n]) {
		free(desc[n]);
		++n;
	}

	return atoi(disk);
}


// 复制vm磁盘文件
int copy_vm_disk(copy_stru *name)
{
    char src[FN_MAX_LEN];
    char dst[FN_MAX_LEN];
    size_t len_in, len_out;
    
    // 首先计算所有磁盘的总大小
    long total_size = 0;
    for (int n = 0; n < name->disks; n++) {
        char disk[32];
        if (n == 0)
            strcpy(disk, "/disk.img");
        else 
            sprintf(disk, "/disk%d.img", n);
        sprintf(src, "%s%s%s", vmdir, name->src, disk);
        
        FILE *in = fopen(src, "rb");
        if (in == NULL) {
            error("open %s error\n", src);
            return RET_FAILURE;
        }
        fseek(in, 0, SEEK_END);
        total_size += ftell(in);
        fclose(in);
    }
    
    // 复制所有磁盘文件
    long total_bytes_copied = 0;
    int last_percent = -1;
    char buf[BUFFERSIZE];
    
    for (int n = 0; n < name->disks; n++) {
        char disk[32];
        if (n == 0)
            strcpy(disk, "/disk.img");
        else 
            sprintf(disk, "/disk%d.img", n);
        sprintf(src, "%s%s%s", vmdir, name->src, disk);
        sprintf(dst, "%s%s%s", vmdir, name->dst, disk);

        FILE *in = fopen(src, "rb");
        if (in == NULL) {
            error("open %s error\n", src);
            return RET_FAILURE;
        }

        FILE *out = fopen(dst, "wb");
        if (out == NULL) {
            error("open %s error\n", dst);
            fclose(in);
            return RET_FAILURE;
        }

        while ((len_in = fread(buf, 1, BUFFERSIZE, in)) > 0) {
            if ((len_out = fwrite(buf, 1, len_in, out)) != len_in) {
                error("write to file '%s' failed!\n", dst);
                fclose(in);
                fclose(out);
                return RET_FAILURE;
            }

            // 更新总进度
            total_bytes_copied += len_in;
            int percent = (int)((float)total_bytes_copied / total_size * 100);
            
            // 只在百分比变化时更新显示
            if (percent != last_percent) {
                printf("\rcloning ... %d%%  ", percent);
                fflush(stdout);
                last_percent = percent;
            }
        }
        
        fclose(in);
        fclose(out);
    }
    
    printf("\n");
    return RET_SUCCESS;
}



// 检测vm文件的完整性
int check_vm_files(char *vm_name)
{
	char file1[FN_MAX_LEN];
	char file2[FN_MAX_LEN];
	char file3[FN_MAX_LEN];
	
	sprintf(file1, "%s%s/device.map", vmdir, vm_name);
	sprintf(file2, "%s%s/disk.img", vmdir, vm_name);
	sprintf(file3, "%s%s/%s.conf", vmdir, vm_name, vm_name);

	//struct stat st;
	//if (stat(file2, &st) == -1) return RET_FAILURE;
	if (access(file1, 0) == -1) return RET_FAILURE;
	if (access(file2, 0) == -1) return RET_FAILURE;
	if (access(file3, 0) == -1) return RET_FAILURE;

	return RET_SUCCESS;

}

// 创建vm列表
void create_vm_list()
{
	destroy_vm_list();
	vms = NULL;
}

// 销毁vm列表
void destroy_vm_list()
{
	if (vms == NULL) 
		return;

	vm_node *p = vms;
	while (p) {
		p = vms->next;
		free(vms);
		vms = p;
	}
}

// 在列表中查找指定的vm
vm_node* find_vm_list(const char *vm_name)
{
	if (vm_name == NULL) return NULL;

	vm_node *p = vms;
	while(p) {
		if (strcmp(vm_name, p->vm.name) == 0)
			return p;
		else
			p = p->next;
	}

	return NULL;
}

// 从列表中删除一个vm
int  del_from_vm_list(char *vm_name)
{
	vm_node *prev, *cur;
	prev = cur = vms;

	while (cur) {
		if (strcmp(vm_name, cur->vm.name) == 0) {
			prev->next = cur->next;
			free(cur);
			return RET_SUCCESS;
		}
		else {
			prev = cur;
			cur = cur->next;
		}
	}

	return RET_FAILURE;
}


// 添加vm到列表
void add_to_vm_list(char *vm_name)
{
	char filename[FN_MAX_LEN];
	sprintf(filename, "%s%s/%s.conf", vmdir, vm_name, vm_name);	
	if (access(filename, 0) == -1) {
		error("%s not exist\n", filename);
		return;
	}

	vm_node *new;
	new = (vm_node*)malloc(sizeof(vm_node));
	if (new == NULL) {
		error("malloc vm error");
		return;
	}

	memset(new, 0, sizeof(vm_node));

	if (vms == NULL)
		vms = new;

	vm_node *p = vms;
	while (p->next) 
		p = p->next;

	p->next = new;
	load_vm_info(vm_name, &(new->vm));	
	new->next = NULL;
}

// 将vm列表按名称排序
// 辅助函数：获取用于显示的IP（支持动态获取）
void get_display_ip(vm_stru *vm, char *ip_buf) 
{
    strcpy(ip_buf, vm->nic[0].ip);
    
    // 如果是 NAT 模式且 VM 运行中，尝试获取动态 IP
    // 仅显示第一块网卡的 IP (nic[0])
    if (strncmp(vm->nic[0].netmode, "NAT", 3) == 0 && get_vm_status(vm->name) == VM_ON) {
         char dhcp_ip[32] = {0};
         // 尝试使用持久化MAC获取IP
         if (get_ip_from_dhcp_pool(vm->nic[0].mac, dhcp_ip) == RET_SUCCESS) {
             strcpy(ip_buf, dhcp_ip);
         }
         // 如果失败（可能是旧VM），尝试使用Bridge表获取MAC
         else if (get_mac_from_bridge(vm->nic[0].bridge, vm->nic[0].tap, vm->nic[0].mac) == RET_SUCCESS) {
             if (get_ip_from_dhcp_pool(vm->nic[0].mac, dhcp_ip) == RET_SUCCESS) {
                 strcpy(ip_buf, dhcp_ip);
             }
         }
    }
}

void sort_vm_list(int type)
{
	char *s1, *s2;
    char ip1[32], ip2[32]; 

	for (vm_node *p1=vms; p1!=NULL; p1=p1->next)
		for (vm_node *p2=p1->next; p2!=NULL; p2=p2->next) {
			if (type == LS_BY_NAME) {
				s1 = p1->vm.name;
				s2 = p2->vm.name;
			} 
			else if (type == LS_BY_IP) {
                get_display_ip(&p1->vm, ip1);
                get_display_ip(&p2->vm, ip2);
				s1 = ip1;
				s2 = ip2;
			}
			else if (type == LS_BY_OS) {
				s1 = p1->vm.ostype;
				s2 = p2->vm.ostype;
			}
			else if (type == LS_BY_STATUS) {
				s1 = p1->vm.status;
				s2 = p2->vm.status;
			}
			if (strcmp(s1, s2) > 0) {
			//if (strcmp(p1->vm.name, p2->vm.name) > 0) {
				vm_stru t;
				t = p1->vm;
				p1->vm = p2->vm;
				p2->vm = t;
			}
		}
}

// 载入vm配置信息
// 从指定路径载入vm配置信息
void load_vm_config_from_path(char *filename, vm_stru *vm)
{
	init_config(filename);
	
	char *value;
	char str[BUFFERSIZE];

	if ((value = get_value_by_name("vm_name")) != NULL)
		strcpy(vm->name, value);
	if ((value = get_value_by_name("vm_profile")) != NULL)
		strcpy(vm->profile, value);
	if ((value = get_value_by_name("vm_disks")) != NULL)
		strcpy(vm->disks, value);
	else
		strcpy(vm->disks, "1");

	if ((value = get_value_by_name("vm_ram")) != NULL)
		strcpy(vm->ram, value);
	if ((value = get_value_by_name("vm_cpus")) != NULL)
		strcpy(vm->cpus, value);
	else
		strcpy(vm->cpus, "1");

	// CPU 拓扑：如果没有配置，自动按最佳实践设置（sockets=1, cores=cpus, threads=1）
	if ((value = get_value_by_name("vm_sockets")) != NULL)
		strcpy(vm->sockets, value);
	else
		strcpy(vm->sockets, "1");

	if ((value = get_value_by_name("vm_cores")) != NULL)
		strcpy(vm->cores, value);
	else
		strcpy(vm->cores, vm->cpus);  // 默认等于总 CPU 数

	if ((value = get_value_by_name("vm_threads")) != NULL)
		strcpy(vm->threads, value);
	else
		strcpy(vm->threads, "1");

	for (int n=0; n<atoi(vm->disks); n++) {
		sprintf(str, "vm_disk%d_name", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->vdisk[n].name, value);
		sprintf(str, "vm_disk%d_size", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->vdisk[n].size, value);
		sprintf(str, "vm_disk%d_path", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->vdisk[n].path, value);
	}
	if ((value = get_value_by_name("vm_zfs")) != NULL)
		strcpy(vm->zfs, value);
	if ((value = get_value_by_name("vm_zpool")) != NULL)
		strcpy(vm->zpool, value);

	if ((value = get_value_by_name("vm_ram")) != NULL)
		strcpy(vm->ram, value);
	if ((value = get_value_by_name("vm_cpus")) != NULL)
		strcpy(vm->cpus, value);
	if ((value = get_value_by_name("vm_ostype")) != NULL)
		strcpy(vm->ostype, value);
	if ((value = get_value_by_name("vm_version")) != NULL)
		strcpy(vm->version, value);
	if ((value = get_value_by_name("vm_cdstatus")) != NULL)
		strcpy(vm->cdstatus, value);
	else
		strcpy(vm->cdstatus, "on");
	
	// 多 CD 支持
	if ((value = get_value_by_name("vm_cds")) != NULL)
		strcpy(vm->cds, value);
	else
		strcpy(vm->cds, "1");  // 默认 1 个 CD
	
	for (int n=0; n<atoi(vm->cds); n++) {
		if (n >= CD_NUM) break;
		sprintf(str, "vm_cd%d_iso", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->cd_iso[n], value);
	}
	
	// 向后兼容：如果 vm_iso 存在但 cd_iso[0] 为空，迁移旧配置
	if ((value = get_value_by_name("vm_iso")) != NULL) {
		strcpy(vm->iso, value);
		if (strlen(vm->cd_iso[0]) == 0 && strlen(vm->iso) > 0) {
			strcpy(vm->cd_iso[0], vm->iso);
		}
	}
	
	if ((value = get_value_by_name("vm_bootfrom")) != NULL)
		strcpy(vm->bootfrom, value);
	if ((value = get_value_by_name("vm_hostbridge")) != NULL)
		strcpy(vm->hostbridge, value);

	// 配置迁移：首先检查 vm_boot_type，然后回退到 vm_uefi
	if ((value = get_value_by_name("vm_boot_type")) != NULL) {
		strcpy(vm->boot_type, value);
		if (strcmp(vm->boot_type, "none") == 0) strcpy(vm->boot_type, "grub");
	}
	else if ((value = get_value_by_name("vm_uefi")) != NULL) {
		strcpy(vm->boot_type, value);
		if (strcmp(vm->boot_type, "none") == 0) strcpy(vm->boot_type, "grub");
	}


	if ((value = get_value_by_name("vm_uefi_vars")) != NULL)
		strcpy(vm->uefi_vars, value);
	if ((value = get_value_by_name("vm_disk")) != NULL)
		strcpy(vm->disk, value);
	if ((value = get_value_by_name("vm_devicemap")) != NULL)
		strcpy(vm->devicemap, value);
	if ((value = get_value_by_name("vm_grubcmd")) != NULL)
		strcpy(vm->grubcmd, value);
	if ((value = get_value_by_name("vm_nics")) != NULL)
		strcpy(vm->nics, value);
	for (int n=0; n<atoi(vm->nics); n++) {
		sprintf(str, "vm_nic%d_name", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].name, value);
		sprintf(str, "vm_nic%d_netmode", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].netmode, value);
		sprintf(str, "vm_nic%d_nat", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].nat, value);
		sprintf(str, "vm_nic%d_rpstatus", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].rpstatus, value);
		sprintf(str, "vm_nic%d_rpnum", n);
		if ((value = get_value_by_name(str)) != NULL)
			vm->nic[n].rpnum = atoi(value);

		for (int m=0; m<vm->nic[n].rpnum; m++) {
			sprintf(str, "vm_nic%d_ports%d_protocol", n, m);
			if ((value = get_value_by_name(str)) != NULL)
				strcpy(vm->nic[n].ports[m].proto, value);
			sprintf(str, "vm_nic%d_ports%d_vm_port", n, m);
			if ((value = get_value_by_name(str)) != NULL)
				vm->nic[n].ports[m].vm_port = atoi(value);
			sprintf(str, "vm_nic%d_ports%d_host_port", n, m);
			if ((value = get_value_by_name(str)) != NULL)
				vm->nic[n].ports[m].host_port = atoi(value);
		}

		sprintf(str, "vm_nic%d_rplist", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].rplist, value);
		sprintf(str, "vm_nic%d_bridge", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].bridge, value);
		sprintf(str, "vm_nic%d_tap", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].tap, value);
		sprintf(str, "vm_nic%d_ip", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].ip, value);
		sprintf(str, "vm_nic%d_mac", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].mac, value);
		sprintf(str, "vm_nic%d_bind", n);
		if ((value = get_value_by_name(str)) != NULL)
			strcpy(vm->nic[n].bind, value);
	}

	if ((value = get_value_by_name("vm_vncstatus")) != NULL)
		strcpy(vm->vncstatus, value);
	else
		strcpy(vm->vncstatus, "on");
	if ((value = get_value_by_name("vm_vncport")) != NULL)
		strcpy(vm->vncport, value);
	if ((value = get_value_by_name("vm_vncwidth")) != NULL)
		strcpy(vm->vncwidth, value);
	if ((value = get_value_by_name("vm_vncheight")) != NULL)
		strcpy(vm->vncheight, value);

	if ((value = get_value_by_name("vm_vncpassword")) != NULL)
		strcpy(vm->vncpassword, value);
	else
		strcpy(vm->vncpassword, "");

	if ((value = get_value_by_name("vm_vncwait")) != NULL)
		strcpy(vm->vncwait, value);
	else
		strcpy(vm->vncwait, "off");

	if ((value = get_value_by_name("vm_vncbind")) != NULL)
		strcpy(vm->vncbind, value);
	else
		strcpy(vm->vncbind, "0.0.0.0");

	if ((value = get_value_by_name("vm_autoboot")) != NULL)
		strcpy(vm->autoboot, value);
	else
		strcpy(vm->autoboot, "no");
	if ((value = get_value_by_name("vm_bootindex")) != NULL)
		strcpy(vm->bootindex, value);
	if ((value = get_value_by_name("vm_bootdelay")) != NULL)
		strcpy(vm->bootdelay, value);

	if ((value = get_value_by_name("vm_status")) != NULL) {
		if (get_vm_status(vm->name) == VM_OFF)
			strcpy(vm->status, "off");
		else {
			if (get_vm_status(vm->name) == VM_ON)
				strcpy(vm->status, "on");
		}
	}

	if ((value = get_value_by_name("vm_lock")) != NULL)
		strcpy(vm->lock, value);
	if ((value = get_value_by_name("vm_crypt")) != NULL)
		strcpy(vm->crypt, value);
	if ((value = get_value_by_name("vm_booter")) != NULL)
		strcpy(vm->booter, value);
	else
		strcpy(vm->booter, "bvmb");

	if ((value = get_value_by_name("vm_network_interface")) != NULL)
		strcpy(vm->network_interface, value);
	else
		strcpy(vm->network_interface, "e1000");

	if ((value = get_value_by_name("vm_storage_interface")) != NULL)
		strcpy(vm->storage_interface, value);
	else
		strcpy(vm->storage_interface, "ahci-hd");

	if ((value = get_value_by_name("vm_tpmstatus")) != NULL)
		strcpy(vm->tpmstatus, value);
	else
		strcpy(vm->tpmstatus, "off");

	if ((value = get_value_by_name("vm_tpmversion")) != NULL)
		strcpy(vm->tpmversion, value);
	else
		strcpy(vm->tpmversion, "");

	if ((value = get_value_by_name("vm_tpmpath")) != NULL)
		strcpy(vm->tpmpath, value);
	else
		strcpy(vm->tpmpath, "");

	if ((value = get_value_by_name("vm_audiostatus")) != NULL)
		strcpy(vm->audiostatus, value);
	else
		strcpy(vm->audiostatus, "off");

	if ((value = get_value_by_name("vm_share_status")) != NULL)
		strcpy(vm->share_status, value);
	else
		strcpy(vm->share_status, "off");

	if ((value = get_value_by_name("vm_share_name")) != NULL)
		strcpy(vm->share_name, value);
	else
		strcpy(vm->share_name, "");

	if ((value = get_value_by_name("vm_share_path")) != NULL)
		strcpy(vm->share_path, value);
	else
		strcpy(vm->share_path, "");

	if ((value = get_value_by_name("vm_share_ro")) != NULL)
		strcpy(vm->share_ro, value);
	else
		strcpy(vm->share_ro, "off");

	free_config();
}

// 载入vm配置信息
void load_vm_info(char *vm_name, vm_stru *vm)
{
	char filename[FN_MAX_LEN];
	sprintf(filename, "%s%s/%s.conf", vmdir, vm_name, vm_name);
	load_vm_config_from_path(filename, vm);
}

// 写入vm配置信息
void save_vm_info(char *vm_name, vm_stru *vm)
{
	char filename[FN_MAX_LEN];
	sprintf(filename, "%s%s/%s.conf", vmdir, vm_name, vm_name);

	FILE *fp;
	if ((fp = fopen(filename, "w")) == NULL) {
		error("open %s error\n", filename);
		exit(1);
	}

	char str[BUFFERSIZE];

	sprintf(str, "vm_name=%s\n", vm->name);
	fputs(str, fp);
	sprintf(str, "vm_profile=%s\n", vm->profile);
	fputs(str, fp);
	sprintf(str, "vm_storage_interface=%s\n", vm->storage_interface);
	fputs(str, fp);
	sprintf(str, "vm_disks=%s\n", vm->disks);
	fputs(str, fp);
	for (int n=0; n<atoi(vm->disks); n++) {
		sprintf(str, "vm_disk%d_name=disk%d\n", n, n);
		fputs(str, fp);
		sprintf(str, "vm_disk%d_size=%s\n", n, vm->vdisk[n].size);
		fputs(str, fp);
		char disk[BUFFERSIZE];
		if (n == 0) 
			strcpy(disk, "disk.img");
		else
			sprintf(disk, "disk%d.img", n);
		sprintf(str, "vm_disk%d_path=%s%s/%s\n", n, vmdir, vm->name, disk);
		fputs(str, fp);
	}
	sprintf(str, "vm_zfs=%s\n", vm->zfs);
	fputs(str, fp);
	sprintf(str, "vm_zpool=%s\n", vm->zpool);
	fputs(str, fp);


	/*
	//------------
	sprintf(str, "vm_imgsize=%s\n", vm->imgsize);
	fputs(str, fp);

	int offset = &vm->img1size - &vm->imgsize;
	for (int n=1; n<atoi(vm->disks); n++) {
		sprintf(str, "vm_img%dsize=%s\n", n, (char*)(&vm->imgsize + n * offset));
		fputs(str, fp);
	}
	//------------
	*/

	sprintf(str, "vm_ram=%s\n", vm->ram);
	fputs(str, fp);
	sprintf(str, "vm_cpus=%s\n", vm->cpus);
	fputs(str, fp);
	sprintf(str, "vm_sockets=%s\n", vm->sockets);
	fputs(str, fp);
	sprintf(str, "vm_cores=%s\n", vm->cores);
	fputs(str, fp);
	sprintf(str, "vm_threads=%s\n", vm->threads);
	fputs(str, fp);
	fputs("\n", fp);

	sprintf(str, "vm_ostype=%s\n", vm->ostype);
	fputs(str, fp);
	sprintf(str, "vm_version=%s\n", vm->version);
	fputs(str, fp);
	sprintf(str, "vm_cdstatus=%s\n", vm->cdstatus);
	fputs(str, fp);
	
	// 多 CD 支持
	sprintf(str, "vm_cds=%s\n", vm->cds);
	fputs(str, fp);
	for (int n=0; n<atoi(vm->cds); n++) {
		sprintf(str, "vm_cd%d_iso=%s\n", n, vm->cd_iso[n]);
		fputs(str, fp);
	}
	
	// 向后兼容：同时保存 vm_iso（使用第一个 CD 的路径）
	if (atoi(vm->cds) > 0 && strlen(vm->cd_iso[0]) > 0)
		sprintf(str, "vm_iso=%s\n", vm->cd_iso[0]);
	else
		sprintf(str, "vm_iso=%s\n", vm->iso);
	fputs(str, fp);
	
	sprintf(str, "vm_bootfrom=%s\n", vm->bootfrom);
	fputs(str, fp);
	sprintf(str, "vm_hostbridge=%s\n", vm->hostbridge);
	fputs(str, fp);
	sprintf(str, "vm_boot_type=%s\n", vm->boot_type);
	fputs(str, fp);
	sprintf(str, "vm_uefi_vars=%s\n", vm->uefi_vars);
	fputs(str, fp);
	sprintf(str, "vm_disk=%s\n", vm->disk);
	fputs(str, fp);
	sprintf(str, "vm_devicemap=%s\n", vm->devicemap);
	fputs(str, fp);
	sprintf(str, "vm_grubcmd=%s\n", vm->grubcmd);
	fputs(str, fp);
	fputs("\n", fp);
	
	sprintf(str, "vm_network_interface=%s\n", vm->network_interface);
	fputs(str, fp);
	sprintf(str, "vm_nics=%s\n", vm->nics);
	fputs(str, fp);
	for (int n=0; n<atoi(vm->nics); n++) {
		sprintf(str, "vm_nic%d_name=nic_%d\n", n, n);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_netmode=%s\n", n, vm->nic[n].netmode);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_nat=%s\n", n, vm->nic[n].nat);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_rpstatus=%s\n", n, vm->nic[n].rpstatus);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_rpnum=%d\n", n, vm->nic[n].rpnum);
		fputs(str, fp);

		for (int m=0; m<vm->nic[n].rpnum; m++) {
			sprintf(str, "vm_nic%d_ports%d_protocol=%s\n", n, m, vm->nic[n].ports[m].proto);
			fputs(str, fp);
			sprintf(str, "vm_nic%d_ports%d_vm_port=%d\n", n, m, vm->nic[n].ports[m].vm_port);
			fputs(str, fp);
			sprintf(str, "vm_nic%d_ports%d_host_port=%d\n", n, m, vm->nic[n].ports[m].host_port);
			fputs(str, fp);
		}

		sprintf(str, "vm_nic%d_rplist=%s\n", n, vm->nic[n].rplist);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_bridge=%s\n", n, vm->nic[n].bridge);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_tap=%s\n", n, vm->nic[n].tap);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_ip=%s\n", n, vm->nic[n].ip);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_mac=%s\n", n, vm->nic[n].mac);
		fputs(str, fp);
		sprintf(str, "vm_nic%d_bind=%s\n", n, vm->nic[n].bind);
		fputs(str, fp);
	}
	fputs("\n", fp);

	sprintf(str, "vm_vncstatus=%s\n", vm->vncstatus);
	fputs(str, fp);
	sprintf(str, "vm_vncport=%s\n", vm->vncport);
	fputs(str, fp);
	sprintf(str, "vm_vncwidth=%s\n", vm->vncwidth);
	fputs(str, fp);
	sprintf(str, "vm_vncheight=%s\n", vm->vncheight);
	fputs(str, fp);
	sprintf(str, "vm_vncpassword=%s\n", vm->vncpassword);
	fputs(str, fp);
	sprintf(str, "vm_vncwait=%s\n", vm->vncwait);
	fputs(str, fp);
	sprintf(str, "vm_vncbind=%s\n", vm->vncbind);
	fputs(str, fp);
	sprintf(str, "vm_audiostatus=%s\n", vm->audiostatus);
	fputs(str, fp);
	fputs("\n", fp);

	sprintf(str, "vm_autoboot=%s\n", vm->autoboot);
	fputs(str, fp);
	sprintf(str, "vm_bootindex=%s\n", vm->bootindex);
	fputs(str, fp);
	sprintf(str, "vm_bootdelay=%s\n", vm->bootdelay);
	fputs(str, fp);
	fputs("\n", fp);

	sprintf(str, "vm_status=%s\n", get_vm_status(vm->name)==VM_ON?"on":"off");
	fputs(str, fp);
	sprintf(str, "vm_lock=%s\n", vm->lock);
	fputs(str, fp);
	sprintf(str, "vm_crypt=%s\n", vm->crypt);
	fputs(str, fp);
	sprintf(str, "vm_booter=%s\n", vm->booter);
	fputs(str, fp);
	fputs("\n", fp);

	sprintf(str, "vm_tpmstatus=%s\n", vm->tpmstatus);
	fputs(str, fp);
	sprintf(str, "vm_tpmversion=%s\n", vm->tpmversion);
	fputs(str, fp);
	sprintf(str, "vm_tpmpath=%s\n", vm->tpmpath);
	fputs(str, fp);
	fputs("\n", fp);

	sprintf(str, "vm_share_status=%s\n", vm->share_status);
	fputs(str, fp);
	sprintf(str, "vm_share_name=%s\n", vm->share_name);
	fputs(str, fp);
	sprintf(str, "vm_share_path=%s\n", vm->share_path);
	fputs(str, fp);
	sprintf(str, "vm_share_ro=%s\n", vm->share_ro);
	fputs(str, fp);
	fputs("\n", fp);

	fclose(fp);

}

// 显示所有vm_name
void show_vm_name(int status)
{
	if (vms == NULL) return;

	char *msg = "Optional vms: ";
	int printed = 0;

	int n = 0;
	vm_node *p = vms;
	while (p) {
		if (status == VM_ALL || get_vm_status(p->vm.name) == status) {
			if (printed == 0) warn("%s\n", msg);
			printed = 1;		
			printf("%2d.%s\n", ++n, p->vm.name);
		}
		p = p->next;
	}
}

// 从状态相同的vm列表中选择
// 用于命令行没有输入vm_name的处理
void select_vm(char *vm_name, int status)
{
	if (vms == NULL) return;

	char *msg = "Select vm: ";
	char *jname[BUFFERSIZE] = {0};
	
	int n = 0;
	vm_node *p = vms;
	while (p) {
		if (status == VM_ALL || get_vm_status(p->vm.name) == status) {
			jname[n++] = p->vm.name;
		}
		p = p->next;
	}

	if (n > 0)
		enter_options(msg, jname, NULL, vm_name);
}
// 输出运行中的虚拟机网络信息
void print_vm_net_stat()
{
    if (vms == NULL) return;
    if (vm_online_count() == 0) return;

    // 定义列宽结构
    struct {
        int name;
        int nic;
        int mode;
        int ip;
        int gateway;
        int ports;
        int bridge;
        int tap;
    } max_width = {4, 3, 4, 2, 7, 5, 6, 3}; // 设置最小宽度(标题长度)

    // 第一遍遍历计算最大宽度
    vm_node *p = vms;
    while (p) {
        if (get_vm_status(p->vm.name) == VM_OFF) {
            p = p->next;
            continue;
        }

        // 更新name列宽
        max_width.name = MAX(max_width.name, strlen(p->vm.name));

        for (int i = 0; i < atoi(p->vm.nics); i++) {
            // 更新nic列宽(数字宽度固定为1)
            max_width.nic = 3;  // "NIC"的宽度

            // 更新mode列宽
            max_width.mode = MAX(max_width.mode, 6); // "BRIDGE"/"SWITCH"的宽度

            // 更新ip列宽
            //max_width.ip = MAX(max_width.ip, strlen(p->vm.nic[i].ip));
            char ip[32];
            strcpy(ip, p->vm.nic[i].ip);
            
            // 如果是 NAT 模式且 VM 运行中，尝试获取动态 IP
            if (strncmp(p->vm.nic[i].netmode, "NAT", 3) == 0 && get_vm_status(p->vm.name) == VM_ON) {
                 char dhcp_ip[32] = {0};
                 // 尝试使用持久化MAC获取IP
                 if (get_ip_from_dhcp_pool(p->vm.nic[i].mac, dhcp_ip) == RET_SUCCESS) {
                     strcpy(ip, dhcp_ip);
                 }
                 // 如果失败（可能是旧VM），尝试使用Bridge表获取MAC
                 else if (get_mac_from_bridge(p->vm.nic[i].bridge, p->vm.nic[i].tap, p->vm.nic[i].mac) == RET_SUCCESS) {
                     if (get_ip_from_dhcp_pool(p->vm.nic[i].mac, dhcp_ip) == RET_SUCCESS) {
                         strcpy(ip, dhcp_ip);
                     }
                 }
            }
            max_width.ip = MAX(max_width.ip, strlen(ip));

            // 更新gateway列宽
            char gateway[64];
            if (strncmp(p->vm.nic[i].netmode, "NAT", 3) == 0) {
                get_nat_info(p->vm.nic[i].nat);
                sprintf(gateway, "%s (%s)", nat.ip, p->vm.nic[i].nat);
                max_width.gateway = MAX(max_width.gateway, strlen(gateway));
            }
            else if (strncmp(p->vm.nic[i].netmode, "SWITCH", 6) == 0) {
                get_switch_info(p->vm.nic[i].bind);
                sprintf(gateway, "%s (%s)", Switch.ip, p->vm.nic[i].bind);
                max_width.gateway = MAX(max_width.gateway, strlen(gateway));
            }

            // 更新ports列宽
            if (strcmp(p->vm.nic[i].rpstatus, "enable") == 0) {
                for (int j = 0; j < p->vm.nic[i].rpnum; j++) {
                    char port[32];
                    sprintf(port, "%s %d:%d", 
                            p->vm.nic[i].ports[j].proto,
                            p->vm.nic[i].ports[j].vm_port,
                            p->vm.nic[i].ports[j].host_port);
                    max_width.ports = MAX(max_width.ports, strlen(port));
                }
            }

            // 更新bridge列宽
            max_width.bridge = MAX(max_width.bridge, strlen(p->vm.nic[i].bridge));

            // 更新tap列宽
            max_width.tap = MAX(max_width.tap, strlen(p->vm.nic[i].tap));

        }
        p = p->next;
    }

    // 打印表头
    printf("\033[1;4m%-*s\033[24m    \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%s\033[0m\n",
           max_width.name, "NAME",
           max_width.nic, "NIC",
           max_width.mode, "MODE",
           max_width.ip, "IP",
           max_width.gateway, "GATEWAY",
           max_width.ports, "PORTS",
           max_width.bridge, "BRIDGE",
           "TAP");

    // 第二遍遍历打印数据
    p = vms;
    while (p) {
        if (get_vm_status(p->vm.name) == VM_OFF) {
            p = p->next;
            continue;
        }

        for (int i = 0; i < atoi(p->vm.nics); i++) {
            int port_rules = (strcmp(p->vm.nic[i].rpstatus, "enable") == 0) ? p->vm.nic[i].rpnum : 1;
            
            for (int port_idx = 0; port_idx < port_rules; port_idx++) {
                // NAME
                if (i == 0 && port_idx == 0) {
                    printf("%-*s", max_width.name, p->vm.name);
                } else {
                    printf("%*s", max_width.name, "");
                }
                printf("    ");  // 增加到4个空格

                // NIC
                if (port_idx == 0) {
                    printf("%-*d", max_width.nic, i);
                } else {
                    printf("%*s", max_width.nic, "");
                }
                printf("  ");  // 2个空格

                // MODE
                const char* mode = strncmp(p->vm.nic[i].netmode, "NAT", 3) == 0 ? "NAT" :
                                 strncmp(p->vm.nic[i].netmode, "SWITCH", 6) == 0 ? "SWITCH" : "BRIDGE";
                printf("%-*s  ", max_width.mode, mode);  // 2个空格

                // IP
                //printf("%-*s  ", max_width.ip, p->vm.nic[i].ip);  // 2个空格
                char ip[32];
                strcpy(ip, p->vm.nic[i].ip);

                // 如果是 NAT 模式且 VM 运行中，尝试获取动态 IP
                if (strncmp(p->vm.nic[i].netmode, "NAT", 3) == 0 && get_vm_status(p->vm.name) == VM_ON) {
                     char dhcp_ip[32] = {0};
                     // 尝试使用持久化MAC获取IP
                     if (get_ip_from_dhcp_pool(p->vm.nic[i].mac, dhcp_ip) == RET_SUCCESS) {
                         strcpy(ip, dhcp_ip);
                     }
                     // 如果失败（可能是旧VM），尝试使用Bridge表获取MAC
                     else if (get_mac_from_bridge(p->vm.nic[i].bridge, p->vm.nic[i].tap, p->vm.nic[i].mac) == RET_SUCCESS) {
                         if (get_ip_from_dhcp_pool(p->vm.nic[i].mac, dhcp_ip) == RET_SUCCESS) {
                             strcpy(ip, dhcp_ip);
                         }
                     }
                }
                printf("%-*s  ", max_width.ip, ip);

                // GATEWAY
                char gateway[64] = "-";
                if (strncmp(p->vm.nic[i].netmode, "NAT", 3) == 0) {
                    get_nat_info(p->vm.nic[i].nat);
                    sprintf(gateway, "%s (%s)", nat.ip, p->vm.nic[i].nat);
                }
                else if (strncmp(p->vm.nic[i].netmode, "SWITCH", 6) == 0) {
                    get_switch_info(p->vm.nic[i].bind);
                    sprintf(gateway, "%s (%s)", Switch.ip, p->vm.nic[i].bind);
                }
                printf("%-*s  ", max_width.gateway, gateway);  // 2个空格

                // PORTS
                char port[32] = "-";
                if (strcmp(p->vm.nic[i].rpstatus, "enable") == 0 && p->vm.nic[i].rpnum > 0) {
                    sprintf(port, "%s %d:%d",
                            p->vm.nic[i].ports[port_idx].proto,
                            p->vm.nic[i].ports[port_idx].vm_port,
                            p->vm.nic[i].ports[port_idx].host_port);
                }
                printf("%-*s  ", max_width.ports, port);  // 2个空格

                // BRIDGE
                printf("%-*s  ", max_width.bridge, p->vm.nic[i].bridge);  // 2个空格

                // TAP
                printf("%s\n", p->vm.nic[i].tap);
            }
        }
        p = p->next;
    }
}

// 输出vm列表
void print_vm_list(int list_type, int online_only)
{
	if (vms == NULL) return;
	if (online_only && vm_online_count() == 0) return;

    // 定义列宽结构
    struct {
        int name;
        int ip;
        int vnc;
        int guest;
        int loader;
        int autostart;
        int cpu;
        int memory;
        int disk;
        int state;
    } max_width = {4, 2, 3, 5, 6, 9, 3, 6, 4, 5}; // 默认最小宽度（标题长度）

    // pass 1: calculate max width
    vm_node *p = vms;
    while (p) {
        if (online_only && strcmp(p->vm.status, "off") == 0) {
            p = p->next;
            continue;
        }

        // NAME
        max_width.name = MAX(max_width.name, strlen(p->vm.name));

        // IP
        if (list_type == VM_LONG_LIST) {
            char ip[32];
            strcpy(ip, p->vm.nic[0].ip);
            
            // 如果是 NAT 模式且 VM 运行中，尝试获取动态 IP
            if (strncmp(p->vm.nic[0].netmode, "NAT", 3) == 0 && get_vm_status(p->vm.name) == VM_ON) {
                 char dhcp_ip[32] = {0};
                 // 尝试使用持久化MAC获取IP
                 if (get_ip_from_dhcp_pool(p->vm.nic[0].mac, dhcp_ip) == RET_SUCCESS) {
                     strcpy(ip, dhcp_ip);
                 }
                 // 如果失败（可能是旧VM），尝试使用Bridge表获取MAC
                 else if (get_mac_from_bridge(p->vm.nic[0].bridge, p->vm.nic[0].tap, p->vm.nic[0].mac) == RET_SUCCESS) {
                     if (get_ip_from_dhcp_pool(p->vm.nic[0].mac, dhcp_ip) == RET_SUCCESS) {
                         strcpy(ip, dhcp_ip);
                     }
                 }
            }
            max_width.ip = MAX(max_width.ip, strlen(ip));

            // VNC
            char vnc[32] = "-";
            if (strcmp(p->vm.boot_type, "uefi") == 0 || strcmp(p->vm.boot_type, "uefi_csm") == 0) {
                 if (strlen(p->vm.vncport) > 0) {
                      sprintf(vnc, "0.0.0.0:%s", p->vm.vncport);
                 }
            }
            max_width.vnc = MAX(max_width.vnc, strlen(vnc));
        }

        // GUEST
        max_width.guest = MAX(max_width.guest, strlen(p->vm.ostype));

        // LOADER
        if (list_type == VM_LONG_LIST) {
             const char* loader = (strcmp(p->vm.boot_type, "uefi") == 0) ? "uefi" : "grub";
             max_width.loader = MAX(max_width.loader, strlen(loader));
        }

        // AUTOSTART
        if (list_type == VM_LONG_LIST) {
            if (strcmp(p->vm.autoboot, "yes") == 0) {
                char str[16];
                sprintf(str, "Yes [%d]", atoi(p->vm.bootindex));
                max_width.autostart = MAX(max_width.autostart, strlen(str));
            } else {
                max_width.autostart = MAX(max_width.autostart, 2); // "No"
            }
        }

        // CPU
        max_width.cpu = MAX(max_width.cpu, strlen(p->vm.cpus));

        // MEMORY
        max_width.memory = MAX(max_width.memory, strlen(p->vm.ram));

        // DISK
        char str1[16], str2[16];
        int n = atoi(p->vm.disks);
        sprintf(str1, "[%d]", n);
        unit_convert(total_disk_size(&p->vm), 1, str2);
        strcat(str1, str2);
        max_width.disk = MAX(max_width.disk, strlen(str1));

        // STATE
        max_width.state = MAX(max_width.state, strlen(p->vm.status));

        p = p->next;
    }

    // print header
    if (list_type == VM_LONG_LIST) {
        printf("\033[1;4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%s\033[0m\n",
            max_width.name, "NAME",
            max_width.ip, "IP",
            max_width.vnc, "VNC",
            max_width.guest, "GUEST",
            max_width.loader, "LOADER",
            max_width.autostart, "AUTOSTART",
            max_width.cpu, "CPU",
            max_width.memory, "MEMORY",
            max_width.disk, "DISK",
            "STATE");
    } else {
        printf("\033[1;4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%-*s\033[24m  \033[4m%s\033[0m\n",
            max_width.name, "NAME",
            max_width.guest, "GUEST",
            max_width.cpu, "CPU",
            max_width.memory, "MEMORY",
            max_width.disk, "DISK",
            "STATE");
    }

    // pass 2: print data
    p = vms;
    while (p) {
        if (online_only && strcmp(p->vm.status, "off") == 0) {
            p = p->next;
            continue;
        }

        // NAME
        printf("%-*s  ", max_width.name, p->vm.name);

        // IP
        if (list_type == VM_LONG_LIST) {
            char ip[32];
            strcpy(ip, p->vm.nic[0].ip);
            int is_dynamic = 0;
            
            // 如果是 NAT 模式且 VM 运行中，尝试获取动态 IP
            if (strncmp(p->vm.nic[0].netmode, "NAT", 3) == 0 && get_vm_status(p->vm.name) == VM_ON) {
                 char dhcp_ip[32] = {0};
                 // 尝试使用持久化MAC获取IP
                 if (get_ip_from_dhcp_pool(p->vm.nic[0].mac, dhcp_ip) == RET_SUCCESS) {
                     strcpy(ip, dhcp_ip);
                     is_dynamic = 1;
                 }
                 // 如果失败（可能是旧VM），尝试使用Bridge表获取MAC
                 else if (get_mac_from_bridge(p->vm.nic[0].bridge, p->vm.nic[0].tap, p->vm.nic[0].mac) == RET_SUCCESS) {
                     if (get_ip_from_dhcp_pool(p->vm.nic[0].mac, dhcp_ip) == RET_SUCCESS) {
                         strcpy(ip, dhcp_ip);
                         is_dynamic = 1;
                     }
                 }
            }
            
            if (is_dynamic) {
                printf("\033[96m%s\033[0m", ip); // Cyan
                int pad = max_width.ip - strlen(ip);
                for (int k = 0; k < pad; k++) printf(" ");
                printf("  ");
            } else {
                printf("%-*s  ", max_width.ip, ip);
            }

            // VNC
            char vnc[32] = "-";
            if (strcmp(p->vm.boot_type, "uefi") == 0 || strcmp(p->vm.boot_type, "uefi_csm") == 0) {
                 if (strlen(p->vm.vncport) > 0) {
                      sprintf(vnc, "0.0.0.0:%s", p->vm.vncport);
                 }
            }
            printf("%-*s  ", max_width.vnc, vnc);
        }

        // GUEST
        printf("%-*s  ", max_width.guest, p->vm.ostype);

        // LOADER
        if (list_type == VM_LONG_LIST) {
            const char* loader = (strcmp(p->vm.boot_type, "uefi") == 0) ? "uefi" : "grub";
            printf("%-*s  ", max_width.loader, loader);
        }

        // AUTOSTART
        if (list_type == VM_LONG_LIST) {
            char str[32] = "No";
            if (strcmp(p->vm.autoboot, "yes") == 0) {
                sprintf(str, "Yes [%d]", atoi(p->vm.bootindex));
            }
            printf("%-*s  ", max_width.autostart, str);
        }

        // CPU
        printf("%-*s  ", max_width.cpu, p->vm.cpus);

        // MEMORY
        printf("%-*s  ", max_width.memory, strtoupper(p->vm.ram));

        // DISK
        char str1[16], str2[16];
        int n = atoi(p->vm.disks);
        sprintf(str1, "[%d]", n);
        unit_convert(total_disk_size(&p->vm), 1, str2);
        strcat(str1, str2);
        printf("%-*s  ", max_width.disk, strtoupper(str1));

		/* STATE */
		//if (strcmp(p->vm.status, "off") == 0)
		//	printf("\033[33m");
        if (strcmp(p->vm.status, "on") == 0)
            printf("\033[32;1m");
        printf("%s\033[0m", p->vm.status);

		/* PID */
		//if (strcmp(p->vm.status, "on") == 0) 
		//	printf(" (%d)", get_vm_pid(&p->vm));

		/* LOCK */
        if (strcmp(p->vm.lock, "1") == 0)
            warn(" *");

		/* CRYPT */
        if (strcmp(p->vm.crypt, "1") == 0)
            error(" *");

        printf("\n");
        p = p->next;
    }
}

// 获得vm的数量
int get_vm_count()
{
	int cnt = 0;

	if (vms == NULL) 
		return 0;

	vm_node *p = vms;
	while (p) {
		++cnt;
		p = p->next;
	}
	return cnt;
}

// 获取vm的状态
// 开机：VM_ON / 关机：VM_OFF
int get_vm_status(const char *vm_name)
{
	char fn[FN_MAX_LEN];
	sprintf(fn, "/dev/vmm/%s", vm_name);
	
	if (access(fn, 0) == -1)
		return VM_OFF;
	else
		return VM_ON;
}

// 更新vm状态
void update_vm_status(char *vm_name, int status)
{
	vm_stru vm;
	load_vm_info(vm_name, &vm);
	if (status == VM_ON)
		strcpy(vm.status, "on");
	if (status == VM_OFF)
		strcpy(vm.status, "off");
	save_vm_info(vm_name, &vm);
}

// 生成uefi启动代码
void gen_uefi_boot_code(char **code, vm_node *p)
{
}

// 生成grub启动代码
void gen_grub_boot_code(char **code, vm_node *p)
{
	//设置启动方式对应的grubcmd
	set_grub_cmd(p);
	
	//个别操作系统的处理
}

// 将启动代码写入文件
int write_boot_code(char **code, vm_node *p)
{
	//生成start.sh脚本
	char fn[FN_MAX_LEN];
	sprintf(fn, "/tmp/start_%s.sh", p->vm.name);

	FILE *fp;
	if ((fp = fopen(fn, "w")) == NULL) {
		perror(fn);
		return RET_FAILURE;
	}
	
	char vm_disk[256];
	int line = 0;
	char str[BUFFERSIZE];
	while (code[line]) {
		strcpy(str, code[line++]);
		strcat(str, "\n");

		if (strlen(p->vm.grubcmd) > 0)
			str_replace(str, "${vm_grubcmd}", p->vm.grubcmd);
		//else
		//	str_replace(str, "echo -e \"${vm_grubcmd}\" |", "");
		str_replace(str, "${vm_grubcd}", 	p->vm.grubcd);
		str_replace(str, "${vm_grubhd}", 	p->vm.grubhd);
		str_replace(str, "${vm_name}", 		p->vm.name);
		str_replace(str, "${vm_start_sh}", 	fn);
		str_replace(str, "${vm_version}", 	p->vm.version);
		str_replace(str, "${vm_bootfrom}", 	p->vm.bootfrom);
		str_replace(str, "${vm_boot_type}", 		p->vm.boot_type);
		str_replace(str, "${vm_devicemap}", 	p->vm.devicemap);
		str_replace(str, "${vm_ram}", 		p->vm.ram);
		str_replace(str, "${vm_cpus}", 		p->vm.cpus);
		str_replace(str, "${vm_hostbridge}", 	p->vm.hostbridge);
		str_replace(str, "${vm_disk}", 		p->vm.disk);
		str_replace(str, "${vm_iso}", 		p->vm.iso);
		str_replace(str, "${vm_vncport}", 	p->vm.vncport);
		str_replace(str, "${vm_vncwidth}", 	p->vm.vncwidth);
		str_replace(str, "${vm_vncheight}", 	p->vm.vncheight);
		
		if (strlen(p->vm.storage_interface) > 0)
			str_replace(str, "${vm_storage_interface}", p->vm.storage_interface);
		else
			str_replace(str, "${vm_storage_interface}", "ahci-hd");

		if (strcmp(p->vm.boot_type, "uefi") == 0)
			str_replace(str, "${vm_bhyve_uefi_fd}", "BHYVE_UEFI.fd");
		if (strcmp(p->vm.boot_type, "uefi_csm")== 0)
			str_replace(str, "${vm_bhyve_uefi_fd}", "BHYVE_UEFI_CSM.fd"); 

		if (strstr(str, "${vm_tap1}") && atoi(p->vm.nics) < 2) continue;
		if (strstr(str, "${vm_tap2}") && atoi(p->vm.nics) < 3) continue;
		if (strstr(str, "${vm_tap3}") && atoi(p->vm.nics) < 4) continue;
		if (strstr(str, "${vm_tap4}") && atoi(p->vm.nics) < 5) continue;
		if (strstr(str, "${vm_tap5}") && atoi(p->vm.nics) < 6) continue;
		if (strstr(str, "${vm_tap6}") && atoi(p->vm.nics) < 7) continue;
		if (strstr(str, "${vm_tap7}") && atoi(p->vm.nics) < 8) continue;

		str_replace(str, "${vm_tap}", 		p->vm.nic[0].tap);
		str_replace(str, "${vm_tap1}", 		p->vm.nic[1].tap);
		str_replace(str, "${vm_tap2}", 		p->vm.nic[2].tap);
		str_replace(str, "${vm_tap3}", 		p->vm.nic[3].tap);
		str_replace(str, "${vm_tap4}", 		p->vm.nic[4].tap);
		str_replace(str, "${vm_tap5}", 		p->vm.nic[5].tap);
		str_replace(str, "${vm_tap6}", 		p->vm.nic[6].tap);
		str_replace(str, "${vm_tap7}", 		p->vm.nic[7].tap);

		str_replace(str, "${vm_mac}", 		p->vm.nic[0].mac);
		str_replace(str, "${vm_mac1}", 		p->vm.nic[1].mac);
		str_replace(str, "${vm_mac2}", 		p->vm.nic[2].mac);
		str_replace(str, "${vm_mac3}", 		p->vm.nic[3].mac);
		str_replace(str, "${vm_mac4}", 		p->vm.nic[4].mac);
		str_replace(str, "${vm_mac5}", 		p->vm.nic[5].mac);
		str_replace(str, "${vm_mac6}", 		p->vm.nic[6].mac);
		str_replace(str, "${vm_mac7}", 		p->vm.nic[7].mac);

		// TPM
		char tpm_param[512] = "";
		char start_swtpm[1024] = "";
		char stop_swtpm[512] = "";

		if (strcmp(p->vm.tpmstatus, "on") == 0) {
			char tpm_sock[256];
			if (strlen(p->vm.tpmpath) > 0)
				strcpy(tpm_sock, p->vm.tpmpath);
			else
				sprintf(tpm_sock, "/tmp/%s/swtpm.sock", p->vm.name);

			char tpm_dir[256];
			sprintf(tpm_dir, "%s%s/tpm", vmdir, p->vm.name);

			char sock_dir[256];
			sprintf(sock_dir, "/tmp/%s", p->vm.name);
			
			char tpm_ctrl_sock[256];
			sprintf(tpm_ctrl_sock, "/tmp/%s/swtpm-ctrl.sock", p->vm.name);
			
			sprintf(start_swtpm, 
				"mkdir -p %s\n"
				"\t\tmkdir -p %s\n"
				"\t\tswtpm socket --tpmstate dir=%s --ctrl type=unixio,path=%s --server type=unixio,path=%s --tpm2 -d --pid file=/var/run/swtpm-%s.pid",
				sock_dir, tpm_dir, tpm_dir, tpm_ctrl_sock, tpm_sock, p->vm.name);

			sprintf(stop_swtpm, 
				"if [ -f /var/run/swtpm-%s.pid ]; then\n"
				"			kill $(cat /var/run/swtpm-%s.pid)\n"
				"			rm /var/run/swtpm-%s.pid\n"
				"		fi",
				p->vm.name, p->vm.name, p->vm.name);

			sprintf(tpm_param, "		-l tpm,swtpm,%s \\", tpm_sock);
		}
		
		str_replace(str, "${vm_tpm_param}", tpm_param);
		str_replace(str, "${vm_start_swtpm}", start_swtpm);
		str_replace(str, "${vm_stop_swtpm}", stop_swtpm);

	
		sprintf(vm_disk, "%s%s/disk1.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk1}",          vm_disk);
		sprintf(vm_disk, "%s%s/disk2.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk2}",          vm_disk);
		sprintf(vm_disk, "%s%s/disk3.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk3}",          vm_disk);
		sprintf(vm_disk, "%s%s/disk4.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk4}",          vm_disk);
		sprintf(vm_disk, "%s%s/disk5.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk5}",          vm_disk);
		sprintf(vm_disk, "%s%s/disk6.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk6}",          vm_disk);
		sprintf(vm_disk, "%s%s/disk7.img", vmdir, p->vm.name);
		str_replace(str, "${vm_disk7}",          vm_disk);

		//输入shell（测试用）
		//printf("%s", str);

		fputs(str, fp);
	}

	fclose(fp);

	//赋予start.sh执行权限
	chmod(fn, S_IRUSR | S_IWUSR | S_IXUSR);
	
	return RET_SUCCESS;
}

// 生成start.sh代码
int  gen_vm_start_code(char *vm_name)
{
	char *grub_boot[] = {
		"#!/bin/sh",
		"# tmux -2 -u new -d -s ${vm_name} \"/bin/sh ${vm_start_sh}\"",
		"# tmux attach-session -t ${vm_name}",
		"boot=\"${vm_bootfrom}\"",
		"while [ 1 ]; do",
		"	if [ \"$boot\" == \"hd0\" ]; then",
		"		${vm_grubhd}",
		"	else",
		"		${vm_grubcd}",
		"	fi",
		"	bhyve   -c ${vm_cpus} -m ${vm_ram} -HAPuw \\",
		"		-s 0:0,${vm_hostbridge} \\",
		"		-s 3:0,${vm_storage_interface},${vm_disk}  \\",
		"		-s 3:1,${vm_storage_interface},${vm_disk1} \\",
		"		-s 3:2,${vm_storage_interface},${vm_disk2} \\",
		"		-s 3:3,${vm_storage_interface},${vm_disk3} \\",
		"		-s 3:4,${vm_storage_interface},${vm_disk4} \\",
		"		-s 3:5,${vm_storage_interface},${vm_disk5} \\",
		"		-s 3:6,${vm_storage_interface},${vm_disk6} \\",
		"		-s 3:7,${vm_storage_interface},${vm_disk7} \\",
		"		-s 2:0,ahci-cd,${vm_iso} \\",
		"		-s 4:0,e1000,${vm_tap},mac=${vm_mac} \\",
		"		-s 4:1,e1000,${vm_tap1},mac=${vm_mac1} \\",
		"		-s 4:2,e1000,${vm_tap2},mac=${vm_mac2} \\",
		"		-s 4:3,e1000,${vm_tap3},mac=${vm_mac3} \\",
		"		-s 4:4,e1000,${vm_tap4},mac=${vm_mac4} \\",
		"		-s 4:5,e1000,${vm_tap5},mac=${vm_mac5} \\",
		"		-s 4:6,e1000,${vm_tap6},mac=${vm_mac6} \\",
		"		-s 4:7,e1000,${vm_tap7},mac=${vm_mac7} \\",
		"		-s 31,lpc -l com1,stdio \\",
		"		${vm_name}",
		"		",
		"	exit_stat=$?",
		"	if [ $exit_stat != 0 ]; then",
		"		break;",
		"	fi",
		"	/usr/sbin/bhyvectl --destroy --vm=${vm_name}",
		"	boot=\"hd0\"",
		"	bvm --hd-booting ${vm_name}",
		"done",
		"/usr/sbin/bhyvectl --destroy --vm=${vm_name}",
		"/sbin/ifconfig ${vm_tap} destroy",
		"/sbin/ifconfig ${vm_tap1} destroy",
		"/sbin/ifconfig ${vm_tap2} destroy",
		"/sbin/ifconfig ${vm_tap3} destroy",
		"/sbin/ifconfig ${vm_tap4} destroy",
		"/sbin/ifconfig ${vm_tap5} destroy",
		"/sbin/ifconfig ${vm_tap6} destroy",
		"/sbin/ifconfig ${vm_tap7} destroy",
		NULL
	};

	char *uefi_boot[] = {
		"#!/bin/sh",
		"boot=\"${vm_bootfrom}\"",
		"${vm_start_swtpm}",
		"while [ 1 ]; do",
		"	if [ \"$boot\" == \"hd0\" ]; then",
		"	bhyve 	-c ${vm_cpus} -m ${vm_ram} -HAPuw \\",
		"		-s 0:0,${vm_hostbridge} \\",
		"		-s 4:0,${vm_storage_interface},${vm_disk} \\",
		"		-s 4:1,${vm_storage_interface},${vm_disk1} \\",
		"		-s 4:2,${vm_storage_interface},${vm_disk2} \\",
		"		-s 4:3,${vm_storage_interface},${vm_disk3} \\",
		"		-s 4:4,${vm_storage_interface},${vm_disk4} \\",
		"		-s 4:5,${vm_storage_interface},${vm_disk5} \\",
		"		-s 4:6,${vm_storage_interface},${vm_disk6} \\",
		"		-s 4:7,${vm_storage_interface},${vm_disk7} \\",
		"		-s 5:0,e1000,${vm_tap} \\",
		"		-s 5:1,e1000,${vm_tap1} \\",
		"		-s 5:2,e1000,${vm_tap2} \\",
		"		-s 5:3,e1000,${vm_tap3} \\",
		"		-s 5:4,e1000,${vm_tap4} \\",
		"		-s 5:5,e1000,${vm_tap5} \\",
		"		-s 5:6,e1000,${vm_tap6} \\",
		"		-s 5:7,e1000,${vm_tap7} \\",
		//"		-s 29,fbuf,tcp=0.0.0.0:${vm_vncport},w=${vm_vncwidth},h=${vm_vncheight} \\",
		"		${vm_tpm_param}",
		"		-s 30,xhci,tablet \\",
		"		-s 31,lpc -l com1,stdio \\",
		"		-l bootrom,/usr/local/share/uefi-firmware/${vm_bhyve_uefi_fd} \\",
		"		${vm_name} ",

		"	else",
		"	bhyve 	-c ${vm_cpus} -m ${vm_ram} -HAPuw \\",
		"		-s 0:0,${vm_hostbridge} \\",
		"		-s 3:0,ahci-cd,${vm_iso} \\",
		"		-s 4:0,${vm_storage_interface},${vm_disk} \\",
		"		-s 4:1,${vm_storage_interface},${vm_disk1} \\",
		"		-s 4:2,${vm_storage_interface},${vm_disk2} \\",
		"		-s 4:3,${vm_storage_interface},${vm_disk3} \\",
		"		-s 4:4,${vm_storage_interface},${vm_disk4} \\",
		"		-s 4:5,${vm_storage_interface},${vm_disk5} \\",
		"		-s 4:6,${vm_storage_interface},${vm_disk6} \\",
		"		-s 4:7,${vm_storage_interface},${vm_disk7} \\",
		"		-s 5:0,e1000,${vm_tap} \\",
		"		-s 5:1,e1000,${vm_tap1} \\",
		"		-s 5:2,e1000,${vm_tap2} \\",
		"		-s 5:3,e1000,${vm_tap3} \\",
		"		-s 5:4,e1000,${vm_tap4} \\",
		"		-s 5:5,e1000,${vm_tap5} \\",
		"		-s 5:6,e1000,${vm_tap6} \\",
		"		-s 5:7,e1000,${vm_tap7} \\",
		"		-s 29,fbuf,tcp=0.0.0.0:${vm_vncport},w=${vm_vncwidth},h=${vm_vncheight},wait \\",
		"		${vm_tpm_param}",
		"		-s 30,xhci,tablet \\",
		"		-s 31,lpc -l com1,stdio \\",
		"		-l bootrom,/usr/local/share/uefi-firmware/${vm_bhyve_uefi_fd} \\",
		"		${vm_name} ",
		"	fi",
		"		",
		"	exit_stat=$?",
		"	if [ $exit_stat != 0 ]; then",
		"		break;",
		"	fi",
		"	/usr/sbin/bhyvectl --destroy --vm=${vm_name}",
		"	boot=\"hd0\"",
		"	bvm --hd-booting ${vm_name}",
		"done",
		"${vm_stop_swtpm}",
		NULL
	};


	vm_node *p;
	if ((p = find_vm_list(vm_name)) == NULL) return RET_FAILURE;
    
    // 检查并生成MAC地址
    int need_save = 0;
    for (int i=0; i<atoi(p->vm.nics); i++) {
        if (strlen(p->vm.nic[i].mac) == 0) {
            generate_mac(p->vm.nic[i].mac);
            need_save = 1;
        }
    }
    if (need_save) save_vm_info(vm_name, &p->vm);
	
	//生成启动代码
	char **code;
	if (strcmp(p->vm.boot_type, "grub") == 0) {
		code = grub_boot;
		gen_grub_boot_code(code, p);
	}
	else {
		code = uefi_boot;
		gen_uefi_boot_code(code, p);
	}

	return RET_SUCCESS;

	//写入启动代码
	//shell脚本
	//return write_boot_code(code, p);
}

// 设置vm的grubcmd字段
void set_grub_cmd(vm_node *p)
{
	char fn[BUFFERSIZE];
	sprintf(fn, "%s%s", osdir, "bvm.conf");
	init_config(fn);

	char item[BUFFERSIZE];
	char *value;
	if (strcmp(p->vm.bootfrom, "cd0") == 0) {
		sprintf(item, "%s_vm_grubcmd_cd", p->vm.ostype);
		if ((value = get_value_by_name(item)) != NULL)
			strcpy(p->vm.grubcmd, value);
		else {
			error("bvm.conf is error\n");
			err_exit();
		}
	}
	if (strcmp(p->vm.bootfrom, "hd0") == 0) {
		sprintf(item, "%s_vm_grubcmd_hdd", p->vm.ostype);
		if ((value = get_value_by_name(item)) != NULL)
			strcpy(p->vm.grubcmd, value);
		else {
			error("bvm.conf is error\n");
			err_exit();
		}
	}

	//设置grubcd/grubhd
	sprintf(item, "%s_vm_grubcmd_cd", p->vm.ostype);
	if ((value = get_value_by_name(item)) != NULL)
		strcpy(p->vm.grubcd, value);
	sprintf(item, "%s_vm_grubcmd_hdd", p->vm.ostype); 
	if ((value = get_value_by_name(item)) != NULL) 
		strcpy(p->vm.grubhd, value);

	
	free_config();
}

// 写入devicemap文件
int write_vm_device_map(vm_stru *vm)
{

	FILE *fp = fopen(vm->devicemap, "w");
	if (fp == NULL) {
		error("open %s error\n", vm->devicemap);
		return RET_FAILURE;
	}

	char buf[BUFFERSIZE];
	sprintf(buf, "(hd0) %s\n", vm->disk);
	fputs(buf, fp);

	sprintf(buf, "(cd0) %s\n", vm->iso);
	fputs(buf, fp);

	fclose(fp);

	return RET_SUCCESS;
}

// 创建网络 (Bridged or NAT)
int create_networking(char *vm_name)
{
	vm_node *p;
        if ((p = find_vm_list(vm_name)) == NULL) return RET_FAILURE;

	for (int n=0; n<atoi(p->vm.nics); n++) {
	
		cur_nic_idx = n;
		cur_vm = &p->vm;

		//桥接 Bridged
		if (strcmp(p->vm.nic[n].netmode, "Bridged") == 0) {

			if (create_bridged(p->vm.nic[n].bind) == RET_FAILURE) return RET_FAILURE;
		}
			

		//NAT
		else if (strcmp(p->vm.nic[n].netmode, "NAT") == 0) {

			if (create_nat(p->vm.nic[n].nat) == RET_FAILURE) return RET_FAILURE;
			run_cmd("set bvm_nat_fw=`sysctl net.inet.ip.forwarding=1`");
		}

		//错误
		else {
			return RET_FAILURE;
		}
		
		strcpy(p->vm.nic[n].bridge, bridge);
		strcpy(p->vm.nic[n].tap, tap);

		save_vm_info(vm_name, &p->vm);

		free_vnet_list(ALL);
	}

	return RET_SUCCESS;

}


// 字符串替换函数
// 将str中的ostr替换成nstr
void str_replace(char *str, char *ostr, const char *nstr)
{
    char *p;
    while ((p = strstr(str, ostr)))
    {
        int olen = strlen(ostr);
        int nlen = strlen(nstr);

        if (nlen > olen)  //新串长，向后移动
        {
            char *tmp = p;
            while (*tmp) tmp++;
            while (tmp>=p+olen)
            {
                *(tmp+(nlen-olen)) = *tmp;
                --tmp;
            }

        }
        else if (nlen < olen)   //新串短，向前移动
        {
            char *tmp = p+nlen;
            while(*(tmp+olen-nlen))
            {
                *tmp = *(tmp+olen-nlen);
                ++tmp;
            }
            *tmp = '\0';

        }
        strncpy(p, nstr, nlen);
    }

}

// 检测vm名称的拼写
int  check_spell(char *vm_name)
{
	if (vm_name == NULL) return RET_FAILURE;
	if (strlen(vm_name) == 0) return RET_FAILURE;

	char *p = vm_name;
	char ch = *p;
	if (isalpha(ch++) == 0) return RET_FAILURE;
	while (ch) {
		if (isalpha(ch) || isdigit(ch) || ch == '_' || ch == '-') {
		       ch = *++p;
		}
		else		
			return RET_FAILURE;
	}
	return RET_SUCCESS;
}

// 获得某个进程id
int bvm_get_pid(char *name)
{
	int pid;
	char cmd[BUFFERSIZE];
	sprintf(cmd, "ps | grep \"%s\" | grep -v grep | awk '{print $1}'", name);
	char buf[16];
	FILE *fp = popen(cmd, "r");
	if (fgets(buf, 16, fp)) {
		buf[strlen(buf)-1] = '\0';
		pid = atoi(buf);
	}
	else
		pid = -1;

	pclose(fp);

	return pid;
}


// 获得vm的进程id
int get_vm_pid(vm_stru *vm)
{
	int pid;
	char cmd[BUFFERSIZE];
	//sprintf(cmd, "ps | grep \"bvmb %s\" | grep -v csh | grep -v grep | awk '{print $1}'", vm->name);
	sprintf(cmd, "ifconfig %s | grep Opened | awk '{print $4}'", vm->nic[0].tap);
	char buf[16];
	FILE *fp = popen(cmd, "r");
	if (fgets(buf, 16, fp)) {
		buf[strlen(buf)-1] = '\0';
		pid = atoi(buf);
	}
	else
		pid = -1;

	pclose(fp);

	return pid;
}

// 获得bvmb的进程id
int get_bvmb_pid(vm_stru *vm)
{
	int pid;
	char cmd[BUFFERSIZE];
	sprintf(cmd, "ps | grep -w \"bvmb %s\" | grep -v \"c bvmb %s\" | grep -v grep | awk '{print $1}'", vm->name, vm->name);

	char buf[16];
	FILE *fp = popen(cmd, "r");
	if (fgets(buf, 16, fp)) {
		buf[strlen(buf)-1] = '\0';
		pid = atoi(buf);
	}
	else
		pid = -1;

	pclose(fp);

	return pid;
}

// 获取是否存在参数hw.vmm.vmx.initialized(存在:1,不存在:0)
int exist_hw_vmm_vmx_initialized(vm_stru *vm)
{
	int value;
	char cmd[BUFFERSIZE];
	sprintf(cmd, "sysctl -a | grep hw.vmm.vmx.initialized");
	char buf[16];
	FILE *fp = popen(cmd, "r");
	if (fgets(buf, 16, fp))
		value = 1;
	else
		value = 0;
	pclose(fp);

	return value;
}

// 获取是否支持虚拟化
int get_vmx(vm_stru *vm)
{
	int value;
	char cmd[BUFFERSIZE];
	sprintf(cmd, "sysctl hw.vmm.vmx.initialized | awk -F: '{print $2}'");
	char buf[16];
	FILE *fp = popen(cmd, "r");
	if (fgets(buf, 16, fp)) {
		buf[strlen(buf)-1] = '\0';
		value = atoi(buf);
	}
	else
		value = -1;

	pclose(fp);

	return value;
}

// 获得bvm支持os的启动状态
void get_bvm_os(os_stru *os)
{
	//if (os->type == NULL) return;

	int n = 0;
	while (strlen(bvm_os[n].type) > 0) {
		if (strcmp(bvm_os[n].type, os->type) == 0) {
			os->uefi_boot = bvm_os[n].uefi_boot;
			os->grub_boot = bvm_os[n].grub_boot;
			os->grub_cmd  = bvm_os[n].grub_cmd;
			return;
		}
		++n;
	}
}

// 检测操作系统对uefi的支持
int support_uefi(char *os)
{
	int n = 0;
	while (strlen(bvm_os[n].type) > 0) {
		if (strcmp(bvm_os[n].type, os) == 0) {
			return bvm_os[n].uefi_boot;
		}
		++n;
	}
	return -1;
}

// 检测操作系统对grub的支持
int support_grub(char *os)
{
	int n = 0;
	while (strlen(bvm_os[n].type) > 0) {
		if (strcmp(bvm_os[n].type, os) == 0) {
			return bvm_os[n].grub_boot;
		}
		++n;
	}
	return -1;
}

/*
// 磁盘文件在conf中的偏移量
int disk_offset(vm_stru *vm)
{
	return &vm->img1size - &vm->imgsize;
}
*/

// 检查磁盘空间的有效性
int check_vm_disks(vm_stru *vm)
{
	//int offset = &vm->img1size - &vm->imgsize;
	int disks = atoi(vm->disks);
	if (disks == 0) return -1;
	for (int n=0; n<disks; n++) {
		//if (strlen((char*)(&vm->imgsize + n * offset)) == 0)
		if (strlen(vm->vdisk[n].size) == 0)
			return -1;
	}
	return 1;
}

// 发生错误时退出处理函数
void err_exit()
{
	//释放vm和vnet分配的内存
	vm_end();
	free_vnet_list(ALL);

	exit(1);
}

// 执行wait处理函数
// func为需等待完成的函数
// args为func的参数
// 如果多个参数，需要使用结构体进行强制转换
int wait_exec(fun func, void *args)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	pid_t pid;

	pid = fork();

	if (pid == 0) waitting();
	else if (pid < 0) error("fork error\n");
	else {
		int ret;
		//ret = (func)(args);
		//ret = (int)(func)(args);
		ret = (intptr_t)(func)(args); 
		kill(pid, SIGTERM);
		printf("\033[100D\033[K\033[?25h\033[0m");
		//printf("\n");
		return ret;
	}
	return 0;
}

// waitting
void waitting()
{
	char *msg = "\033[32m\033[?25l";
	char ch[4] = {'\\', '|', '/', '-'};

	printf(" %s", msg);

	int n = 0;
	while (1) {
		printf("%c", ch[n]);
		usleep(100000);
		printf("\033[1D");
		if (++n >= 4) n = 0;
	}
}

// 时间延迟
// 参数sec为延迟秒数
void delay(int sec)
{
	 clock_t start, finish;
         start = clock();
 	 while (1) {
		finish = clock();
		double pass = (double)(finish - start) / CLOCKS_PER_SEC;
		if ((int)pass > sec) {
			return;
		}
	}

}

//输出最新的地址池分配情况
void show_dhcp_pool()
{
	char fn[FN_MAX_LEN];
	sprintf(fn, "%s/%s", vmdir, dhcp_pool_file);

     	FILE *fp;
	if ((fp = fopen(fn, "r")) == NULL) return;

	char line[BUFFERSIZE];
	while (fgets(line , BUFFERSIZE, fp)) {
		printf("%s", line);
	}

	fclose(fp);

}

// 错误信息（红色高亮）
int error(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	//屏幕输出
	printf("\033[1;31m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	
	//日志输出
	write_log_time();
	if (logfp) {
		fprintf(logfp, "[error] ");
		va_start(argptr, fmt);
		cnt = vfprintf(logfp, fmt, argptr);
		va_end(argptr);
	
		if (lastch(fmt) != '\n') fprintf(logfp, "\n");

		fclose(logfp);
	}
	
	return cnt;
}

// 调试输出
int debug(unsigned color, char *fmt, ...)
{	
#ifdef BVM_DEBUG
	va_list argptr;
	int cnt;

	if (color == NOCOLOR)
		printf("\033[m");
	if (color == RED)
		printf("\033[1;31m");
	if (color == GREEN)
		printf("\033[32m");
	if (color == YELLOW)
		printf("\033[1;33m");

	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;
#else
	return 0;
#endif
}

// 严重警告信息（红色高亮闪烁）
int WARN(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	printf("\033[1;5;31m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;

}


// 警告信息（黄色高亮）
int warn(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	printf("\033[1;33m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;

}

// 成功信息（绿色高亮）
int success(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	printf("\033[1;32m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;

}

// 输出文字(绿色)
int green(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	printf("\033[32m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;

}

// 输出文字(红色高亮)
int red(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	printf("\033[1;31m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;

}

// 标题格式输出（下划线+高亮）
int title(char *fmt, ...)
{
	va_list argptr;
	int cnt;

	printf("\033[4;1m");
	va_start(argptr, fmt);
	cnt = vprintf(fmt, argptr);
	va_end(argptr);
	printf("\033[0m");
	return cnt;

}


// 获取实际的CPU频率
unsigned long long get_cpu_frequency()
{
    unsigned long long freq = 0;
    size_t size = sizeof(freq);
    if (sysctlbyname("hw.clockrate", &freq, &size, NULL, 0) == -1) {
        perror("sysctl");
        return 2000000000ULL; // 默认值为2GHz
    }
    return freq * 1000000ULL; // 将MHz转换为Hz
}

// 将CPU时钟周期转换为可读的时间格式
void format_cpu_time(unsigned long long ticks, char *buf, size_t bufsize, unsigned long long cpu_freq)
{
    // 将时钟周期转换为秒
    unsigned long long total_seconds = ticks / cpu_freq;
    
    // 计算时、分、秒
    unsigned long hours = total_seconds / 3600;
    unsigned long minutes = (total_seconds % 3600) / 60;
    unsigned long seconds = total_seconds % 60;
    
    if (hours > 0) {
        snprintf(buf, bufsize, "%lu时%lu分%lu秒", hours, minutes, seconds);
    } else if (minutes > 0) {
        snprintf(buf, bufsize, "%lu分%lu秒", minutes, seconds);
    } else {
        snprintf(buf, bufsize, "%lu秒", seconds);
    }
}

// 格式化字节大小为可读格式
void format_bytes(unsigned long long bytes, char *buf, size_t bufsize)
{
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    double size = bytes;
    
    while (size >= 1024 && i < 4) {
        size /= 1024;
        i++;
    }
    
    if (i == 0) {
        snprintf(buf, bufsize, "%.0f %s", size, units[i]);
    } else {
        snprintf(buf, bufsize, "%.2f %s", size, units[i]);
    }
}

void vm_show_stats(const char *vm_name) {
    vm_node *p;
    if ((p = find_vm_list(vm_name)) == NULL) {
        error("VM '%s' not found\n", vm_name);
        return;
    }

    if (get_vm_status(vm_name) != VM_ON) {
        error("VM '%s' is not running\n", vm_name);
        return;
    }

    char cmd[BUFFERSIZE];
    FILE *fp;
    char line[BUFFERSIZE];

    // --- 1. 基础设施指标 ---
    title("\n[ Infrastructure Metrics ]\n");

    // CPU使用率和运行时间 CPU Stats
    unsigned long long total_runtime = 0;
    unsigned long long idle_ticks = 0;
    double cpu_usage = 0.0;
    char runtime_str[64] = "0s";
    
    // 虚拟机退出和中断计数器 VM Exits & Interrupts counters
    unsigned long long total_exits = 0;
    unsigned long long io_intercept = 0;
    unsigned long long hlt_intercept = 0;
    unsigned long long inst_emul = 0;
    unsigned long long nmi_count = 0;

    sprintf(cmd, "bhyvectl --vm=%s --get-stats", vm_name);
    fp = popen(cmd, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "total runtime")) {
                sscanf(line, "%*[^0-9]%llu", &total_runtime);
            } else if (strstr(line, "ticks vcpu was idle")) {
                sscanf(line, "%*[^0-9]%llu", &idle_ticks);
            } else if (strstr(line, "total number of vm exits")) {
                sscanf(line, "%*[^0-9]%llu", &total_exits);
            } else if (strstr(line, "number of times in/out was intercepted")) { // IO
                sscanf(line, "%*[^0-9]%llu", &io_intercept);
            } else if (strstr(line, "number of times hlt was intercepted")) { // HLT
                sscanf(line, "%*[^0-9]%llu", &hlt_intercept);
            } else if (strstr(line, "vm exits for instruction emulation")) { // Emulation
                sscanf(line, "%*[^0-9]%llu", &inst_emul);
            } else if (strstr(line, "NMIs delivered")) {
                sscanf(line, "%*[^0-9]%llu", &nmi_count);
            }
        }
        pclose(fp);
    }
    
    // 计算CPU使用率和运行时间
    if (total_runtime > 0) {
        unsigned long long idle_time_ns = idle_ticks * 1000000ULL;
        if (idle_time_ns <= total_runtime) {
            cpu_usage = 100.0 * (1.0 - ((double)idle_time_ns / total_runtime));
        } else {
             cpu_usage = 0.0;
        }
        if (cpu_usage < 0) cpu_usage = 0;
        if (cpu_usage > 100) cpu_usage = 100;

        unsigned long long seconds = total_runtime / 1000000000ULL;
        unsigned long hours = seconds / 3600;
        unsigned long minutes = (seconds % 3600) / 60;
        unsigned long secs = seconds % 60;
        if (hours > 0) snprintf(runtime_str, sizeof(runtime_str), "%luh %lum %lus", hours, minutes, secs);
        else if (minutes > 0) snprintf(runtime_str, sizeof(runtime_str), "%lum %lus", minutes, secs);
        else snprintf(runtime_str, sizeof(runtime_str), "%lus", secs);
    }

    printf("CPU Usage      : %.2f%% (Allocated: %s Cores)\n", cpu_usage, p->vm.cpus);

    // 内存使用率和运行时间
    unsigned long long resident_mem = 0;
    unsigned long long total_mem_bytes = parse_size(p->vm.ram);
    double mem_usage = 0.0;
    char resident_str[64] = "0B";

    sprintf(cmd, "bhyvectl --vm=%s --get-stats | grep 'Resident memory' | awk '{print $3}'", vm_name);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            resident_mem = strtoull(line, NULL, 10);
            format_bytes(resident_mem, resident_str, sizeof(resident_str));
            if (total_mem_bytes > 0)
                 mem_usage = (double)resident_mem / total_mem_bytes * 100.0;
        }
        pclose(fp);
    }
    printf("Memory Usage   : %.2f%% (Allocated: %s, Active: %s)\n", mem_usage, p->vm.ram, resident_str);

    // 磁盘I/O和容量
    printf("Disk I/O & Cap :\n");
    int disk_count = atoi(p->vm.disks);
    for (int i=0; i < disk_count; i++) {
         struct stat st;
         unsigned long long used_size = 0;
         char used_str[64];
         if (strlen(p->vm.vdisk[i].path) > 0) {
             if (stat(p->vm.vdisk[i].path, &st) == 0) {
                 used_size = (unsigned long long)st.st_blocks * 512;
             }
         }
         format_bytes(used_size, used_str, sizeof(used_str));
         printf("  - %-10s : Cap: %s, Used: %s (%s)\n", 
                strlen(p->vm.vdisk[i].name) > 0 ? p->vm.vdisk[i].name : "disk", 
                p->vm.vdisk[i].size, 
                used_str,
                p->vm.vdisk[i].path);

        // ZFS 磁盘使用率
        if (strcmp(p->vm.zfs, "on") == 0) {
            if (strncmp(p->vm.vdisk[i].path, "/dev/zvol/", 10) == 0) {
                 char *dataset = p->vm.vdisk[i].path + 10;
                 char ratio[16] = "-";
                 // Get compress ratio
                 sprintf(cmd, "zfs get -H -o value compressratio %s 2>/dev/null", dataset);
                 fp = popen(cmd, "r");
                 if(fp) {
                     if(fgets(line, sizeof(line), fp)) {
                         line[strcspn(line, "\n")] = 0;
                         strcpy(ratio, line);
                     }
                     pclose(fp);
                 }
                 if (strcmp(ratio, "-") != 0 && strlen(ratio) > 0) {
                     printf("    [ZFS] Ratio: %s, Dataset: %s\n", ratio, dataset);
                 }
            }
        }
    }

    // 网络流量 Network Traffic
    printf("Network Traffic:\n");
    int nic_count = atoi(p->vm.nics);
    for (int i = 0; i < nic_count; i++) {
        unsigned long long bytes_in = 0, bytes_out = 0;
        unsigned long long pkts_in = 0, pkts_out = 0;
        unsigned long long drops = 0;
        
        sprintf(cmd, "netstat -I %s -b -d -n | tail -n 1", p->vm.nic[i].tap);
        fp = popen(cmd, "r");
        if (fp) {
             if (fgets(line, sizeof(line), fp)) {
                 unsigned long long err_in=0, drop_in=0, err_out=0, drop_out=0;
                 sscanf(line, "%*s %*d %*s %*s %llu %llu %llu %llu %llu %llu %llu %llu",
                        &pkts_in, &err_in, &drop_in, &bytes_in,
                        &pkts_out, &err_out, &bytes_out, &drop_out);
                 drops = drop_in + drop_out;
             }
             pclose(fp);
        }
        
        char in_str[64], out_str[64];
        format_bytes(bytes_in, in_str, sizeof(in_str));
        format_bytes(bytes_out, out_str, sizeof(out_str));
        
        printf("  - %-10s : RX: %s / TX: %s (Drops: %llu)\n", 
               p->vm.nic[i].tap, in_str, out_str, drops);
    }
    
    // --- 2. 高级统计信息 ---
    title("\n[ Advanced VM Stats ]\n");
    printf("VM Exits       : %'llu (Rate: ~%.0f/sec)\n", total_exits, total_runtime > 0 ? (double)total_exits / (total_runtime/1000000000.0) : 0);
    printf("  - IO Access  : %'llu\n", io_intercept);
    printf("  - Emulation  : %'llu\n", inst_emul);
    printf("  - Interrupts : %'llu (NMI: %llu)\n", hlt_intercept, nmi_count);

    // --- 3. 可用性和服务 ---
    title("\n[ Availability & Services ]\n");
    
    // PID
    int pid = get_vm_pid(&p->vm);
    if (pid <= 0) {
        sprintf(cmd, "pgrep -f 'bhyve: %s'", vm_name);
        fp = popen(cmd, "r");
        if(fp) {
             if(fgets(line, sizeof(line), fp)) pid = atoi(line);
             pclose(fp);
        }
    }
    printf("PID            : %d\n", pid);

    // 主机负载	Host Load
    double load[3];
    if (getloadavg(load, 3) != -1) {
        printf("Host Load Avg  : %.2f, %.2f, %.2f\n", load[0], load[1], load[2]);
    }
    
    // 运行时间	Uptime
    char process_runtime[64] = "Unknown";
    sprintf(cmd, "ps -o etime= -p %d", pid);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = 0;
            char *ptr = line;
            while(*ptr == ' ') ptr++;
            strcpy(process_runtime, ptr);
        }
        pclose(fp);
    }
    printf("Status         : Online\n");
    printf("Uptime         : %s (Process)\n", process_runtime);
    printf("Boot Time      : %s (CPU Runtime)\n", runtime_str);

    // VNC
    if (strcmp(p->vm.vncstatus, "on") == 0) {
        printf("VNC Service    : Enabled (Port: %s, Listen: %s)\n", 
               p->vm.vncport, strlen(p->vm.vncbind)>0 ? p->vm.vncbind : "Default");
    } else {
        printf("VNC Service    : Disabled\n");
    }
    
    // Port Forwarding Check
    if (strcmp(p->vm.nic[0].rpstatus, "on") == 0 || p->vm.nic[0].rpnum > 0) {
         printf("Port Forward   : Active (%d rules)\n", p->vm.nic[0].rpnum);
    }
    
    printf("\n");
}

// 辅助函数：解析内存大小字符串（如 "4G"）转换为字节数
unsigned long long parse_size(const char *size_str) {
    unsigned long long size;
    char unit;
    sscanf(size_str, "%llu%c", &size, &unit);
    
    switch (toupper(unit)) {
        case 'G': return size * 1024 * 1024 * 1024;
        case 'M': return size * 1024 * 1024;
        case 'K': return size * 1024;
        default: return size;
    }
}