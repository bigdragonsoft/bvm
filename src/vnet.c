/*--------------------------------------------

 桥接方式：
     将所有tap加入bridge0，也将em0加入bridge0

    tap0  tap1  tap2
     |     |     |
     +-----+-----+
           |
           V
      +---------+
      | bridge0 |
      +---------+
           A
           |
          em0


 NAT方式：
    将所有tap加入bridge0，em0不加入
    bridge0起网关IP，防火墙起NAT

           em0
            |
            V
    +---------------+
    | ipfw 端口转发 |
    +---------------+
            |
            |       tap0  tap1  tap2
            |        |     |     |
            |        +-----+-----+
            |              |
            |              V
            |         +---------+
            +-------->| bridge0 |
                      +---------+
 
 --------------------------------------------*/
#include "vnet.h"
#include "vm.h"
#include "config.h"

char *bridge_list[VNET_LISTSIZE] = {0};
char *tap_list[VNET_LISTSIZE] = {0};
nat_stru *nat_list[VNET_LISTSIZE] = {0};
nat_stru *switch_list[VNET_LISTSIZE] = {0};

char bridge[VNET_BUFFERSIZE];
char tap[VNET_BUFFERSIZE];
char nic[VNET_BUFFERSIZE];
char nic_list[VNET_LISTSIZE][VNET_BUFFERSIZE];

nat_stru nat;
nat_stru Switch;

int cur_nic_idx = 0;
vm_stru *cur_vm = NULL;

// 字符串最后一个字符
char lastch(char *s)
{
	if (s == NULL) return 0;
	return s[strlen(s)-1];
}

// 字符串转换成小写
char *strtolower(char *s)
{
	char *p = s;
	while ((*p = tolower(*p))) p++;
	return s;
}

// 字符串转换成大写
char *strtoupper(char *s)
{
	char *p = s;
	while ((*p = toupper(*p))) p++;
	return s;
}

// 截取字符串右边n个字符
char *rightstr(char *dst, char *src, int n)
{
	char *p = src;  
	char *q = dst;  
	int len = strlen(src);  
	if (n > len) n = len;  
	p += (len-n);   //从右边第n个字符开始，到0结束  
	while ((*(q++) = *(p++)));  
	return dst;  
}

// 截取字符串左边n个字符
char *leftstr(char *dst,char *src, int n)  
{  
	char *p = src;  
	char *q = dst;  
	int len = strlen(src);  
	if (n > len) n = len;  
	while (n--) *(q++) = *(p++);  
	*(q++) = '\0';  
	return dst;  
}  

// 删除字符串左侧空白
void ltrim(char *s)
{
	char *p;
	p = s;
	while (*p == ' ' || *p == '\t') p++;
	strcpy(s, p);
}

// 删除字符串右侧空白
void rtrim(char *s)
{
	int i;

	i = strlen(s) - 1;
	while ((s[i] == ' ' || s[i] == '\t') && i >= 0) i--;
	s[i+1] = '\0';
}

// 删除字符串两侧空白
void trim(char *s)
{
	ltrim(s);
	rtrim(s);
}

// 网桥相关命令
void run_bridge_command(int action)
{
	char cmd[CMD_MAX_LEN] = {0};

	switch (action) {
	case CREATE_BRIDGE:
		sprintf(cmd, "ifconfig %s create", bridge);
		break;
	case CREATE_TAP:
		sprintf(cmd, "ifconfig %s create", tap);
		break;
	case DESTROY_BRIDGE:
		sprintf(cmd, "ifconfig %s destroy", bridge);
		break;
	case DESTROY_TAP:
		sprintf(cmd, "ifconfig %s destroy", tap);
		break;
	case SET_NAT_IP:
		sprintf(cmd, "ifconfig %s inet %s", bridge, nat.ip);
		break;
	case SET_SWITCH_IP:
		sprintf(cmd, "ifconfig %s inet %s", bridge, Switch.ip);
		break;
	case SET_NAT_DESC:
		sprintf(cmd, "ifconfig %s description \"%s\"", bridge, nat.desc);
		break;
	case SET_SWITCH_DESC:
		sprintf(cmd, "ifconfig %s description \"%s\"", bridge, Switch.desc);
		break;
	case SET_TAP_DESC:
		sprintf(cmd, "ifconfig %s description \"%s-nic%d\"", tap, cur_vm->name, cur_nic_idx);
		break;
	case SET_DESC:
		sprintf(cmd, "ifconfig %s description \"%s\"", bridge, VNET_BRIDGED_DESC);
		break;
	case UNSET_DESC:
		sprintf(cmd, "ifconfig %s -description", bridge);
		break;
	case ADD_NIC:
		sprintf(cmd, "ifconfig %s addm %s", bridge, nic);
		break;
	case ADD_TAP:
		sprintf(cmd, "ifconfig %s addm %s", bridge, tap);
		break;
	case ADD_TAP_NIC:	
		sprintf(cmd, "ifconfig %s addm %s addm %s", bridge, tap, nic);
		break;
	case UP_BRIDGE:
		sprintf(cmd, "ifconfig %s up", bridge);
		break;
	case UP_TAP:
		sprintf(cmd, "ifconfig %s up", tap);
		break;
	case DEL_TAP:
		sprintf(cmd, "ifconfig %s deletem %s", bridge, tap);
		break;
	case DEL_NIC:
		sprintf(cmd, "ifconfig %s deletem %s", bridge, nic);
		break;
	default:
		break;
	}

	FILE *fp;
	if (strlen(cmd) > 0) {
		if ((fp = popen(cmd, "r")) == NULL) {
			error("can't run the bridge command\n");
			err_exit();
		}

		pclose(fp);
	}
}

// 建立NAT
int create_nat(char *nat_name)
{

	//获取可用的bridge,tap以及物理网卡
	//get_nic_name(0, nic);
	get_nic_list();
	get_new_tap(tap);
	get_new_bridge(bridge);

	//获取nat信息
	if (get_nat_info(nat_name) == NULL) {
		error("%s not found\n", nat_name);
		err_exit();
	}

	//若没有网桥
	//则获取可用的bridge和tap，建立NAT
	//并设置网桥IP
	char **p = bridge_list;
	if (*p == NULL) {
		run_bridge_command(CREATE_BRIDGE);
		run_bridge_command(SET_NAT_DESC);
		run_bridge_command(SET_NAT_IP);
		run_bridge_command(UP_BRIDGE);
		run_bridge_command(CREATE_TAP);
		run_bridge_command(SET_TAP_DESC);
		run_bridge_command(UP_TAP); 
		run_bridge_command(ADD_TAP);
		return RET_SUCCESS;
	}

	//查找有desc标志的网桥
	char bridge_desc[VNET_BUFFERSIZE];
	find_desc_in_all_bridges("NAT", bridge_desc);

	int n = 0;
	while (strlen(nic_list[n]) > 0) {
		
		//依次对比每块物理网卡
		strcpy(nic, nic_list[n]);

		//查找含有物理网卡的网桥
		char bridge_nic[VNET_BUFFERSIZE];
		find_nic_in_all_bridges(bridge_nic);


		//若有网桥
		//若存在含desc标志的网桥，且这个网桥不包含物理网卡，则添加tap
		//if (*bridge_desc != NULL && strcmp(bridge_desc, bridge_nic) != 0) {
		if (*bridge_desc && strcmp(bridge_desc, bridge_nic) != 0) {

			strcpy(bridge, bridge_desc);
			run_bridge_command(CREATE_TAP);
			run_bridge_command(SET_TAP_DESC);
			run_bridge_command(UP_TAP);
			run_bridge_command(ADD_TAP);
			return RET_SUCCESS;

		}

		//若存在含desc标志的网桥，但这个网桥包含了物理网卡，则无法创建NAT
		//if (*bridge_desc != NULL && strcmp(bridge_desc, bridge_nic) == 0) {
		if (*bridge_desc && strcmp(bridge_desc, bridge_nic) == 0) {

			++n;
		}

		//若不存在含有desc标志的网桥，则新建一个网桥并添加tap，并设置网桥网关
		//if (*bridge_desc == NULL) {
		if (*bridge_desc == 0) {

			run_bridge_command(CREATE_BRIDGE);
			run_bridge_command(SET_NAT_DESC);
			run_bridge_command(SET_NAT_IP);
			run_bridge_command(UP_BRIDGE);
			run_bridge_command(CREATE_TAP);
			run_bridge_command(SET_TAP_DESC);
			run_bridge_command(UP_TAP); 
			run_bridge_command(ADD_TAP);
			return RET_SUCCESS;

		}
	}
	error("can't create NAT\n");
	err_exit();
	return RET_FAILURE;
}

// 建立桥接
int  create_bridged(char *bind)
{

	get_nic_list();
	if (strstr(bind, "switch")) return create_switch(bind);

	//获取可用的bridge,tap以及物理网卡
	//get_nic_name(0, nic);
	strcpy(nic, bind);
	get_new_tap(tap);
	get_new_bridge(bridge);

	//若没有网桥
	//则获取可用bridge和tap，并建立桥接
	char **p = bridge_list;
	if (*p == NULL) {
		run_bridge_command(CREATE_BRIDGE);
		run_bridge_command(SET_DESC);
		run_bridge_command(UP_BRIDGE);
		run_bridge_command(CREATE_TAP);
		run_bridge_command(SET_TAP_DESC);
		run_bridge_command(UP_TAP);
		run_bridge_command(ADD_TAP_NIC);
		return RET_SUCCESS;
	}	

	//查找含有物理网卡的网桥
	char bridge_nic[VNET_BUFFERSIZE];
	find_nic_in_all_bridges(bridge_nic);

	//查找有desc标志的网桥
	char bridge_desc[VNET_BUFFERSIZE];
	find_desc_in_all_bridges("Bridged", bridge_desc);

	//若没有含物理网卡的网桥，也没有含desc标志的网桥，则新建一个网桥并添加物理网卡和tap
	//if (*bridge_nic == NULL && *bridge_desc == NULL) {	
	if (*bridge_nic == 0 && *bridge_desc == 0) {	
		
		run_bridge_command(CREATE_BRIDGE);
		run_bridge_command(SET_DESC);
		run_bridge_command(UP_BRIDGE);
		run_bridge_command(CREATE_TAP);
		run_bridge_command(SET_TAP_DESC);
		run_bridge_command(UP_TAP);
		run_bridge_command(ADD_TAP_NIC);
		return RET_SUCCESS;

	}

	//若没有含物理网卡的网桥，但有含有desc标志的网桥，则在含desc标志的网桥上添加物理网卡和tap
	//if (*bridge_nic == NULL && *bridge_desc != NULL) {
	if (*bridge_nic == 0 && *bridge_desc != 0) {

		strcpy(bridge, bridge_desc);
		run_bridge_command(UP_BRIDGE);
		run_bridge_command(CREATE_TAP);
		run_bridge_command(SET_TAP_DESC);
		run_bridge_command(UP_TAP);
		run_bridge_command(ADD_TAP_NIC);
		return RET_SUCCESS;

	}

	//若存在含物理网卡的网桥，但此网桥无desc标志，则无法建立一个桥接
	if (strcmp(bridge_nic, bridge_desc) != 0) {

		error("can't create Bridged\n");
		err_exit();

	}

	//若存在含物理网卡的网桥，且此网桥有desc标志，则在此网桥上添加tap
	if (strcmp(bridge_nic, bridge_desc) == 0) {

		strcpy(bridge, bridge_nic);
		run_bridge_command(UP_BRIDGE);
		run_bridge_command(CREATE_TAP);
		run_bridge_command(SET_TAP_DESC);
		run_bridge_command(UP_TAP);
		run_bridge_command(ADD_TAP);
		return RET_SUCCESS;
	}

	return RET_FAILURE;
}

// 建立桥接switch
int  create_switch(char *switch_name)
{

	//获取可用的bridge,tap以及物理网卡
	strcpy(nic, switch_name);
	get_new_tap(tap);
	get_new_bridge(bridge);

	//获取switch信息
	if (get_switch_info(switch_name) == NULL) {
		error("%s not found\n", switch_name);
		err_exit();
	}

	//若没有网桥
	//则获取可用的bridge和tap，建立switch
	//并设置网桥IP
	char **p = bridge_list;
	if (*p == NULL) {
		run_bridge_command(CREATE_BRIDGE);
		run_bridge_command(SET_SWITCH_DESC);
		run_bridge_command(SET_SWITCH_IP);
		run_bridge_command(UP_BRIDGE);
		run_bridge_command(CREATE_TAP);
		run_bridge_command(SET_TAP_DESC);
		run_bridge_command(UP_TAP); 
		run_bridge_command(ADD_TAP);
		return RET_SUCCESS;
	}

	//查找有desc标志的网桥
	char bridge_desc[VNET_BUFFERSIZE];
	find_desc_in_all_bridges("switch", bridge_desc);

	int n = 0;
	while (strlen(nic_list[n]) > 0) {
		
		//依次对比每块物理网卡
		strcpy(nic, nic_list[n]);

		//查找含有物理网卡的网桥
		char bridge_nic[VNET_BUFFERSIZE];
		find_nic_in_all_bridges(bridge_nic);


		//若有网桥
		//若存在含desc标志的网桥，且这个网桥不包含物理网卡，则添加tap
		//if (*bridge_desc != NULL && strcmp(bridge_desc, bridge_nic) != 0) {
		if (*bridge_desc != 0 && strcmp(bridge_desc, bridge_nic) != 0) {

			strcpy(bridge, bridge_desc);
			run_bridge_command(CREATE_TAP);
			run_bridge_command(SET_TAP_DESC);
			run_bridge_command(UP_TAP);
			run_bridge_command(ADD_TAP);
			return RET_SUCCESS;

		}

		//若存在含desc标志的网桥，但这个网桥包含了物理网卡，则无法创建NAT
		//if (*bridge_desc != NULL && strcmp(bridge_desc, bridge_nic) == 0) {
		if (*bridge_desc != 0 && strcmp(bridge_desc, bridge_nic) == 0) {

			++n;
		}

		//若不存在含有desc标志的网桥，则新建一个网桥并添加tap，并设置网桥网关
		//if (*bridge_desc == NULL) {
		if (*bridge_desc == 0) {

			run_bridge_command(CREATE_BRIDGE);
			run_bridge_command(SET_SWITCH_DESC);
			run_bridge_command(SET_SWITCH_IP);
			run_bridge_command(UP_BRIDGE);
			run_bridge_command(CREATE_TAP);
			run_bridge_command(SET_TAP_DESC);
			run_bridge_command(UP_TAP); 
			run_bridge_command(ADD_TAP);
			return RET_SUCCESS;

		}
	}
	error("can't create switch\n");
	err_exit();
	return RET_FAILURE;
}


// 获取网桥description字段
// 参数：desc为回传参数
void get_bridge_desc(char *bridge, char *desc)
{
	char cmd[CMD_MAX_LEN];
	sprintf(cmd, "ifconfig %s | grep description | awk -F: '{print $2}'", bridge);

	FILE *fp = popen(cmd, "r");
	if (fp == NULL) {
		error("can't get desc in bridge\n");
		err_exit();
	}

	char buf[BUFFERSIZE];
	fgets(buf, BUFFERSIZE, fp);
	buf[strlen(buf)-1] = '\0';
	ltrim(buf);

	if (strlen(buf) == 0) {
		pclose(fp);
		//*desc = NULL;
		*desc = 0;
	}
	else {
		strcpy(desc, buf);
		pclose(fp);
	}
}

// 查找符合description字段的网桥
void find_desc_in_all_bridges(char *mode, char *bridge)
{
	int n = 0;
	char desc[VNET_BUFFERSIZE] = {0};
	char **p = bridge_list;
	while (*(p+n)) {

		get_bridge_desc(*(p+n), desc);

		if (strcmp(mode, "Bridged") == 0) {
			if (strcmp(desc, VNET_BRIDGED_DESC) == 0) {
				strcpy(bridge, *(p+n));
				return;
			}
		}

		if (strcmp(mode, "NAT") == 0) {
			if (strcmp(desc, nat.desc) == 0) {
				strcpy(bridge, *(p+n));
				return;
			}
		}

		if (strcmp(mode, "switch") == 0) {
			if (strcmp(desc, Switch.desc) == 0) {
				strcpy(bridge, *(p+n));
				return;
			}
		}

		++n;
	}

	//*bridge = NULL;
	*bridge = 0;
	return;
}

// 查找含有物理网卡的网桥
// bridge为回传参数
void find_nic_in_all_bridges(char *bridge)
{
	int n = 0;
	char **p = bridge_list;
	while (*(p+n)) {

		if (check_nic_in_bridge(*(p+n), nic) == VNET_TRUE) {
			strcpy(bridge, *(p+n));
			return;
		}
		++n;
	}

	//*bridge = NULL;
	*bridge = 0;
	return;
}

// 检测网桥是否包含物理网卡
int  check_nic_in_bridge(char *bridge, char *nic)
{
	char cmd[CMD_MAX_LEN];
	sprintf(cmd, "ifconfig %s | grep member | awk -F: '{print $2}' | awk '{print $1}'", bridge);

	FILE *fp = popen(cmd, "r");
	if (fp == NULL) {
		error("can't check bridge\n");
		err_exit();
	}

	char buf[BUFFERSIZE];
	while (fgets(buf, BUFFERSIZE, fp)) {
		buf[strlen(buf)-1] = '\0';
		ltrim(buf);

		if (strcmp(buf, nic) == 0) 
			return VNET_TRUE;
	}

	return VNET_FALSE;
}

// 销毁所有bridge
void destroy_all_bridge()
{
	get_vnet_list(BRIDGE);

	int n = 0;
	char **p = bridge_list;
	while (*(p+n)) {
		strcpy(bridge, *(p+n));
		run_bridge_command(DESTROY_BRIDGE);
		++n;
	}

	free_vnet_list(BRIDGE);
}

// 销毁所有tap
void destroy_all_tap()
{
	get_vnet_list(TAP);

	int n = 0;
	char **p = tap_list;
	while (*(p+n)) {
		strcpy(tap, *(p+n));
		run_bridge_command(DESTROY_TAP);
		++n;
	}

	free_vnet_list(TAP);
}

// 获得一个新bridge
void get_new_bridge(char *bridge)
{
	get_new_vnet_name(BRIDGE, bridge);
}

// 获取一个新tap
void get_new_tap(char *tap)
{
	get_new_vnet_name(TAP, tap);
}

// 检测IP地址的有效性
// 返回：若成功则为1,不成功为0 
int check_ip(char *ip)
{
	if (ip == NULL) return 0;

	char str[BUFFERSIZE];
	strcpy(str, ip);
	
	//分割ip和掩码
	char *delims = "/";
	char *ipv4 = NULL, *mask = NULL;

	ipv4 = strtok(str, delims);
	mask = strtok(NULL, delims);

	//检测子网掩码
	if (mask == NULL) return 0;
	int n = 0;
	while (*mask) {
		if (*mask >= '0' && *mask <='9') {
			n = n * 10 + *mask - '0';
		}
		mask++;
	}
	int mask_ret = (n % 8 == 0) && (n <= 32);

	//检测ip
	struct in_addr addr; //IPv4地址结构体
	int ipv4_ret = inet_pton(AF_INET, ipv4, (void *)&addr);
	
	return ipv4_ret > 0 && mask_ret;

}

// 从文件中载入nat/switch列表
void load_ng_list(nat_stru **ng_list, char *file)
{
	char fn[CMD_MAX_LEN];
	sprintf(fn, "%s%s", osdir, file);

	init_config(fn);


	key_type *curr = list->head;
	
	int n = 0;
	while (curr != NULL && n < VNET_LISTSIZE) {
	
		nat_stru *p = (nat_stru*)malloc(sizeof(nat_stru));
		if (!p) {
			error("malloc error\n");
			err_exit();
		}	
		memset(p, 0, sizeof(nat_stru));
		strcpy(p->name, curr->name);
		strcpy(p->ip, curr->value);
		ng_list[n++] = p;

		curr = curr->next;
	}

	free_config();

}

// 将nat/switch列表保存到文件
void save_ng_list(nat_stru **ng_list, char *file)
{
	char fn[CMD_MAX_LEN];
	sprintf(fn, "%s%s", osdir, file);

	FILE *fp = fopen(fn, "w");
	if (fp == NULL) {
		error("can't write to %s\n", fn);
		err_exit();
	}

	int n = 0;
	while (ng_list[n] && n < VNET_LISTSIZE) {
		char str[BUFFERSIZE];
		sprintf(str, "%s=%s\n", ng_list[n]->name, ng_list[n]->ip);
		fputs(str, fp);
		++n;
	}

	fclose(fp);
}

// 删除nat/switch
void del_ng(char *ng_name, char *file)
{

	if (get_ng_info(ng_name, file) == NULL) {
		error("not found %s\n", ng_name);
		err_exit();
	}

	nat_stru **ng_list;
	if (strcmp(file, NAT_CONF_FN) == 0)
		ng_list = nat_list;
	if (strcmp(file, SWITCH_CONF_FN) == 0)
		ng_list = switch_list;

	load_ng_list(ng_list, file);

	int n = 0;
	while (ng_list[n]) {
		if (strcmp(ng_list[n]->name, ng_name) == 0) {
			while (ng_list[n+1]) {
				strcpy(ng_list[n]->ip, ng_list[n+1]->ip);
				++n;
			}
			ng_list[n] = NULL;
			break;
		}
		++n;
	}


	save_ng_list(ng_list, file);

	free_vnet_list(NAT);

}

// 修改nat/switch的ip
void set_ng(char *ng_name, char *ip, char *file)
{

	if (get_ng_info(ng_name, file) == NULL) {
		error("not found %s\n", ng_name);
		err_exit();
	}

	if (check_ip(ip) == 0) {
		error(" %s is a invalid IPv4 address\n", ip);
		err_exit();
	}

	nat_stru **ng_list;
	if (strcmp(file, NAT_CONF_FN) == 0)
		ng_list = nat_list;
	if (strcmp(file, SWITCH_CONF_FN) == 0)
		ng_list = switch_list;

	load_ng_list(ng_list, file);


	int n = 0;
	while (ng_list[n]) {
		if (strcmp(ng_list[n]->name, ng_name) == 0) {
			strcpy(ng_list[n]->ip, ip);
			break;
		}
		++n;
	}

	save_ng_list(ng_list, file);

	free_vnet_list(NAT);
}

// 清除nat/switch的IP地址
void unset_ng(char *ng_name, char *file)
{

	if (get_ng_info(ng_name, file) == NULL) {
		error("not found %s\n", ng_name);
		err_exit();
	}

	nat_stru **ng_list;
	if (strcmp(file, NAT_CONF_FN) == 0)
		ng_list = nat_list;
	if (strcmp(file, SWITCH_CONF_FN) == 0)
		ng_list = switch_list;

	load_ng_list(ng_list, file);

	int n = 0;
	while (ng_list[n]) {
		if (strcmp(ng_list[n]->name, ng_name) == 0) {
			strcpy(ng_list[n]->ip, "");
		}
		++n;
	}


	save_ng_list(ng_list, file);

	free_vnet_list(NAT);

}


// 新增NAT/switch
void add_ng(char *ip, char *file)
{
	if (check_ip(ip) == 0) {
		error("%s is invalid IPv4 address\n", ip);
		return;
	}

	char fn[FN_MAX_LEN];
	sprintf(fn, "%s%s", osdir, file);

	FILE *fp = fopen(fn, "a+");
	if (fp == NULL) {
		error("can't open %s\n", file);
		err_exit();
	}

	char str[BUFFERSIZE];
	if (strcmp(file, NAT_CONF_FN) == 0)
		sprintf(str, "nat%d=%s\n", get_new_ng(file), ip);
	if (strcmp(file, SWITCH_CONF_FN) == 0)
		sprintf(str, "switch%d=%s\n", get_new_ng(file), ip);
	fputs(str, fp);
	fclose(fp);
}

// 获取一个新的NAT/switch序号
int  get_new_ng(char *file)
{
	char nn[BUFFERSIZE];
	int i;
	for (i = 0; ;i++) {
		if (strcmp(file, NAT_CONF_FN) == 0)
			sprintf(nn, "nat%d", i);
		if (strcmp(file, SWITCH_CONF_FN) == 0)
			sprintf(nn, "switch%d", i);
		if (get_ng_info(nn, file) == NULL) break;
	}

	return i;	

}


// 输出所有nat/switch信息
void ng_info(char *file)
{
	char fn[CMD_MAX_LEN];
	sprintf(fn, "%s%s", osdir, file);

	init_config(fn);

	key_type *curr = list->head;

	while (curr != NULL) {
		printf("%s = %s\n", curr->name, curr->value);
		curr = curr->next;
	}

	free_config();
}

// 获取nat/switch信息
// 函数依赖参数nat的name字段
char *get_ng_info(char *ng_name, char *file)
{
	char fn[CMD_MAX_LEN];
	sprintf(fn, "%s%s", osdir, file);

	init_config(fn);

	nat_stru *p;
	if (strcmp(file, NAT_CONF_FN) == 0)
		p = &nat;
	if (strcmp(file, SWITCH_CONF_FN) == 0)
		p = &Switch;

	char *value;
	if ((value = get_value_by_name(ng_name)) != NULL) {
		strcpy(p->ip, value);
		strcpy(p->name, ng_name);
		sprintf(p->desc, "bvm-%s", p->name);
	}

	free_config();
	return value;
}

// 从文件载入nat_list
void load_nat_list()
{
	load_ng_list(nat_list, NAT_CONF_FN);
}

// 从文件载入switch_list
void load_switch_list()
{
	load_ng_list(switch_list, SWITCH_CONF_FN);
}


// 保存nat_list到文件
void save_nat_list()
{
	save_ng_list(nat_list, NAT_CONF_FN);
}

// 保存switch_list到文件
void save_switch_list()
{
	save_ng_list(switch_list, SWITCH_CONF_FN);
}


// 删除nat
void del_nat(char *nat_name)
{
	del_ng(nat_name, NAT_CONF_FN);
}

// 删除switch
void del_switch(char *switch_name)
{
	del_ng(switch_name, SWITCH_CONF_FN);
}


// 修改nat的ip
void set_nat(char *nat_name, char *ip)
{
	set_ng(nat_name, ip, NAT_CONF_FN);
}

// 修改switch的ip
void set_switch(char *switch_name, char *ip)
{
	set_ng(switch_name, ip, SWITCH_CONF_FN);
}

// 清除设备ip
void unset_device(char *device)
{
	if (device == NULL) {
		error("device can't be empty\n");
		return;
	}

	if (strstr(device, "nat")) 
		unset_nat(device);
	else if (strstr(device, "switch")) 
		unset_switch(device);
	else
		error("device \"%s\" is invalid\n", device);
}

// 清除nat的ip
void unset_nat(char *nat_name)
{
	unset_ng(nat_name, NAT_CONF_FN);
}

// 清除switch的ip
void unset_switch(char *switch_name)
{
	unset_ng(switch_name, SWITCH_CONF_FN);
}

// 新增NAT
void add_nat(char *ip)
{
	add_ng(ip, NAT_CONF_FN);
}

// 新增SWITCH
void add_switch(char *ip)
{
	add_ng(ip, SWITCH_CONF_FN);
}


// 获取一个新的NAT序号
int  get_new_nat()
{
	get_new_ng(NAT_CONF_FN);
	return 0;
}

// 获取一个新的SWITCH序号
int  get_new_switch()
{
	get_new_ng(SWITCH_CONF_FN);
	return 0;
}


// 输出所有nat信息
void nat_info()
{
	ng_info(NAT_CONF_FN);
}

// 输出所有switch信息
void switch_info()
{
	ng_info(SWITCH_CONF_FN);
}

	
// 输出nat列表
void print_nat_list()
{
	//if (nat_list == NULL) return;
	if (*nat_list == NULL) return;

	int n = 0;
	while (nat_list[n]) {
		printf("%s = %s\n", nat_list[n]->name, nat_list[n]->ip);
		++n;
	}
}

// 获取nat信息
// 函数依赖参数nat的name字段
char *get_nat_info(char *nat_name)
{
	return get_ng_info(nat_name, NAT_CONF_FN);
}

// 获取switch信息
// 函数依赖参数switch的name字段
char *get_switch_info(char *switch_name)
{
	return get_ng_info(switch_name, SWITCH_CONF_FN);
}

// 获得tap_list中的tap数量
// flag_nic 为是否将nic物理网卡计算在内的标志
// TL_NIC,1：包含物理网卡
// TL_NO_NIC,0：不包含物理网卡
int tap_list_count(int flag_nic)
{
	int count = 0;
	int n = 0;
	while (tap_list[n]) {
		if (strstr(tap_list[n], "tap")) ++count;
		else if (flag_nic) ++count;
		++n;
	}

	return count;
}

// 获取网桥下的members成员tap
void get_members_in_bridge(char *bridge_name)
{
	free_vnet_list(TAP);

	char cmd[BUFFERSIZE];
	sprintf(cmd, "ifconfig %s | grep member | awk '{print $2}'", bridge_name);

	FILE *fp;
	if ((fp=popen(cmd, "r")) == NULL) {
		error("can't get members\n");
		err_exit();
	}

	get_buffer(fp, TAP);
	pclose(fp);
}

// 获得bridge/tap分组列表
void get_vnet_list(int type)
{
	char cmd[32];
	if (type == BRIDGE)
		strcpy(cmd, "ifconfig -g bridge");
	if (type == TAP)
		strcpy(cmd, "ifconfig -g tap");

	FILE *fp;
	if ((fp=popen(cmd, "r")) == NULL) {
		error("can't get network info\n");
		err_exit();
	}

	get_buffer(fp, type);

	pclose(fp);

	return ;
}

void get_buffer(FILE *fp, int type)
{
	char buf[VNET_BUFFERSIZE];
 	char *p;	

	int n = 0;
	while (fgets(buf, VNET_BUFFERSIZE, fp)) {
		buf[strlen(buf)-1] = '\0';

		p = (char*)malloc(VNET_BUFFERSIZE*sizeof(char));
		if (!p) {
			error("malloc error\n");
			err_exit();
		}	
		memset(p, 0, VNET_BUFFERSIZE);
		strcpy(p, buf);

		if (type == BRIDGE)
			bridge_list[n++] = p;
        	if (type == TAP)
			tap_list[n++] = p;
	}

	return;
}

// 对bridge/tap名称进行排序
void sort_vnet_list(int type)
{
	char **p;
	if (type == BRIDGE)
		p = bridge_list;
	if (type == TAP)
		p = tap_list;

	int len = 0;
	while(*(p+len)) ++len;

	for (int i=0;i<len-1;i++)
		for (int j=i+1;j<len;j++)
			if (get_vnet_name_ord(*(p+i)) > get_vnet_name_ord(*(p+j))) {
				char *tmp;
				tmp = *(p+i);
				*(p+i) = *(p+j);
				*(p+j) = tmp;
			}
}

// 获取bridge/tap的序号
int get_vnet_name_ord(char *name)
{
	if (strstr(name, "bridge"))
		return atoi(name+strlen("bridge"));

	else if (strstr(name, "tap"))
		return atoi(name+strlen("tap"));

	else
		return -1;
}

// 获得可用bridge/tap名称
void get_new_vnet_name(int type, char *name)
{
	get_vnet_list(type);
	sort_vnet_list(type);

	char **p;
	if (type == BRIDGE) {
		p = bridge_list;
		strcpy(name, "bridge");
	}
	if (type == TAP) {
		p = tap_list;
		strcpy(name ,"tap");
	}

	int index = 0;
	int n = 0;
	while (*(p+n)) {
		if (get_vnet_name_ord(*(p+n)) == index) {
			index++;
			n++;
		}
		else
			break;
	}

	char tmp[VNET_BUFFERSIZE];
	sprintf(tmp, "%s%d", name, index);
	strcpy(name, tmp);

}

/*
// 获得物理网卡名称
void get_nic_name(char *nic)
{
	FILE *fp;
	fp = popen("ifconfig -l | awk '{print $1}'", "r");
	if (fp == NULL) {
		error("can't get nic name\n");
		err_exit();
	}

	char buf[VNET_BUFFERSIZE];
	while (fgets(buf, VNET_BUFFERSIZE, fp)) {
		buf[strlen(buf)-1] = '\0';
		strcpy(nic, buf);
	}

	pclose(fp);
}*/

// 获得物理网卡名称
void get_nic_name(int index, char *nic)
{
	if (strlen(nic_list[0]) == 0)
		get_nic_list();

	strcpy(nic, nic_list[index]);
}

// 获取wlan名称
void get_wlan_name(char *name)
{
	FILE *fp;
	fp = popen("ifconfig -g wlan | awk '{print $1}'", "r");
	if (fp == NULL) {
		error("can't get wlan name\n");
		err_exit();
	}
	
	char buf[VNET_BUFFERSIZE];
	while (fgets(buf, VNET_BUFFERSIZE, fp)) {
		buf[strlen(buf)-1] = '\0';
		strcpy(name, buf);
		break;
	}

	pclose(fp);
}


// 获取lo名称
void get_lo_name(char *name)
{
	FILE *fp;
	fp = popen("ifconfig -g lo | awk '{print $1}'", "r");
	if (fp == NULL) {
		error("can't get nic name\n");
		err_exit();
	}
	
	char buf[VNET_BUFFERSIZE];
	while (fgets(buf, VNET_BUFFERSIZE, fp)) {
		buf[strlen(buf)-1] = '\0';
		strcpy(name, buf);
		break;
	}

	pclose(fp);
}

// 获取所有物理网卡列表
int get_nic_list()
{
	FILE *fp;
	fp = popen("ifconfig -l | awk '{for(i=1;i<NF;i++) print $i}'", "r");
	if (fp == NULL) {
		error("can't get nic name\n");
		err_exit();
	}

	char loname[VNET_BUFFERSIZE];
	get_lo_name(loname);

	char wlan[VNET_BUFFERSIZE] = {0};
	get_wlan_name(wlan);

	int n = 0;
	char buf[VNET_BUFFERSIZE];
	while (fgets(buf, VNET_BUFFERSIZE, fp)) {
		buf[strlen(buf)-1] = '\0';
		if (strcmp(buf, loname) != 0) {
			strcpy(nic_list[n++], buf);
		}
		else
			break;
	}
	
	if (strlen(wlan) > 0) strcpy(nic_list[n], wlan);

	pclose(fp);

	return n;
}

// 打印birdge/tap列表
void print_vnet_list(int type)
{
	char **p;

	if (type == BRIDGE)
		p = bridge_list;

	if (type == TAP)
		p = tap_list;

	int n = 0;
	while (*(p+n) != '\0') {
		printf("%s\t", *(p+n));
		++n;
	}

	printf("\n");
	return;
}

// 释放列表占用的内存
void free_vnet_list(int type)
{
	switch (type) {
	case BRIDGE:
		free_vnet_list_proc(bridge_list);
		break;
	case TAP:
		free_vnet_list_proc(tap_list);
		break;
	case NAT:
		free_nat_list_proc(nat_list);
		free_nat_list_proc(switch_list);
		break;
	case ALL:
		free_vnet_list_proc(bridge_list);
		free_vnet_list_proc(tap_list);
		free_nat_list_proc(nat_list);
		free_nat_list_proc(switch_list);
		break;
	default:
		break;
	}
}

void free_vnet_list_proc(char **p)
{
	if (p) {
		for (int i=0; i<VNET_LISTSIZE; i++)
			if (p[i]) {
				free(p[i]);
				p[i] = NULL;
			}
	}
}

void free_nat_list_proc(nat_stru **p)
{
	if (p) {
		for (int i=0; i<VNET_LISTSIZE; i++)
			if (p[i]) {
				free(p[i]);
				p[i] = NULL;
			}
	
	}
}

