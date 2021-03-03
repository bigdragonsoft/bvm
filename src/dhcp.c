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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/errno.h>
#include <time.h>
#include <ctype.h>
#include <regex.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>  
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pcap.h>  

#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <net/if_dl.h>

#include "dhcp.h"
#include "config.h"


pthread_mutex_t mux = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mux_callback = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

dhcp_server_stru dhcp_pool[VNET_LISTSIZE] = {0};
host_mac_list *client_list = NULL;

const uint8_t option_magic[4] = { 0x63, 0x82, 0x53, 0x63 };

// DHCP选项和解析函数之间的映射表
static struct {

    char *name;
    int (*f) (char *, void **);

} dhcp_option_info [256] = {

	[PAD] = { "PAD", NULL },
	[END] = { "END", NULL },
	[SUBNET_MASK] = { "SUBNET_MASK", parse_ip },
	[ROUTER] = { "ROUTER", parse_ip_list },
	[DOMAIN_NAME_SERVER] = { "DOMAIN_NAME_SERVER", parse_ip_list },
	[HOST_NAME] = { "HOST_NAME", parse_string },
	[REQUESTED_IP_ADDRESS] = { "REQUESTED_IP_ADDRESS", NULL },
	[IP_ADDRESS_LEASE_TIME] = { "IP_ADDRESS_LEASE_TIME", parse_long },
	[DHCP_MESSAGE_TYPE] = { "DHCP_MESSAGE_TYPE", parse_byte },
	[SERVER_IDENTIFIER] = { "SERVER_IDENTIFIER", parse_ip },
	[PARAMETER_REQUEST_LIST] = { "PARAMETER_REQUEST_LIST", NULL },
	[MESSAGE] = { "MESSAGE", NULL },
	[RENEWAL_T1_TIME_VALUE] = { "RENEWAL_T1_TIME_VALUE", parse_long },
	[REBINDING_T2_TIME_VALUE] = { "REBINDING_T2_TIME_VALUE", parse_long },
	[VENDOR_CLASS_IDENTIFIER] = { "VENDOR_CLASS_IDENTIFIER", NULL },
	[CLIENT_IDENTIFIER] = { "CLIENT_IDENTIFIER", NULL },
};

// 将 ip 地址转换成字符串
char *ip_to_str(uint32_t ip)
{
	struct in_addr addr;
	memcpy(&addr, &ip, sizeof(ip));
	return inet_ntoa(addr);
}

// 将 mac 地址转换成字符串
char *mac_to_str(uint8_t *mac)
{
	static char str[128];
	sprintf(str, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return str;
}

// 将状态转换成字符串
char *status_to_str(int status)
{
	switch(status)
	{
		case ERROR_STATUS:
			return "ERROR_STATUS";
		case EMPTY:
			return "EMPTY";
		case ASSOCIATED:
			return "ASSOCIATED";
		case PENDING:
			return "PENDING";
		case EXPIRED:
			return "EXPIRED";
		case RELEASED:
			return "RELEASED";
		case DISABLE:
			return "DISABLE";
		case STATIC:
			return "STATIC";
		default:
			return NULL;
	}
}

int parse_byte(char *s, void **p)
{
	*p = malloc(sizeof(uint8_t));
	uint8_t n = ((uint8_t)strtol(s, NULL, 0));
	memcpy(*p, &n, sizeof(n));
    
	return sizeof(uint8_t);
}

int parse_byte_list(char *s, void **p)
{
	*p = malloc(strlen(s) * sizeof(uint8_t));

	int count = 0;

	char *s2 = strdup(s);
	char *s3 = strtok(s2, ", ");

	while(s3 != NULL) {

		uint8_t n = ((uint8_t) strtol(s3, NULL, 0));

		memcpy(((uint8_t *) *p) + count, &n, sizeof(uint8_t));

		count += sizeof(uint8_t);
		s3 = strtok(NULL, " ");
	}

	free(s2);

	return count;
}

int parse_short(char *s, void **p)
{
	*p = malloc(sizeof(uint16_t));
	uint16_t n = ((uint16_t) strtol(s, NULL, 0));
	memcpy(*p, &n, sizeof(n));
    
	return sizeof(uint16_t);
}

int parse_short_list(char *s, void **p)
{
	*p = malloc(strlen(s) * sizeof(uint16_t));

	int count = 0;

	char *s2 = strdup(s);
	char *s3 = strtok(s2, ", ");

	while(s3 != NULL) {

		uint16_t n = ((uint16_t) strtol(s3, NULL, 0));

		memcpy(((uint8_t *) *p) + count, &n, sizeof(uint16_t));

		count += sizeof(uint16_t);
		s3 = strtok(NULL, " ");
	}

	free(s2);

	return count;
}

int parse_long(char *s, void **p)
{
	*p = malloc(sizeof(uint32_t));
	uint32_t n = strtol(s, NULL, 0);
	n = ntohl(n);
	memcpy(*p, &n, sizeof(n));

	return sizeof(uint32_t);
}

int parse_string(char *s, void **p)
{
	*p = strdup(s);

	return strlen(s);
}

int parse_ip(char *s, void **p)
{
	struct sockaddr_in ip;
    
	*p = malloc(sizeof(uint32_t));

	if (inet_aton(s, &ip.sin_addr) == 0) {
		free(*p);
		return 0;
	}

	memcpy(*p, &ip.sin_addr, sizeof(uint32_t));

	return sizeof(uint32_t);
}

int parse_ip_list(char *s, void **p)
{
	*p = malloc(strlen(s) * sizeof(uint32_t) / 4);

	int count = 0;

	char *s2 = strdup(s);
	char *s3 = strtok(s2, ", ");

	while(s3 != NULL) {
		struct sockaddr_in ip;

		if (inet_aton(s3, &ip.sin_addr) == 0) { // error: 无效的 IP 地址
			free(*p);
			return 0;
		}

	memcpy(((uint8_t *) *p) + count, &ip.sin_addr, sizeof(uint32_t));

	count += sizeof(uint32_t);
	s3 = strtok(NULL, " ");
	}

	free(s2);

	return count;
}

int parse_mac(char *s, void **p)
{
	*p = malloc(6);
	int i;

	if (strlen(s) != 17 ||
		s[2] != ':' || s[5] != ':' || s[8] != ':' || s[11] != ':' || s[14] != ':') {
		free(*p);
		return 0; // error: 无效的 MAC 地址
	}

	if (!isxdigit(s[0]) || !isxdigit(s[1]) || !isxdigit(s[3]) || !isxdigit(s[4]) || 
		!isxdigit(s[6]) || !isxdigit(s[7]) || !isxdigit(s[9]) || !isxdigit(s[10]) ||
		!isxdigit(s[12]) || !isxdigit(s[13]) || !isxdigit(s[15]) || !isxdigit(s[16])) {
		free(*p);
		return 0; // error: 无效的 MAC 地址
	}

	for (i = 0; i < 6; i++) {
		long b = strtol(s+(3*i), NULL, 16);
		((uint8_t *) *p)[i] = (uint8_t) b;
	}

	return 6;
}

uint8_t parse_option (dhcp_option *opt, char *name, char *value)
{
	int (*f) (char *, void **);
	int id;

	uint8_t len;
	uint8_t *p;

	for (id = 0; id < 256; id++) {	//按名称查询
		if (dhcp_option_info[id].name &&
			strcmp(dhcp_option_info[id].name, name) == 0) break;
	}

	if (id == 256) { 
		printf("Unsupported DHCP option '%s'", name);
		return 0;
	}

	f = dhcp_option_info[id].f;

	if (f == NULL) {
		printf("Unsupported DHCP option '%s'", name);
		return 0;
	}

	len = f(value, (void **)&p);

	if(len == 0) return 0;

	// 填写结构
	opt->id = id;
	opt->len = len;
	memcpy(opt->data, p, len);

	free(p);

	return opt->id;
}

// 设置一组option
int set_option(dhcp_option *opt, uint8_t id, char *data)
{    
	if (id == END) {
		opt->id = id;
		opt->len = 0;
		memcpy(opt->data, NULL, 0);	
		return id;
	}

	int (*f) (char *, void **);

	uint8_t len;
	uint8_t *p;

	if (dhcp_option_info[id].name == NULL) return -1;

	f = dhcp_option_info[id].f;

	if (f == NULL) {
        	printf("Unsupported DHCP option '%s'", dhcp_option_info[id].name);
		return -1;
	}

	len = f(data, (void **)&p);

	if(len == 0) return -1;

	opt->id = id;
	opt->len = len;
	memcpy(opt->data, p, len);

	free(p);

	return opt->id;
}

// 从报文的options（非列表）中载入一组数据
int load_options(dhcp_option *opt, uint8_t id, dhcp_msg *msg)
{
	int i = 0;
	int _id;
	while ((_id = msg->hdr.options[i]) != END) {

		int len = msg->hdr.options[i + 1];

		if (id == _id) {
			opt->id = id;
			opt->len = len;
			memcpy(opt->data, &msg->hdr.options[i + 2], len);
			return id;
		}
		i = i + len + 2;
	}
	return -1;

}

// 在列表中添加一组options
int add_option_list(dhcp_option *opt, dhcp_option_list **list)
{
	dhcp_option_list *new;
	new = (dhcp_option_list*)malloc(sizeof(dhcp_option_list));

	if (new == NULL) {
		printf("malloc error\n");
		return -1;
	}
	
	memset(new, 0, sizeof(dhcp_option_list));

	new->opts.id = opt->id;
	new->opts.len = opt->len;
	memcpy(new->opts.data, opt->data, opt->len);
	

	if (*list == NULL) {
		*list = new;
	}
	else {

		dhcp_option_list *p = *list;
		while (p->next)
			p = p->next;

		p->next = new;
	}

	new->next = NULL;
	return 0;

}

// 打印输出option列表
void print_option_list(dhcp_option_list *list)
{
	if (list == NULL) return;

	warn("option list:\n");
	warn("ID\tLEN\tVALUE\n");
	warn("--\t---\t-----\n");
	dhcp_option_list *p = list;
	while (p) {
		printf("%d\t%d\t", p->opts.id, p->opts.len);
		for (int i=0; i<p->opts.len; i++)
			printf("%02x ", p->opts.data[i]);
		printf("\n");
		p = p->next;
	}
}

// 打印输出dhcp报文的options
void print_options(dhcp_msg *msg)
{
	if (msg == NULL) return;

	warn("options:\n");
	warn("ID\tLEN\tVALUE\n");
	warn("--\t---\t-----\n");

	int i = 0;
	int id;
	while ((id = msg->hdr.options[i]) != END) {
		int len = msg->hdr.options[i+1];
		printf("%d\t%d\t", id, len);
		for (int j=0; j<len; j++)
			printf("%02x ", msg->hdr.options[i+j+2]);
		printf("\n");

		i = i + len + 2;
	}
	printf("%d\n", END);

}

// 打印输出dhcp报文
void print_dhcp_msg(dhcp_msg *msg)
{
	if (msg == NULL) return;

	warn("dhcp mssage:\n");
	warn("FILED\tVALUE\n");
	warn("-----\t-----\n");
        printf("op\t%02x\n", 		msg->hdr.op);		// 报文类型 1=请求，2=应答
        printf("htype\t%02x\n", 	msg->hdr.htype);	// 客户端 MAC 地址类型 1=以太网
        printf("hlen\t%02x\n", 		msg->hdr.hlen);		// 客户端 MAC 地址长度 6=以太网长度
        printf("hops\t%02x\n",		msg->hdr.hops);		// 经过中继服务器的个数
        printf("xid\t%08x\n",		msg->hdr.xid);		// 客户端的随机校验码
        printf("secs\t%04x\n",		msg->hdr.secs);		// 从获取到 IP 地址或者续约开始到现在的消耗时间
        printf("flags\t%04x\n",		msg->hdr.flags);	// 广播应答标志位 0x8000=广播 0x0000=单播
        printf("ciaddr\t%08x\n",	msg->hdr.ciaddr);	// 客户端 IP 地址，仅在服务器发送的 ACK 报文中显示
        printf("yiaddr\t%08x\n",	msg->hdr.yiaddr);	// 服务器分配给客户端的 IP 地址，仅在服务器发送 OFFER 和 ACK 报文中显示
        printf("siaddr\t%08x\n",	msg->hdr.siaddr);	// 下一个为客户端分配 IP 地址的服务器 IP
        printf("giaddr\t%08x\n",	msg->hdr.giaddr);	// 客户端发出请求报文后经过的第一个中继服务器的 IP 地址
	printf("chaddr\t");					// 客户端 MAC 地址
	for (int i=0; i<msg->hdr.hlen; i++)
		printf("%02x ", 	msg->hdr.chaddr[i]);
	printf("\n");
        printf("sname\t%s\n",		msg->hdr.sname);	// DHCP 服务器名称，在 OFFER 和 ACK 报文中显示
        printf("file\t%s\n",		msg->hdr.file);		// 服务器为客户端指定的启动配置，仅在 OFFER 报文中显示
	printf("magic\t");					// magic cookie 0x63, 0x82, 0x53, 0x63
	for (int i=0; i<4; i++)
		printf("%02x ", 	msg->hdr.magic[i]);
	printf("\n");

	print_options(msg);
}

// 初始化option列表
void init_option_list(dhcp_option_list *list)
{
	destroy_option_list(list);
	list = NULL;
}

// 销毁option列表
void destroy_option_list(dhcp_option_list *list)
{
	if (list == NULL) return;

	dhcp_option_list *p = list;
	while (p) {
		p = list->next;
		free(list);
		list = p;
	}
}

// 将列表数据写入报文options中
int list_to_options(dhcp_msg *msg)
{
	dhcp_option_list *list = msg->opts_list;
	int cnt = 0;
	int i = 0;

	while (list) {
		msg->hdr.options[i++] = list->opts.id;	
		msg->hdr.options[i++] = list->opts.len;	
		for (int j=0; j<list->opts.len; j++)
			msg->hdr.options[i++] = list->opts.data[j];	
		++cnt;
		list = list->next;
	}

	return cnt;
}

// 发送应答报文
int send_dhcp_reply(int fd, struct sockaddr_in *client_sock, dhcp_msg *reply)
{
	int idx = get_server_index(reply->hdr.chaddr);
	if (idx < 0) return idx;

	size_t ret;
	size_t len = sizeof(reply->hdr);
    
	client_sock->sin_family = AF_INET;
	//client_sock->sin_addr.s_addr = inet_addr("172.16.1.255");
	client_sock->sin_addr.s_addr = dhcp_pool[idx].broadcast;
	
	//debug(YELLOW, "index=%d, broadcast=%s\n", idx, ip_to_str(client_sock->sin_addr.s_addr));

	client_sock->sin_port = htons(DHCP_CLIENT_PORT);
	if ((ret = sendto(fd, &reply->hdr, len, 0, (struct sockaddr *)client_sock, sizeof(*client_sock))) < 0) {
		printf("send dhcp reply failed\n");
		return -1;
	}

	return ret;
}

//获取网卡掩码
struct in_addr *get_interfaces_netmask(const char *ifname)
{
	struct in_addr *p;
	struct ifaddrs * ifaddrs_ptr;
	int status;

	status = getifaddrs (& ifaddrs_ptr);
	if (status == -1)
		return NULL;


	while (ifaddrs_ptr) {

		if (strncmp(ifaddrs_ptr->ifa_name, ifname, strlen(ifname))) {
			ifaddrs_ptr = ifaddrs_ptr->ifa_next;
			continue;
		}

		if(!ifaddrs_ptr->ifa_netmask){
			ifaddrs_ptr = ifaddrs_ptr->ifa_next;
			continue;
		}

		if (ifaddrs_ptr->ifa_addr->sa_family == AF_INET){
			p = calloc(1, sizeof(struct in_addr));
			if(!p)
				return NULL;

			memcpy(p, &((struct sockaddr_in *)ifaddrs_ptr->ifa_netmask)->sin_addr, sizeof(struct in_addr));
    			freeifaddrs (ifaddrs_ptr);
			return p;
		}

		ifaddrs_ptr = ifaddrs_ptr->ifa_next;
	}

    	freeifaddrs (ifaddrs_ptr);
	return NULL;
}


//获取网卡的IP地址
struct in_addr *get_interfaces_ip(const char *ifname)
{

	struct in_addr *p = NULL;
	struct ifaddrs * ifaddrs_ptr;
	int status;

	status = getifaddrs (& ifaddrs_ptr);
	if (status == -1) 
		return NULL;


	while (ifaddrs_ptr) {

		if (strncmp(ifaddrs_ptr->ifa_name, ifname, strlen(ifname))) {
			ifaddrs_ptr = ifaddrs_ptr->ifa_next;
			continue;
		}

		if(!ifaddrs_ptr->ifa_addr){
			ifaddrs_ptr = ifaddrs_ptr->ifa_next;
			continue;
		}

		if (ifaddrs_ptr->ifa_addr->sa_family == AF_INET){
			p = calloc(1, sizeof(struct in_addr));
			if(!p)
				return NULL;

			memcpy(p, &((struct sockaddr_in *)ifaddrs_ptr->ifa_addr)->sin_addr, sizeof(struct in_addr));
    			freeifaddrs (ifaddrs_ptr);
			return p;
		}

		ifaddrs_ptr = ifaddrs_ptr->ifa_next;
	}

    	freeifaddrs (ifaddrs_ptr);
	return NULL;
}

// 获取网卡的广播域
struct in_addr get_interfaces_broadcast(const char *ifname)
{
	struct in_addr *ip = NULL;
	ip = get_interfaces_ip(ifname);

	struct in_addr *netmask = NULL;
	netmask = get_interfaces_netmask(ifname);
	
	struct in_addr broadcast;
	broadcast.s_addr = ((ip->s_addr) & (netmask->s_addr)) | (~(netmask->s_addr));

	free(ip);
	free(netmask);

	return broadcast;
}

// 获取网卡的mac地址
int get_interfaces_mac(char *ifname, uint8_t *mac) 
{
	struct ifaddrs *ifap, *ifaptr;
	uint8_t *ptr;
	//unsigned char *ptr;

	if (getifaddrs(&ifap) == 0) {
		for(ifaptr = ifap; ifaptr != NULL; ifaptr = (ifaptr)->ifa_next) {
			#ifdef __linux__
			if (!strcmp((ifaptr)->ifa_name, ifname) && (((ifaptr)->ifa_addr)->sa_family == AF_PACKET)) {
				struct sockaddr_ll *s = (struct sockaddr_ll*)(ifaptr->ifa_addr);
				int i;
				int len = 0;
				for (i = 0; i < 6; i++) {
					len += sprintf(macaddrstr+len, "%02X%s", s->sll_addr[i], i < 5 ? ":":"");
				}
				break;
			}
			#else
			if (!strcmp((ifaptr)->ifa_name, ifname) && (((ifaptr)->ifa_addr)->sa_family == AF_LINK)) {
				ptr = (uint8_t *)LLADDR((struct sockaddr_dl *)(ifaptr)->ifa_addr);
				memcpy(mac, ptr, ETHER_ADDR_LEN);
				//sprintf(macaddrstr, "%02x:%02x:%02x:%02x:%02x:%02x", 
				//	*ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));
				break;
			}
			#endif
		}
        
		freeifaddrs(ifap);
		return ifaptr != NULL;
	} 
	else {
		return 0;
	}
}

// 获取可监测网桥名称
void get_bridge_name(listen_dev_stru *dev)
{
	get_vnet_list(BRIDGE);

	char **p = bridge_list;
	char desc[VNET_BUFFERSIZE] = {0};

	int n = 0;
	int m = 0;
	while (*(p+n)) {
		
		get_bridge_desc(*(p+n), desc);
	
		if (strstr(desc, "bvm-nat")) {
			strcpy(dev[m].name, *(p+n));
			++m;
		}
		++n;
	}
	dev[m].name[0] = '\0';

	//print_vnet_list(BRIDGE);
	free_vnet_list(BRIDGE);
}

// 获取可监测网桥数量
int get_bridge_num(listen_dev_stru *dev)
{
	int n = 0;
	while (strlen(dev[n].name) > 0) ++n;
	return n;
}

// 抓包回调函数
void get_packet(u_char *dev, const struct pcap_pkthdr *hdr, const u_char *packet)
{ 

	static int count = 0; 
	struct ether_header *eth_header; 
	u_char *ptr; 
     
	//printf("Packet length %d\n", hdr->len); 
 
	eth_header = (struct ether_header*)packet; 
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) { 
		debug(DEFAULT_COLOR, "not ethernet packet\n"); 
		return; 
	} 

	//上锁
	pthread_mutex_lock(&mux_callback);

	host_mac_stru host;
	strcpy(host.ifname, (char*)dev);

	ptr = eth_header->ether_shost;
	memcpy(host.mac, ptr, ETHER_ADDR_LEN);

	//添加到客户列表中
	uint8_t if_mac[16] = {0};
	get_interfaces_mac(host.ifname, if_mac);
	if (memcmp(if_mac, host.mac, ETHER_ADDR_LEN) != 0) {
		if (find_client(&host) == (host_mac_stru*)NULL) {
			add_client_list(&host);
			//print_client_list();
		}
	}


	//解锁
	pthread_mutex_unlock(&mux_callback);
 
} 

// 监听网桥
// net_dev：网桥名称
void *listen_bridge(void *net_dev)
{ 
	pcap_t *sniffer_des; 
	char errbuf[PCAP_ERRBUF_SIZE]; 
	bpf_u_int32 net, mask; 
	struct bpf_program fp; 
	const u_char *packet; 
	struct pcap_pkthdr hdr; 
     
	int ret; 
	static int ok = 0, fail = -1;
 
	//char filter[] = "port 68"; 
	char filter[] = "udp and port bootps"; 
 
	/*
	char *dev = pcap_lookupdev(errbuf); 
	if (dev == NULL) { 
		printf("get device error:%s\n", errbuf); 
		return &fail; 
	} 
	printf("pcap_lookupdev %s\n", dev);

	pcap_if_t *it;
	if (pcap_findalldevs(&it, errbuf) >= 0) {
		while (it) {
			printf(":%s\n", it->name);
			it = it->next;
		}
	}
	*/

	//获取网桥的ip地址和掩码
	while (1) {
		if (pcap_lookupnet((char*)net_dev, &net, &mask, errbuf) == -1) { 
			debug(RED, "get net error:%s\n", errbuf); 
			continue;
			//return &fail; 
		} 
		break;
	}
 	
	//输出IP地址和掩码
	struct in_addr addr;
	addr.s_addr = net;
	//debug(0, "ip: %s\n", inet_ntoa(addr));
	addr.s_addr = mask;
	//debug(0, "mask: %s\n", inet_ntoa(addr));
	//debug(0, "dev: %s\n", net_dev);

	sniffer_des = pcap_open_live((char*)net_dev, 65535, 1, 50, errbuf); 
	if (sniffer_des == NULL) { 
		printf("pcap_open_live%s\n", errbuf); 
		return &fail; 
	} 
 
	if (pcap_compile(sniffer_des, &fp, filter, 1, mask) == -1) {
		printf("pcap_compile error\n"); 
		return &fail; 
	} 
 
	if (pcap_setfilter(sniffer_des, &fp) == -1) {
		printf("pcap_setfilter() error\n"); 
		return &fail; 
	} 
 

	//防止网桥传递错误
	char bridge[16] = {0};
	strcpy(bridge, net_dev);

	//开始抓包
	ret = pcap_loop(sniffer_des, -1, get_packet, (void*)bridge); 
	if (ret == -1 || ret == -2) { 
		debug(0, "cannot get the pcaket\n"); 
		return &fail; 
	} 

	//packet = pcap_next(sniffer_des, &hdr);
	
	//清理
	pcap_freecode(&fp);
	pcap_close(sniffer_des);

	return &ok; 
} 

// 将客户机MAC添加到client_list列表
int add_client_list(host_mac_stru *host)
{
	debug(RED, "add client list ==> %s %s\n", host->ifname, mac_to_str(host->mac));
	debug(DEFAULT_COLOR, "FOUND %s on %s\n", mac_to_str(host->mac), host->ifname);
	host_mac_list *new;
	new = (host_mac_list*)malloc(sizeof(host_mac_list));

	if (new == NULL) {
		printf("malloc error\n");
		return -1;
	}
	
	memset(new, 0, sizeof(host_mac_list));

	strcpy(new->host.ifname, host->ifname);
	memcpy(&new->host.mac, &host->mac, ETHER_ADDR_LEN);
	

	if (client_list == NULL) {
		client_list = new;
	}
	else {

		host_mac_list *p = client_list;
		while (p->next)
			p = p->next;

		p->next = new;
	}

	new->next = NULL;
	return 0;

}

// 销毁client_list列表
void destroy_client_list()
{
	if (client_list == NULL) return;

	host_mac_list *p = client_list;
	while (p) {
		p = client_list->next;
		free(client_list);
		client_list = p;
	}
}

// 打印client_list
int print_client_list()
{
	int cnt = 0;
	if (client_list == NULL)
		return cnt;

	warn("idx\tifname\tMAC\n");
	warn("---\t------\t---\n");

	host_mac_list *p = client_list;
	while (p) {
		printf("%d\t%s\t%02x:%02x:%02x:%02x:%02x:%02x\n", 
				++cnt,
				p->host.ifname,
				p->host.mac[0], p->host.mac[1],
				p->host.mac[2], p->host.mac[3],
				p->host.mac[4], p->host.mac[5]);

		p = p->next;
	}

	return cnt;
}

// 在client_list中查找相匹配的主机记录
// 找到返回对应的指针
// 找不到返回NULL
host_mac_stru *find_client(host_mac_stru *host)
{
	if (client_list == NULL) 
		return (host_mac_stru*)NULL;

	host_mac_list *p = client_list;
	while (p) {
		if (memcmp(host->mac, p->host.mac, ETHER_ADDR_LEN) == 0) {
			return &(p->host);
		}
		p = p->next;
	}

	return (host_mac_stru*)NULL;
}

// 在client_list中删除指定的主机记录
// type = REMOVE_BRIDGE 是删除指定网桥的记录
// type = REMOVE_MAC 是删除指定mac地址的记录
// 返回删除记录的数量
int remove_client(int type, host_mac_stru *host)
{
	int cnt = 0;

	if (client_list == NULL) 
		return cnt;

	host_mac_list *p = client_list;
	host_mac_list *temp = client_list;
	while (p) {

		if (type == REMOVE_BRIDGE) {
			if (strcmp(host->ifname, p->host.ifname) == 0) {
				host_mac_list *del = p;
				if (p == client_list) {
					client_list = p->next;
				}

				++cnt;
				temp->next = del->next;
				p = p->next;
				
				free(del);
				continue;
			}
		}

		if (type == REMOVE_MAC) {
			if (memcmp(host->mac, p->host.mac, ETHER_ADDR_LEN) == 0) {
				host_mac_list *del = p;
				if (p == client_list) {
					client_list = p->next;
				}

				++cnt;
				temp->next = del->next;
				p = p->next;

				free(del);
				continue;
			}
		}

		temp = p;
		p = p->next;
	}

	return cnt;
}

// 打印地址池数据
// bind_idx=-1 打印全部ip
void print_dhcp_pool(int server_idx, int bind_idx)
{
	warn("server index : %d\n", server_idx);
	warn("id\tip\tmac\txid\tbind_time\tstatus\n");
	warn("--\t--\t---\t---\t---------\t------\n");
	
	int first = 0, last = 256;
	if (bind_idx != -1) {
		first = bind_idx;
		last = bind_idx + 1;
	}

	for (int i=first; i<last; i++)
	printf("%3d|%s|%s|%u|%ld|%s\n", 	bind_idx, 
						ip_to_str(dhcp_pool[server_idx].bind[i].ip), 
						mac_to_str(dhcp_pool[server_idx].bind[i].mac),
						dhcp_pool[server_idx].bind[i].xid,
						dhcp_pool[server_idx].bind[i].bind_time,
						status_to_str(dhcp_pool[server_idx].bind[i].status));
}

// 在地址池中寻找指定的网桥
// 返回网桥的索引值
int find_bridge_in_pool(char *dev)
{
	for (int i=0; i<VNET_LISTSIZE; i++) {
		if (strcmp(dhcp_pool[i].ifname, dev) == 0)
			return i;
	}

	return -1; 
}

// 在地址池中查找指定mac
// 返回mac所在数组的索引值
int find_mac_in_pool(int server_id, uint8_t *mac)
{
	int idx = server_id;

	for (int i=0; i<256; i++) {
		if (memcmp(dhcp_pool[idx].bind[i].mac, mac, ETHER_ADDR_LEN) == 0)
			return i;
	}

	return -1;
}

// 在地址池中查找一个可以使用的空ip
// 返回ip所在数组的索引值
int find_empty_ip_in_pool(int server_id)
{
	int idx = server_id;

	uint32_t first = ntohl(dhcp_pool[idx].first_ip);
	uint32_t last = ntohl(dhcp_pool[idx].last_ip);

	for (int i=0; i<256; i++) {
		uint32_t ip = ntohl(dhcp_pool[idx].bind[i].ip);
		int status = dhcp_pool[idx].bind[i].status;
		if (ip >= first && ip <= last && status == EMPTY)
			return i;
	}

	return -1;
}

// 获取地址池中指定ip地址的状态
// 参数bind_idx为查找到ip地址的索引号
int get_ip_status_in_pool(int server_id, uint32_t *ip, int *bind_idx)
{
	int idx = server_id;

	*bind_idx = ntohl(*ip) - ntohl(dhcp_pool[idx].bind[0].ip);

	if (*bind_idx > 0 && *bind_idx < 256)
		return dhcp_pool[idx].bind[*bind_idx].status;
	else
		return ERROR_STATUS;
}

// 在地址池中填写ip绑定信息
void fill_bind_in_pool(int server_idx, int bind_idx, int status, dhcp_msg *request)
{
	int idx = server_idx;
	int ip_idx = bind_idx;

	memcpy(dhcp_pool[idx].bind[ip_idx].mac, request->hdr.chaddr, ETHER_ADDR_LEN);
	dhcp_pool[idx].bind[ip_idx].xid = request->hdr.xid;
	dhcp_pool[idx].bind[ip_idx].status = status;

	#ifdef BVM_DEBUG
	//print_dhcp_pool(idx, bind_idx);
	#endif
}

// 设置reply报文的options
void set_reply_options(dhcp_msg *reply, int dhcp_type, int server_idx, int bind_idx)
{
	char str[BUFFERSIZE] = {0};
	int idx = server_idx;

	//设置yiaddr和sname
	//reply->hdr.yiaddr = inet_addr("172.16.1.2");
	if (bind_idx == -1)
		reply->hdr.yiaddr = 0;
	else
		reply->hdr.yiaddr = dhcp_pool[idx].bind[bind_idx].ip;

	//设置options
	//DHCP_MESSAGE_TYPE 报文类型
	dhcp_option t;
	sprintf(str, "%d", dhcp_type);
	set_option(&t, DHCP_MESSAGE_TYPE, str);
	add_option_list(&t, &reply->opts_list);

	//SERVER_IDENTIFIER 服务器ip
	strcpy(str, ip_to_str(dhcp_pool[idx].ip));
        set_option(&t, SERVER_IDENTIFIER, str);
        add_option_list(&t, &reply->opts_list);

	//IP_ADDRESS_LEASE_TIME 租赁时间
	sprintf(str, "%u", htonl(dhcp_pool[idx].lease_time));
	set_option(&t, IP_ADDRESS_LEASE_TIME, str);
        add_option_list(&t, &reply->opts_list);

	//RENEWAL_T1_TIME_VALUE T1时间为租赁时间的1/2
	sprintf(str, "%u", htonl(dhcp_pool[idx].lease_time)/2);
	set_option(&t, RENEWAL_T1_TIME_VALUE, str);
        add_option_list(&t, &reply->opts_list);

	//REBINDING_T2_TIME_VALUE T2时间为租赁时间的87.5%
	sprintf(str, "%u", (uint32_t)(htonl(dhcp_pool[idx].lease_time) * 0.875));
	set_option(&t, REBINDING_T2_TIME_VALUE, str);
	add_option_list(&t, &reply->opts_list);

	//SUBNET_MASK 掩码
	strcpy(str, ip_to_str(dhcp_pool[idx].netmask));
	set_option(&t, SUBNET_MASK, str);
	add_option_list(&t, &reply->opts_list);
	
	//END 结束标志
        set_option(&t, END, NULL);
        add_option_list(&t, &reply->opts_list);

	//将列表写入options
	list_to_options(reply);

}

// DHCP_DISCOVER 报文处理
int dhcp_discover_proc(dhcp_msg *request, dhcp_msg *reply)
{
	//通过请求报文中的mac来确定dhcp服务器索引
	int idx = get_server_index(request->hdr.chaddr);

	debug(DEFAULT_COLOR, "DHCPDISCOVER on %s from %s\n", idx<0?"unknow":dhcp_pool[idx].ifname, mac_to_str(request->hdr.chaddr));
	
	//对于没有得到索引值的无效报文不做处理
	if (idx < 0) return DHCP_INVALID;

	//查找一个可供分配的ip地址
	//首先看一下报文options中是否存在50代码REQUESTED_IP_ADDRESS
	//如果存在的话，就先看一下这个ip是否可用
	//若不可用则从地址池中选取
	//从地址池中选取的时候先扫描地址池中是否存在相同的客户端mac
	//若存在mac则不处理
	//若不存在mac则需要逐一扫描dhcp_pool中未使用过的ip地址
	//找到ip后，将报文中的客户端mac地址chaddr和校验码xid存入对应的dhcp_pool记录中
	//并且将状态status设置为PENDING状态，说明这是一个尚未完成分配的对话

	dhcp_option t;
	if (load_options(&t, REQUESTED_IP_ADDRESS, request) == REQUESTED_IP_ADDRESS) {
		
		int bind_idx;
		if (get_ip_status_in_pool(idx, (uint32_t*)&t.data, &bind_idx) == EMPTY) {
		
			fill_bind_in_pool(idx, bind_idx, PENDING, request);
			set_reply_options(reply, DHCP_OFFER, idx, bind_idx);
			
			return DHCP_OFFER;
		}
	}

	if (find_mac_in_pool(idx, request->hdr.chaddr) >= 0)
		return DHCP_INVALID;

	int ip_idx = find_empty_ip_in_pool(idx);
	if (ip_idx == -1) {

		set_reply_options(reply, DHCP_NAK, idx, -1);

		return DHCP_NAK;
	}
	else {

		fill_bind_in_pool(idx, ip_idx, PENDING, request);
		set_reply_options(reply, DHCP_OFFER, idx, ip_idx);
		
		return DHCP_OFFER;
	}
}

// DHCP_REQUEST 报文处理
int dhcp_request_proc(dhcp_msg *request, dhcp_msg *reply)
{

	//通过请求报文中的mac来确定dhcp服务器索引
	int idx = get_server_index(request->hdr.chaddr);

	debug(DEFAULT_COLOR, "DHCPREQUEST on %s from %s\n", idx<0?"unknow":dhcp_pool[idx].ifname, mac_to_str(request->hdr.chaddr));

	//对于没有得到索引值的无效报文不做处理
	if (idx < 0) return DHCP_INVALID;

	//首先根据请求报文request中的mac地址在地址池dhcp_pool中查找有没有相对应记录
	//如果找到还需要检测这个ip的状态是否为PENDING（首次申请）或ASSOCIATED（续租）
	//如果是PENDING则更新地址池中记录的状态ASSOCIATED
	//以及绑定时间bind_time，并且发送DHCP_ACK报文给客户端
	//如果是ASSOCIATED则处理方法同PENDING
	//如果状态不是PENDING/ASSOCIATED或者没能找到对应的mac则要发送DHCP_NAK报文给客户端

	int ip_idx = find_mac_in_pool(idx, request->hdr.chaddr);
	if (ip_idx >= 0) {

		int status = dhcp_pool[idx].bind[ip_idx].status;
		int xid = dhcp_pool[idx].bind[ip_idx].xid;
		
		if (status == PENDING || status == ASSOCIATED) {

			dhcp_pool[idx].bind[ip_idx].status = ASSOCIATED;
			dhcp_pool[idx].bind[ip_idx].bind_time = time(NULL);

			set_reply_options(reply, DHCP_ACK, idx, ip_idx);

			return DHCP_ACK;
		}
	}

	set_reply_options(reply, DHCP_NAK, idx, -1);
	return DHCP_NAK;

}

// DHCP_DECLINE 报文处理
int dhcp_decline_proc(dhcp_msg *request, dhcp_msg *reply)
{
	
	//通过请求报文中的mac来确定dhcp服务器索引
	int idx = get_server_index(request->hdr.chaddr);

	debug(DEFAULT_COLOR, "DHCPDECLINE on %s from %s\n", idx<0?"unknow":dhcp_pool[idx].ifname, mac_to_str(request->hdr.chaddr));

	//对于没有得到索引值的无效报文不做处理
	if (idx < 0) return DHCP_INVALID;

	//在地址池中找到对应的记录将状态恢复成EMPTY
	int ip_idx = find_mac_in_pool(idx, request->hdr.chaddr);
	if (ip_idx >= 0) {
		if (dhcp_pool[idx].bind[ip_idx].status == ASSOCIATED) {

			memset(dhcp_pool[idx].bind[ip_idx].mac, 0, 16);

			dhcp_pool[idx].bind[ip_idx].bind_time = 0;
			dhcp_pool[idx].bind[ip_idx].status = EMPTY;

			return DHCP_NONE;
		}
	}

	return DHCP_INVALID;
}

// DHCP_RELEASE 报文处理
int dhcp_release_proc(dhcp_msg *request, dhcp_msg *reply)
{

	//通过请求报文中的mac来确定dhcp服务器索引
	int idx = get_server_index(request->hdr.chaddr);

	debug(DEFAULT_COLOR, "DHCPRELEASE on %s from %s\n", idx<0?"unknow":dhcp_pool[idx].ifname, mac_to_str(request->hdr.chaddr));

	//对于没有得到索引值的无效报文不做处理
	if (idx < 0) return DHCP_INVALID;

	//在地址池中找到对应的记录将状态恢复成EMPTY
	int ip_idx = find_mac_in_pool(idx, request->hdr.chaddr);
	if (ip_idx >= 0) {
		if (dhcp_pool[idx].bind[ip_idx].status == ASSOCIATED) {

			memset(dhcp_pool[idx].bind[ip_idx].mac, 0, 16);

			dhcp_pool[idx].bind[ip_idx].bind_time = 0;
			dhcp_pool[idx].bind[ip_idx].status = EMPTY;

			return DHCP_NONE;
		}
	}

	return DHCP_INVALID;
}

// DHCP_INFORM 报文处理
int dhcp_inform_proc(dhcp_msg *request, dhcp_msg *reply)
{
	//通过请求报文中的mac来确定dhcp服务器索引
	int idx = get_server_index(request->hdr.chaddr);

	debug(DEFAULT_COLOR, "DHCPINFORM on %s from %s\n", idx<0?"unknow":dhcp_pool[idx].ifname, mac_to_str(request->hdr.chaddr));

	//对于没有得到索引值的无效报文不做处理
	if (idx < 0) return DHCP_INVALID;

	//直接发送一个DHCP_ACK作为回应
	return DHCP_ACK;
}



// 初始化应答报文
void init_reply(dhcp_msg *request, dhcp_msg *reply)
{
        memset(&reply->hdr, 0, sizeof(reply->hdr));
        reply->opts_list = NULL;
        init_option_list(reply->opts_list);

        reply->hdr.op = BOOTREPLY;

        reply->hdr.htype = request->hdr.htype;
        reply->hdr.hlen  = request->hdr.hlen;

        reply->hdr.xid   = request->hdr.xid;
        reply->hdr.flags = DHCP_BROADCAST_FLAG;

        reply->hdr.giaddr = request->hdr.giaddr;

        memcpy(reply->hdr.chaddr, request->hdr.chaddr, request->hdr.hlen);
	
	memcpy(reply->hdr.magic, option_magic, 4);
}

// 获取 dhcp 报文类型
int get_dhcp_message_type(dhcp_msg *msg)
{
	dhcp_option t;
	load_options(&t, DHCP_MESSAGE_TYPE, msg);
	return(t.data[0]);
}

// 报文控制器
void message_controller(int fd, struct sockaddr_in server_sock)
{
	while (1) {
		struct sockaddr_in client_sock;
		socklen_t slen = sizeof(client_sock);
		size_t len;

		dhcp_msg request;
		dhcp_msg reply;

		request.opts_list = NULL;
		reply.opts_list = NULL;

		len = recvfrom(fd, &request.hdr, sizeof(request.hdr), 0, (struct sockaddr *)&client_sock, &slen); 

		if(request.hdr.op != BOOTREQUEST) continue;

		#ifdef BVM_DEBUG
		//debug(YELLOW, "--- 接收到的报文 request ---\n\n");
		//print_dhcp_msg(&request);
		#endif

		//读取报文类型
		uint8_t type = get_dhcp_message_type(&request);

		int ret;

		//初始化应答报文
		init_reply(&request, &reply);
		
		//对不同的报文类型进行分支处理
		switch (type) {

		case DHCP_DISCOVER:
			ret = dhcp_discover_proc(&request, &reply);
			break;

		case DHCP_REQUEST:
			ret = dhcp_request_proc(&request, &reply);
			break;
	    
		case DHCP_DECLINE:
			ret = dhcp_decline_proc(&request, &reply);
			break;
	    
		case DHCP_RELEASE:
	    		ret = dhcp_release_proc(&request, &reply);
			break;
	    
		case DHCP_INFORM:
			ret = dhcp_inform_proc(&request, &reply);
			break;
	    
		default:
			debug(YELLOW, "%s.%u: request with invalid DHCP message type option\n", 
					inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
			break;
		}

		//发送应答报文
		if(ret >  0) {
			//debug(YELLOW, "--- 发送的报文 reply ---\n\n");
			//print_dhcp_msg(&reply);
			//debug(YELLOW, "A message of %d bytes has been sent\n", send_dhcp_reply(fd, &client_sock, &reply));

			send_dhcp_reply(fd, &client_sock, &reply);

			char str[16] = {0};
			if (ret == DHCP_OFFER)
				strcpy(str, "DHCPOFFER");
			if (ret == DHCP_ACK)
				strcpy(str, "DHCPACK");
			if (ret == DHCP_NAK)
				strcpy(str, "DHCPNAK");
			debug(DEFAULT_COLOR, "%s to %s (%s)\n", str, mac_to_str(reply.hdr.chaddr), ip_to_str(reply.hdr.yiaddr));

		}
		
		destroy_option_list(request.opts_list);
		destroy_option_list(reply.opts_list);
		
		sleep(1);
	}
}

// 主流程
// 查看进程号为pid的所有线程 top -p <pid> -H
int main(int argc, char **argv)
{
	#ifndef BVM_DEBUG
	if (argc < 2 || strcmp(argv[1], "9250b212ea95c6897aeef888c0b6611c18682957") != 0) {
		debug(RED, "cannot run this program\n");
		exit(1);
	}
	#endif

	init_dhcp_pool();

	int err;
	pthread_t tid_dhcp;
	pthread_t tid_scanif;
	
	pthread_mutex_init(&mux, NULL);
	pthread_mutex_init(&mux_callback, NULL);

	//创建扫描网桥线程
	err = pthread_create(&tid_scanif, NULL, scan_if, NULL);
	if (err) {
		printf("can't create pthread scan_bridge\n");
		exit(1);
	}

	//创建dhcp线程
	err = pthread_create(&tid_dhcp, NULL, dhcp_server, NULL);
	if (err) {
		printf("can't create pthread dhcp\n");
		exit(1);
	}
	pthread_join(tid_dhcp, NULL);

	pthread_mutex_destroy(&mux);
	pthread_mutex_destroy(&mux_callback);
	pthread_cond_destroy(&cond);

	return 0;
}

// 扫描网桥
void *scan_if()
{
	listen_dev_stru cur_dev[VNET_LISTSIZE] = {0};
	listen_dev_stru new_dev[VNET_LISTSIZE] = {0};
	
	memset(cur_dev, 0, sizeof(cur_dev));
	memset(new_dev, 0, sizeof(new_dev));

	//获取网桥放入cur_dev，并设置INIT初始状态
	get_bridge_name(cur_dev);
	for (int i=0; i<get_bridge_num(cur_dev); i++)
		cur_dev[i].status = BRIDGE_INIT;

	while(1) {
		//反复读取网桥放入new_dev
		get_bridge_name(new_dev);

		//检测new_dev中网桥数量
		if (get_bridge_num(new_dev) == 0) {
			debug(RED, "cannot scan bridge and exit\n");
			exit(1);
		}

		//对比网桥
		bridge_cmp(cur_dev, new_dev);

		//打印客户机列表
		//print_client_list();

	}
}

// 对比网桥的增减情况
void bridge_cmp(listen_dev_stru *cur_dev, listen_dev_stru *new_dev)
{
	int i, j;
	int err;

	//扫描需要删除的网桥
	for (i=0; i<get_bridge_num(cur_dev); i++) {
		int find = 0;
		for (j=0; j<get_bridge_num(new_dev); j++) {
			if (strcmp(cur_dev[i].name, new_dev[j].name) == 0) {
				find = 1;
				if (cur_dev[i].status == BRIDGE_INIT)
					new_dev[j].status = BRIDGE_NEW;
				else
					new_dev[j].status = BRIDGE_WORKING;
				break;
			}
		}
		if (!find) { //网桥无需监控，删除线程
			cur_dev[i].status = BRIDGE_REMOVE;
			pthread_cancel(cur_dev[i].tid);
			debug(YELLOW, "cancel pthread \n");

			//同时也需要删除与网桥相关的客户机列表
			host_mac_stru host;
			strcpy(host.ifname, cur_dev[i].name);
			debug(YELLOW, "remove %d clients from list\n", remove_client(REMOVE_BRIDGE, &host));
			//print_client_list();
		}
	}



	//扫描新添加的网桥
	for (i=0; i<get_bridge_num(new_dev); i++) {
		int find = 0;
		for (j=0; j<get_bridge_num(cur_dev); j++) {
			if (strcmp(new_dev[i].name, cur_dev[j].name) == 0) {
				find = 1;
				if (cur_dev[j].status == BRIDGE_INIT) {
					new_dev[i].status = BRIDGE_NEW;
					create_listen(&new_dev[i]);
				}
				else
					new_dev[i].status = BRIDGE_WORKING;
				break;
			}
		}
		if (!find) { //新增网桥，创建线程
			new_dev[i].status = BRIDGE_NEW;
			create_listen(&new_dev[i]);
			debug(YELLOW, "create pthread\n");
		}
	}
	
	for (i=0; i<get_bridge_num(new_dev); i++) {
		memcpy(&cur_dev[i], &new_dev[i], sizeof(new_dev[i]));
	}
	cur_dev[i].name[0] = '\0';
}

// 建立网桥监控线程
void create_listen(listen_dev_stru *dev)
{
	int err;
	static char arg[VNET_BUFFERSIZE] = {0};
	strcpy(arg, dev->name);
	
	//创建线控
	//debug(YELLOW, "listen %s ...\n", dev->name);
	err = pthread_create(&dev->tid, NULL, listen_bridge, (void*)arg);
	if (err) {
		printf("can't create pthread listen_bridge\n");
		exit(1);
	}
	
	sleep(1);
	//pthread_join(dev->tid, NULL);
}

// DHCP SERVER
void *dhcp_server()
{
	int fd;
	struct protoent *pp;
	struct servent *ss;
	struct sockaddr_in server_sock;


	// 初始化
	if ((ss = getservbyname("bootps", "udp")) == 0) {
		printf("server: getservbyname() error\n");
		exit(1);
	}

	if ((pp = getprotobyname("udp")) == 0) {
		printf("server: getprotobyname() error\n");
		exit(1);
	}

	if ((fd = socket(AF_INET, SOCK_DGRAM, pp->p_proto)) == -1) {
		printf("server: socket() error\n");
		exit(1);
	}

	server_sock.sin_family = AF_INET;
	server_sock.sin_addr.s_addr = htonl(INADDR_ANY);
	server_sock.sin_port = ss->s_port;

        int flag = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&flag , sizeof(int)) < 0) {
                printf("Error: Could not set reuse address option on DHCP socket!\n");
                exit(1);
        }

	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (const void *)&flag , sizeof(int)) < 0) {
                printf("Error: Could not set broadcast option on DHCP socket!\n");
                exit(1);
        }

	if (bind(fd, (struct sockaddr *) &server_sock, sizeof(server_sock)) == -1) {
		printf("server: bind()\n");
		close(fd);
		exit(1);
	}

	//debug(0, "dhcp server: listening on %d\n", ntohs(server_sock.sin_port));

	// 对接收到的报文进行处理
	message_controller(fd, server_sock);
	
	close(fd);
	return NULL;
}

// 初始化dhcp地址池
void init_dhcp_pool()
{
	load_nat_list();
        int n = 0;
        while (nat_list[n]) {
		//nat
		strcpy(dhcp_pool[n].nat, nat_list[n]->name);
		
		//ip
		char str[BUFFERSIZE];
	        strcpy(str, nat_list[n]->ip);

		char *ipv4 = strtok(str, "/");
		char *mask = strtok(NULL, "/");

		struct sockaddr_in p;
		p.sin_family = AF_INET;
		p.sin_addr.s_addr = inet_addr(ipv4);
		dhcp_pool[n].ip = p.sin_addr.s_addr;

		//netmask
		int m = atoi(mask);
		strcpy(str, "");
		for (int i=0; i<4; i++) {
			if (m > 0) {
				strcat(str, "255.");
				m -= 8;
			}
			else
				strcat(str, "0.");
		}
		str[strlen(str) - 1] = '\0';

		p.sin_addr.s_addr = inet_addr(str);
		dhcp_pool[n].netmask = p.sin_addr.s_addr;

		//broadcast
		p.sin_addr.s_addr = ((dhcp_pool[n].ip) & (dhcp_pool[n].netmask)) | (~(dhcp_pool[n].netmask));
		dhcp_pool[n].broadcast =  p.sin_addr.s_addr;

		//lease_time
		char fn[FN_MAX_LEN];
		sprintf(fn, "%s%s", osdir, "dhcp.conf");

		init_config(fn);
		
		char *value;
		if ((value = get_value_by_name("lease_time")) != NULL) {
			uint32_t *p;
			parse_long(value, (void **)&p);
			dhcp_pool[n].lease_time = *p;
			free(p);
		}
		
		sprintf(str, "%s_lease_time", dhcp_pool[n].nat);
		if ((value = get_value_by_name(str)) != NULL) {
			uint32_t *p;
			parse_long(value, (void **)&p);
			dhcp_pool[n].lease_time = *p;
			free(p);
		}

		//first_ip last_ip
		sprintf(str, "%s_dynamic_ip", dhcp_pool[n].nat);
		if ((value = get_value_by_name(str)) != NULL) {
			uint32_t *p;
			parse_ip_list(value, (void **)&p);
			dhcp_pool[n].first_ip = *p;
			dhcp_pool[n].current_ip = *p;
			dhcp_pool[n].last_ip = *(p + 1);
			free(p);
		}


		free_config();

		//bind_list
		//dhcp_pool[n].bind_list = NULL;
		
		//bind
		memset(dhcp_pool[n].bind, 0, sizeof(address_bind) * 256);

		for (int i=0; i<256; i++) {
			
			dhcp_pool[n].bind[i].ip = htonl(ntohl(dhcp_pool[n].ip & inet_addr("255.255.255.0")) + i);

			if (i == 0 || i == 255 || dhcp_pool[n].bind[i].ip == dhcp_pool[n].ip)
				dhcp_pool[n].bind[i].status = DISABLE;

		}

		++n;
	}
}

// 获得dhcp服务器的索引值
// 用来确定与之对应的地址池
int get_server_index(uint8_t *mac)
{
	//首先通过mac找到与之对应的网桥
	host_mac_stru host;
	memcpy(host.mac, mac, ETHER_ADDR_LEN);

	host_mac_stru *p = find_client(&host);
	if (p == NULL) {
		return -1;
	}

	//获得网桥的ip
	struct in_addr *ip = NULL;
	ip = get_interfaces_ip(p->ifname);

	uint32_t net_ip = ip->s_addr;
	
	free(ip);


	//通过ip地址确定dhcp服务器索引值
	int n = 0;
	while (strlen(dhcp_pool[n].nat) > 0) {
		if (dhcp_pool[n].ip == net_ip) {
			strcpy(dhcp_pool[n].ifname, p->ifname);
			return n;
		}
		++n;
	}

	//没有找到dhcp服务器索引值
	return -1;
}

void test()
{
	host_mac_stru c1;
       	strcpy(c1.ifname, "bridge0");
	c1.mac[0]=0; c1.mac[1]=1; c1.mac[2]=2; c1.mac[3]=3; c1.mac[4]=4; c1.mac[5]=5;
	add_client_list(&c1);
	
       	strcpy(c1.ifname, "bridge1");
	c1.mac[0]=10; c1.mac[1]=11; c1.mac[2]=12; c1.mac[3]=13; c1.mac[4]=14; c1.mac[5]=15;
	add_client_list(&c1);

       	strcpy(c1.ifname, "bridge0");
	c1.mac[0]=20; c1.mac[1]=21; c1.mac[2]=22; c1.mac[3]=23; c1.mac[4]=24; c1.mac[5]=25;
	add_client_list(&c1);

	print_client_list();

	strcpy(c1.ifname, "bridge0");
	c1.mac[0]=20; c1.mac[1]=21; c1.mac[2]=22; c1.mac[3]=23; c1.mac[4]=24; c1.mac[5]=25;
	remove_client(REMOVE_MAC, &c1);

	//strcpy(c1.ifname, "bridge1");
	//remove_client(REMOVE_BRIDGE, &c1);

	print_client_list();
	destroy_client_list();
	return;

	debug(YELLOW, "broadcast = %s\n", inet_ntoa(get_interfaces_broadcast("bridge0")));

	dhcp_msg msg;
	msg.opts_list = NULL;
	dhcp_option t;

	init_option_list(msg.opts_list);

	set_option(&t, ROUTER, "172.16.1.0 192.168.1.1");
	add_option_list(&t, &msg.opts_list);
	set_option(&t, SERVER_IDENTIFIER, "172.16.1.22");
	add_option_list(&t, &msg.opts_list);
	set_option(&t, HOST_NAME, "bigdragon");
	add_option_list(&t, &msg.opts_list);
	set_option(&t, END, NULL);
	add_option_list(&t, &msg.opts_list);

	print_option_list(msg.opts_list);
	
	list_to_options(&msg);
	print_options(&msg);


	destroy_option_list(msg.opts_list);
}
