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

#include "dhcp.h"
#include "vnet.h"



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

int parse_byte(char *s, void **p)
{
	*p = malloc(sizeof(uint8_t));
	uint8_t n = ((uint8_t)strtol(s, NULL, 0));
	memcpy(*p, &n, sizeof(n));
    
	return sizeof(uint8_t);
}

int parse_byte_list (char *s, void **p)
{
    *p = malloc(strlen(s) * sizeof(uint8_t)); // slightly over the strictly requested size

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

int
parse_short_list (char *s, void **p)
{
    *p = malloc(strlen(s) * sizeof(uint16_t)); // slightly over the strictly requested size

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

int
parse_ip_list (char *s, void **p)
{
    *p = malloc(strlen(s) * sizeof(uint32_t) / 4); // slightly over the strictly required size

    int count = 0;

    char *s2 = strdup(s);
    char *s3 = strtok(s2, ", ");

    while(s3 != NULL) {
	struct sockaddr_in ip;

	if (inet_aton(s3, &ip.sin_addr) == 0) { // error: invalid IP address
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

int
parse_mac (char *s, void **p)
{
    *p = malloc(6);
    int i;

    if (strlen(s) != 17 ||
       s[2] != ':' || s[5] != ':' || s[8] != ':' || s[11] != ':' || s[14] != ':') {
	free(*p);
	return 0; // error: invalid MAC address
    }

    if (!isxdigit(s[0]) || !isxdigit(s[1]) || !isxdigit(s[3]) || !isxdigit(s[4]) || 
	!isxdigit(s[6]) || !isxdigit(s[7]) || !isxdigit(s[9]) || !isxdigit(s[10]) ||
	!isxdigit(s[12]) || !isxdigit(s[13]) || !isxdigit(s[15]) || !isxdigit(s[16])) {
	free(*p);
	return 0; // error: invalid MAC address
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

    for (id = 0; id < 256; id++) { // search the option by name
        if (dhcp_option_info[id].name &&
                strcmp(dhcp_option_info[id].name, name) == 0) break;
    }

    if (id == 256) { // not found
        printf("Unsupported DHCP option '%s'", name);
        return 0;
    }

    f = dhcp_option_info[id].f;

    if (f == NULL) { // no parsing function available
        printf("Unsupported DHCP option '%s'", name);
        return 0;
    }

    len = f(value, (void **)&p); // parse the value

    if(len == 0) // error parsing the value
	return 0;

    // structure filling
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
		error("malloc error\n");
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

	warn("list:\n");
	warn("ID	LEN	VALUE\n");
	warn("--	---	-----\n");
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

	//for (int i = 0; i<256;) {
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
        printf("op\t%02x\n", 	msg->hdr.op);             // 报文类型 1=请求，2=应答
        printf("htype\t%02x\n", msg->hdr.htype);  	  // 客户端 MAC 地址类型 1=以太网
        printf("hlen\t%02x\n", 	msg->hdr.hlen);           // 客户端 MAC 地址长度 6=以太网长度
        printf("hops\t%02x\n",	msg->hdr.hops);           // 经过中继服务器的个数
        printf("xid\t%08x\n",	msg->hdr.xid);            // 客户端的随机校验码
        printf("secs\t%04x\n",	msg->hdr.secs);           // 从获取到 IP 地址或者续约开始到现在的消耗时间
        printf("flags\t%04x\n",	msg->hdr.flags);          // 广播应答标志位 0x8000=广播 0x0000=单播
        printf("ciaddr\t%08x\n",msg->hdr.ciaddr);         // 客户端 IP 地址，仅在服务器发送的 ACK 报文中显示
        printf("yiaddr\t%08x\n",msg->hdr.yiaddr);         // 服务器分配给客户端的 IP 地址，仅在服务器发送 OFFER 和 ACK 报文中显示
        printf("siaddr\t%08x\n",msg->hdr.siaddr);         // 下一个为客户端分配 IP 地址的服务器 IP
        printf("giaddr\t%08x\n",msg->hdr.giaddr);         // 客户端发出请求报文后经过的第一个中继服务器的 IP 地址
	printf("chaddr\t");				  // 客户端 MAC 地址
	for (int i=0; i<msg->hdr.hlen; i++)
		printf("%02x ", msg->hdr.chaddr[i]);
	printf("\n");
        printf("sname\t%s\n",	msg->hdr.sname); 	  // DHCP 服务器名称，在 OFFER 和 ACK 报文中显示
        printf("file\t%s\n",	msg->hdr.file);          // 服务器为客户端指定的启动配置，仅在 OFFER 报文中显示
	printf("magic\t");				// magic cookie 0x63, 0x82, 0x53, 0x63
	for (int i=0; i<4; i++)
		printf("%02x ", msg->hdr.magic[i]);
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
	size_t ret;
	size_t len = sizeof(reply->hdr);
    
	client_sock->sin_family = AF_INET;
	client_sock->sin_addr.s_addr = inet_addr("172.16.1.255");
	//client_sock->sin_addr.s_addr = inet_addr("255.255.255.255");
	client_sock->sin_port = htons(DHCP_CLIENT_PORT);
	if ((ret = sendto(fd, &reply->hdr, len, 0, (struct sockaddr *)client_sock, sizeof(*client_sock))) < 0) {
		error("sendto failed");
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

// 获取网桥名称
char *get_bridge_name()
{
	get_vnet_list(BRIDGE);

	char **p = bridge_list;
	char desc[VNET_BUFFERSIZE] = {0};
	int n = 0;
	while (*(p+n) != (void*)0) {
		get_bridge_desc(*(p+n), desc);
		if (strstr(desc, "bvm-nat")) {
			printf("%d.%s\n", n, *(p+n));
			listen_bridge(*(p+n));
		}
		++n;
	}

	//print_vnet_list(BRIDGE);
	free_vnet_list(BRIDGE);
	return NULL;
}

void get_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet)
{ 
	static int count = 0; 
	struct ether_header *eth_header; 
	u_char *ptr; 
     
	//printf("Packet length %d\n", hdr->len); 
	//printf("length of portion present: %d\n", hdr->caplen); 
 
	eth_header = (struct ether_header*)packet; 
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) { 
		printf("not ethernet packet\n"); 
		return; 
	} 
 
	//ptr = eth_header->ether_dhost; 
	int i = 0; 
	/*printf("destination address(MAC):"); 
	while (i < ETHER_ADDR_LEN) { 
		printf(" %x", *ptr++); 
		i++; 
	} 
 
	printf("\nsource address(MAC):"); */
	ptr = eth_header->ether_shost; 
	i = 0; 
	while (i < ETHER_ADDR_LEN) { 
		printf(" %02x", *ptr++); 
		i++; 
	} 
 
	//printf("\nfinish deal with %d packet\n", count); 
	count++; 
} 

// 监听网桥
// net_dev：网桥名称
int listen_bridge(char *net_dev)
{ 
	pcap_t *sniffer_des; 
	char errbuf[PCAP_ERRBUF_SIZE]; 
	bpf_u_int32 net, mask; 
	struct bpf_program fp; 
	const u_char *packet; 
	struct pcap_pkthdr hdr; 
     
	int ret; 
 
	char filter[] = "port 68"; 
 
	//net_dev = pcap_lookupdev(errbuf); 
	//if(net_dev == NULL){ 
	//    printf("get device error:%s\n", errbuf); 
	//    return 1; 
	//} 

	//获取网桥的ip地址和掩码
	if (pcap_lookupnet(net_dev, &net, &mask, errbuf) == -1) { 
		printf("get net error:%s\n", errbuf); 
		return 1; 
	} 
 	
	//输出IP地址和掩码
	struct in_addr addr;
	addr.s_addr = net;
	printf("ip: %s\n", inet_ntoa(addr));
	addr.s_addr = mask;
	printf("mask: %s\n", inet_ntoa(addr));

	sniffer_des = pcap_open_live(net_dev, 65535, 1, 5000, errbuf); 
	if (sniffer_des == NULL) { 
		printf("pcap_open_live%s\n", errbuf); 
		return 1; 
	} 
 
	if (pcap_compile(sniffer_des, &fp, filter, 0, mask) == -1) {
		printf("pcap_compile error\n"); 
		return 1; 
	} 
 
	if (pcap_setfilter(sniffer_des, &fp) == -1) {
		printf("pcap_setfilter() error\n"); 
		return 1; 
	} 
 
	ret = pcap_loop(sniffer_des, 1, get_packet, NULL); 
	if (ret == -1 || ret == -2) { 
		printf("cannot get the pcaket\n"); 
		return 1; 
	} 

	//packet = pcap_next(sniffer_des, &hdr);
	
	//cleanup
	pcap_freecode(&fp);
	pcap_close(sniffer_des);

	return 0; 
} 

// HTCP_DISCOVER 报文处理
int dhcp_discover_proc(dhcp_msg *request, dhcp_msg *reply)
{
	//设置yiaddr和sname
	reply->hdr.yiaddr = 0xac100102; //172.16.1.2

	//设置options
	//DHCP_MESSAGE_TYPE
	dhcp_option t;
	set_option(&t, DHCP_MESSAGE_TYPE, "2" /*DHCP_OFFER*/);
	add_option_list(&t, &reply->opts_list);

	//SERVER_IDENTIFIER
        set_option(&t, SERVER_IDENTIFIER, "172.16.1.1");
        add_option_list(&t, &reply->opts_list);

	//IP_ADDRESS_LEASE_TIME
	set_option(&t, IP_ADDRESS_LEASE_TIME, "3600");
        add_option_list(&t, &reply->opts_list);

	//RENEWAL_T1_TIME_VALUE
	set_option(&t, RENEWAL_T1_TIME_VALUE, "1800");
        add_option_list(&t, &reply->opts_list);

	//REBINDING_T2_TIME_VALUE
	set_option(&t, REBINDING_T2_TIME_VALUE, "3150");
	add_option_list(&t, &reply->opts_list);

	//SUBNET_MASK
	set_option(&t, SUBNET_MASK, "255.255.255.0");
	add_option_list(&t, &reply->opts_list);
	
	//END
        set_option(&t, END, NULL);
        add_option_list(&t, &reply->opts_list);

	//将列表写入options
	list_to_options(reply);

	return DHCP_OFFER;
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

		//--debug--
		warn("--- request ---\n");
		print_dhcp_msg(&request);

		//读取报文类型
		uint8_t type = get_dhcp_message_type(&request);

		//初始化应答报文
		init_reply(&request, &reply);
		
		//对不同的报文类型进行分支处理
		switch (type) {

		case DHCP_DISCOVER:
			type = dhcp_discover_proc(&request, &reply);
			break;

		case DHCP_REQUEST:
			warn("dhcp_request ....\n");
			//type = serve_dhcp_request(&request, &reply);
			break;
	    
		case DHCP_DECLINE:
			//type = serve_dhcp_decline(&request, &reply);
			break;
	    
		case DHCP_RELEASE:
	    		//type = serve_dhcp_release(&request, &reply);
			break;
	    
		case DHCP_INFORM:
			//type = serve_dhcp_inform(&request, &reply);
			break;
	    
		default:
			warn("%s.%u: request with invalid DHCP message type option\n", 
					inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
			break;
		}

		//发送应答报文
		if(type != 0) {
			warn("--- reply ---\n");
			print_dhcp_msg(&reply);
			warn("send ret=%d\n", send_dhcp_reply(fd, &client_sock, &reply));
		}
		
		destroy_option_list(request.opts_list);
		destroy_option_list(reply.opts_list);

	}
}

// DHCP SERVER 
int main(int argc, char **argv)
{
	test();
	int fd;
	struct protoent *pp;
	struct servent *ss;
	struct sockaddr_in server_sock;


	// 初始化
	if ((ss = getservbyname("bootps", "udp")) == 0) {
		error("server: getservbyname() error\n");
		exit(1);
	}

	if ((pp = getprotobyname("udp")) == 0) {
		error("server: getprotobyname() error\n");
		exit(1);
	}

	if ((fd = socket(AF_INET, SOCK_DGRAM, pp->p_proto)) == -1) {
		error("server: socket() error\n");
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
		error("server: bind()\n");
		close(fd);
		exit(1);
	}

	printf("dhcp server: listening on %d\n", ntohs(server_sock.sin_port));

	// 对接收到的报文进行处理
	message_controller(fd, server_sock);
	
	close(fd);
	return 0;
}


void test()
{
	get_bridge_name();return;
	warn("broadcast = %s\n", inet_ntoa(get_interfaces_broadcast("bridge0")));

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
