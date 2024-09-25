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

#ifndef BVM_DHCP_H
#define BVM_DHCP_H

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

#include "vnet.h"
#include "config.h"

#define DHCP_BROADCAST_FLAG 	0x8000
#define DHCP_INVALID 		-1
#define DHCP_NONE		0

//地址池输出类型
enum OUTPUT_TYPE_ENUM {
	OUTPUT_TO_CONSOLE = 0,
	OUTPUT_TO_FILE = 1,
};

// 报文类型
enum DHCP_MSSAGE_TYPES_ENUM {
	DHCP_DISCOVER = 1,
	DHCP_OFFER    = 2,
	DHCP_REQUEST  = 3,
	DHCP_DECLINE  = 4,
	DHCP_ACK      = 5,
	DHCP_NAK      = 6,
	DHCP_RELEASE  = 7,
	DHCP_INFORM   = 8,
};


// options 可选项代码
enum DHCP_OPTIONS_ENUM {

	// 用于后续字节字段在单词边界上对齐，填充功能
	PAD = 0,	//value:0

	//标识报文option字段结束，后面的字节应该由pad填充
	END = 255,	//value:0xff

	//子网掩码选项
	SUBNET_MASK = 1,

	//路由器选项
	ROUTER = 3,

	//指定DHCP Client可用的DNS的地址列表
	DOMAIN_NAME_SERVER = 6,

	//DHCP Client填充自己的主机名，可以是本地域名限定，也可以不限定，长度最小为1
	HOST_NAME = 12,

	//客户端通过域名系统解析主机名
	DOMAIN_NAME = 15,

	//客户端请求（DHCPDISCOVER）中，客户端请求分配特定的IP地址
	REQUESTED_IP_ADDRESS = 50,		

	//客户端请求（DHCPDISCOVER或DHCPREQUEST）中，客户端请求IP 地址的租用时间。
	//在服务器应答（DHCPOFFER）中，DHCP服务器使用此选项指定它愿意提供的租用时间
	IP_ADDRESS_LEASE_TIME = 51,

	//DHCP 报文类型
	DHCP_MESSAGE_TYPE = 53,

	//用于DHCPOFFER和DHCPREQUEST消息中，并且可以选择包含在DHCPACK和DHCPNAK消息中。
	//DHCP Server在DHCPOFFER中包含此选项，以便客户端区分哪一个DHCP Server提供的服务。
	//DHCP Client通过在DHCPREQUEST消息中包含此选项来接收哪一个Server的服务。
	SERVER_IDENTIFIER = 54,

	//表示DHCP Client请求指定的配置参数列表。客户端可以按优先顺序列出选项。
	//DHCP Server不需要按请求的顺序返回选项，但必须尝试按客户端请求的顺序插入请求的选项。
	PARAMETER_REQUEST_LIST = 55,

	//DHCP服务器使用此选项在发生故障时通过DHCPNAK消息向DHCP客户端提供错误消息。
	//客户机可以在DHCPDECLINE消息中使用此选项来指示客户机拒绝所提供参数的原因，
	//客户端可以将其显示在可用的输出设备上。
	MESSAGE = 56,

	//指定从地址分配到客户端转换到续订状态的时间间隔，一般为租约时间的一半
	RENEWAL_T1_TIME_VALUE = 58,

	//指定从地址分配到客户端转换到重新绑定状态的时间间隔，一般为租约时间87.5%
	REBINDING_T2_TIME_VALUE = 59,

	//DHCP客户端使用此选项来选择性地标识DHCP客户端的类型和配置
	VENDOR_CLASS_IDENTIFIER = 60,

	//DHCP客户端使用此选项指定其唯一标识符。
	//DHCP服务器使用这个值来索引它们的地址绑定数据库。
	//此值对于管理域中的所有客户端都是唯一的。
	CLIENT_IDENTIFIER = 61

};

// 端口
enum PORTS_ENUM {
	DHCP_SERVER_PORT = 67,
	DHCP_CLIENT_PORT = 68
};

// 报文操作类型
enum OP_TYPES_ENUM {
	BOOTREQUEST = 1,	//请求
	BOOTREPLY   = 2,	//应答
};

// MAC 地址类型
enum HARDWARE_ADDR_TYPES_ENUM {
	ETHERNET     = 0x01,
	ETHERNET_LEN = 0x06,
};

// DHCP 报文格式 -----------------------------------------------------------------------------
enum {
	DHCP_HEADER_SIZE = 236,	//报文头部（options之前）所占字节数
};

struct _dhcp_message_header {
	uint8_t 	op;		// 报文类型 1=请求，2=应答
	uint8_t 	htype;		// 客户端 MAC 地址类型 1=以太网
	uint8_t 	hlen;		// 客户端 MAC 地址长度 6=以太网长度
	uint8_t 	hops;		// 经过中继服务器的个数
	uint32_t 	xid;		// 客户端的随机校验码
	uint16_t 	secs;		// 从获取到 IP 地址或者续约开始到现在的消耗时间
	uint16_t 	flags;		// 广播应答标志位 0x8000=广播 0x0000=单播
	uint32_t 	ciaddr;		// 客户端 IP 地址，仅在服务器发送的 ACK 报文中显示
	uint32_t 	yiaddr;		// 服务器分配给客户端的 IP 地址，仅在服务器发送 OFFER 和 ACK 报文中显示
	uint32_t 	siaddr;		// 下一个为客户端分配 IP 地址的服务器 IP
	uint32_t 	giaddr;		// 客户端发出请求报文后经过的第一个中继服务器的 IP 地址
	uint8_t 	chaddr[16];	// 客户端 MAC 地址
	uint8_t 	sname[64];	// DHCP 服务器名称，在 OFFER 和 ACK 报文中显示
	uint8_t 	file[128];	// 服务器为客户端指定的启动配置，仅在 OFFER 报文中显示
	uint8_t		magic[4];	// magic cookie 0x63, 0x82, 0x53, 0x63
	uint8_t 	options[312];	// 可选项字段，长度可变
};
typedef struct _dhcp_message_header dhcp_message_header;

// DHCP options 
// 可选选项格式为 “代码 + 长度 + 数据”
struct _dhcp_option {
    uint8_t id;        // 代码
    uint8_t len;       // 长度
    uint8_t data[256]; // 数据

};
typedef struct _dhcp_option dhcp_option;

// 由于options为可变长度，所以定义一个链表记录数据
struct _dhcp_option_list {
	dhcp_option opts;
	struct _dhcp_option_list *next;
};
typedef struct _dhcp_option_list dhcp_option_list;

// 完整的报文格式（包含options链表）
struct _dhcp_msg {
	dhcp_message_header hdr;
	dhcp_option_list *opts_list;
};  
typedef struct _dhcp_msg dhcp_msg;


// DHCP 地址池 -----------------------------------------------------------------------------
// 地址绑定的格式
enum BIND_STATUS {
	ERROR_STATUS = -1,	// 错误状态
	EMPTY = 0,		// 空闲
	ASSOCIATED,		// 已分配
	PENDING,		// 未完成
	EXPIRED,		// 已过期
	RELEASED,		// 已回收
	DISABLE,		// 禁用
	STATIC,			// 静态ip
};

struct _address_bind {
	uint32_t ip;		// ip地址
	uint8_t mac[16];	// mac地址
	uint32_t xid;		// 验证码
	uint8_t cid[16];	// 客户端标识
	uint8_t cid_len;	// 客户端标识长度
	time_t bind_time;	// 绑定开始的时间
	int status;		// 绑定的状态
};
typedef struct _address_bind address_bind;

// 地址绑定链表
struct _address_bind_list {
	address_bind addr;
	struct _address_bind_list *next;
};
typedef struct _address_bind_list address_bind_list;

// DHCP 服务器
struct _dhcp_server_stru {
	uint32_t ip;		// 服务器ip
	uint32_t netmask;	// 服务器掩码
	uint32_t broadcast;	// 服务器广播域
	uint32_t gateway;	// 网关
	char dns[128];		// DNS
	char domain_name[128];	// DOMAIN_NAME
	char ifname[16];	// 网卡（网桥）名称
	char nat[16];		// nat名称
	uint32_t lease_time;	// 租赁时间长度
	uint32_t first_ip;	// 动态ip开始
	uint32_t last_ip;	// 动态ip结束
	uint32_t current_ip;	// 当前要分配的动态ip

	address_bind bind[256];
	//address_bind_list *bind_list;
};
typedef struct _dhcp_server_stru dhcp_server_stru;

// 网桥监控 -----------------------------------------------------------------------------
enum {
	REMOVE_BRIDGE = 0,		//删除网桥
	REMOVE_MAC,			//删除MAC
};

enum {
	BRIDGE_INIT =0,			//初始状态
	BRIDGE_WORKING,			//网桥工作中
	BRIDGE_REMOVE,			//删除网桥
	BRIDGE_NEW,			//新增网桥
};

struct _listen_dev_stru {
	char name[VNET_BUFFERSIZE];	//网桥名称
	int status;			//网桥的状态 1:正在监控，2:无需监控，3:新增监控
	pthread_t tid;			//线程id
};
typedef struct _listen_dev_stru listen_dev_stru;

//主机mac地址与网桥的对应结构
struct _host_mac_stru {
	char ifname[VNET_BUFFERSIZE];	//网桥名称
	uint8_t mac[16];		//经过网桥服务器的MAC地址
};
typedef struct _host_mac_stru host_mac_stru;

//对应结构链表
struct _host_mac_list {
        host_mac_stru host;
        struct _host_mac_list *next;
};
typedef struct _host_mac_list host_mac_list;

//给pcap_loop回调函数中传递参数的结构
struct _configuration {
	int id;
	char title[255];
};
typedef struct _configuration configuration;

/************函数部分**************/

//线程
void *dhcp_server();
void *scan_if();
void *listen_bridge(void *net_dev);


//地址池 ----------
void init_dhcp_pool();
int  get_server_index(uint8_t *mac);
int  find_bridge_in_pool(char *dev);
int  find_mac_in_pool(int server_id, uint8_t *mac);
int  find_empty_ip_in_pool(int server_id);
int  get_ip_status_in_pool(int server_id, uint32_t *ip, int *bind_idx);
int  fresh_pool(int server_id);
void init_address_bind(address_bind *bind);
void fill_bind_in_pool(int server_idx, int bind_idx, int status, dhcp_msg *request);
void print_dhcp_pool(int output, int server_idx, int bind_idx);
void print_dhcp_pool_used(int output);


//报文处理 ----------
int  get_dhcp_message_type(dhcp_msg *msg);
int  set_option(dhcp_option *opt, uint8_t id, char *data);
int  load_options(dhcp_option *opt, uint8_t id, dhcp_msg *msg);
int  list_to_options(dhcp_msg *msg);
int  add_option_list(dhcp_option *opt, dhcp_option_list **list);

void message_controller(int fd, struct sockaddr_in server_sock);

int dhcp_discover_proc(dhcp_msg *request, dhcp_msg *reply);
int dhcp_request_proc(dhcp_msg *request, dhcp_msg *reply);
int dhcp_decline_proc(dhcp_msg *request, dhcp_msg *reply);
int dhcp_release_proc(dhcp_msg *request, dhcp_msg *reply);
int dhcp_inform_proc(dhcp_msg *request, dhcp_msg *reply);

void init_reply(dhcp_msg *request, dhcp_msg *reply);
void set_reply_options(dhcp_msg *reply, int dhcp_type, int server_idx, int bind_idx);
int  send_dhcp_reply(int s, struct sockaddr_in *client_sock, dhcp_msg *reply);

void init_option_list(dhcp_option_list *list);
void destroy_option_list(dhcp_option_list *list);
void print_option_list(dhcp_option_list *list);
void print_options(dhcp_msg *msg);
void print_dhcp_msg(dhcp_msg *msg);

int parse_byte(char *s, void **p);
int parse_byte_list (char *s, void **p);
int parse_short(char *s, void **p);
int parse_short_list(char *s, void **p);
int parse_long(char *s, void **p);
int parse_string(char *s, void **p);
int parse_ip(char *s, void **p);
int parse_ip_list(char *s, void **p);
int parse_mac(char *s, void **p);
uint8_t parse_option(dhcp_option *opt, char *name, char *value);


//监控网桥 ----------
void get_bridge_name(listen_dev_stru *dev);
int  get_bridge_num(listen_dev_stru *dev);
void bridge_cmp(listen_dev_stru *cur_dev, listen_dev_stru *new_dev);

void create_listen(listen_dev_stru *dev);
void get_packet(u_char *dev, const struct pcap_pkthdr *hdr, const u_char *packet);

struct in_addr *get_interfaces_ip(const char *ifname);
struct in_addr *get_interfaces_netmask(const char *ifname);
struct in_addr get_interfaces_broadcast(const char *ifname);
int get_interfaces_mac(char *ifname, uint8_t *mac); 
 
int add_client_list(host_mac_stru *host);
void destroy_client_list();
host_mac_stru *find_client(host_mac_stru *host);
int remove_client(int type, host_mac_stru *host);
int print_client_list();


//辅助函数 ----------
char *ip_to_str(uint32_t ip);
char *mac_to_str(uint8_t *mac);
char *status_to_str(int status);
char *time_to_str(time_t time);

void test();

#endif	//BVM_DHCP_H
