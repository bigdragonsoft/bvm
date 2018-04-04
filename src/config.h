#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME_LEN	200
#define	VALUE_LEN	512
#define	true		1
#define false		0

//链表节点数据结构
struct _key{
	char	name[NAME_LEN];
	char	value[VALUE_LEN];
	struct	_key*	prive;
	struct	_key*	next;
};

typedef struct _key key_type;


//数据链表结构体
struct _list_key{
	key_type	*head;
	key_type	*tail;
};

typedef struct _list_key list_t;

//全局变量，初始化链表地址
extern list_t *list;
extern list_t LIST;


void init_config(const char *);		//接口函数, 初始化数据结构 ***
char * get_value_by_name(const char *); //接口函数，根据键值名获取键值 ***
void free_config(void);			//接口函数，释放动态申请内存 ***
void print_list(void);			//debug 函数查看所有 key->value ***
//
//
//
int has_equal(const char *str);
void add_key_to_list(key_type);
void copy_data(key_type *, key_type);
void read_config(const char *);
int check_shot_notes(const char *);
int check_long_start_notes(const char *);
int check_long_end_notes(const char *);
char * check_notes(int *,const char *);
void * malloc_data(size_t, int);
void delte_space(char *);
char * get_str_in_line(char *, const char *);
void make_str_to_key(char *);
int has_double_quotes(const char *);
char * get_str_in_long_end_notes(char *, const char *);
char * get_double_qutes(char *str);
void str_to_key(key_type *, char *);

#endif // _CONFIG_H

