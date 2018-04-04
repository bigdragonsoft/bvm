/* ICEAGE 写于 2017年12月8日
 * 此模块用于读取配置文件中的键值
 * 配置文件的书写方式为: key = value
 * 可以过滤掉不含有 "[=]" 的行
 * 支持 "[#] [;] [//] [/ * * /]" 等类型注释
 * 支持空格过滤，如必须使用空格，支持双引号引用字符串，这样空格可以保留
 */

#include "config.h"


list_t	*list, LIST;


//释放动态内存
void free_config()
{

	key_type   *curr = list->head;

	if(curr != NULL){
		for(;curr != NULL; curr = curr->next){
			free(curr->prive);
		}
	}
}


//根据键名获取键值接口 ****
char * get_value_by_name(const char * name)
{
	key_type	*curr = list->head;

	while(curr){
		if(strcmp(curr->name, name) == 0)
			return curr->value;
		curr = curr->next;
	}

	return NULL;
}



//判断是否有等于号
int has_equal(const char *str)
{
	int	i;

	for(i = 0; i < strlen(str); i++){
		if(*(str + i) == 61) return true;
	}

	return false;
}




//读取配置文件
void read_config(const char * config_name)
{
	FILE	*fp;
	char	buf[NAME_LEN + VALUE_LEN];
	int	long_flag = 0;
	char	*str;

	if(!(fp = fopen(config_name, "r"))){
		printf("Open %s error\n", config_name);
		exit(0);
	}

	while(!feof(fp)){
		fscanf(fp, "%[^\n]\n", buf);
		if(has_equal(buf)){
			if((str = check_notes(&long_flag, buf))){
				make_str_to_key(str);
			}
		}
	}

	fclose(fp);
}

//从字符串中获取键名和键值
void make_str_to_key(char * str)
{
	key_type	key;

	str_to_key(&key, str);
	delte_space(key.name);

	has_double_quotes(key.value) ? get_double_qutes(key.value) : delte_space(key.value);
	add_key_to_list(key);

	free(str);
}

/*
//从字符串中获取键名和键值
void make_str_to_key(char * str)
{
	key_type	key;

	if (has_double_quotes(key.value))
		get_double_qutes(key.value);
	else
		str_to_key(&key, str);

	delte_space(key.value);

	add_key_to_list(key);

	free(str);
}
*/

void str_to_key(key_type * key, char * str)
{
	int     i;
	int     j = 0;
	int     flag = false;

	//printf("%s\n", str);
	for(i=0; i<strlen(str); i++){
		if (flag != true)
		if(*(str + i) == 61){
			flag = true;
			*(key->name + i) = '\0';
			continue;
		}

		if(!flag){
			*(key->name + i) = *(str + i);
		}else{
			*(key->value + j) = *(str + i);
			j++;
		}
	}

	*(key->value + j) = '\0';

}





char * get_double_qutes(char *str)
{
	char tmp[VALUE_LEN];

	int	i;
	int	j = 0;
	int	flag = false;

	strcpy(tmp, str);
	memset(str, 0, strlen(str));

	for(i=0; i<strlen(tmp); i++){
		if(!flag && *(tmp + i) == 34){
			flag = true;
			continue;
		}

		if(flag && (*(tmp + i) != 34)){
			*(str + j) = *(tmp + i);
			j++;
		}
	}

	*(str + j) = '\0';

	return str;
}

//判断双引号
int has_double_quotes(const char *str)
{
	int	i;
	int	flag = 0;

	for(i = 0; i < strlen(str); i++){
		if(*(str + i) == 34) flag++;
	}

	return (flag > 1) ? true : false;

}



//删除字符串中空格
void delte_space(char *str)
{
	char	tmp[VALUE_LEN + NAME_LEN];
	int	i, j = 0;


	strcpy(tmp, str);

	for(i = 0; i < strlen(tmp); i++){
		if(*(tmp+i) != 32){
			*(str+j) = *(tmp+i);
			j++;
		}
	}

	*(str+j) = '\0';
}






//检查 "[#] [;] [//] [/* */]" 等类型注释
char * check_notes(int * flag, const char * str)
{

	char * p;
	p = (char *)malloc_data(sizeof(char), VALUE_LEN + NAME_LEN);

	if(!(*flag)){
		if(check_long_start_notes(str)){
			*flag = 1;
			 return get_str_in_line(p, str);
		}else{
			return check_shot_notes(str) ? get_str_in_line(p, str) : strcpy(p,str);
		}
	}else{
		if(check_long_end_notes(str)){
		       	*flag = 0;
			return get_str_in_long_end_notes(p, str);
		}
		return NULL;
	}
}


//获取长注释行 [* /] 结尾后的字符串
char * get_str_in_long_end_notes(char * dst, const char * str)
{
	int	i = 0;
	int	j = 0;

	for(i = 0; i < strlen(str); i++)
		if(*(str + i) == 42 && *(str + i + 1) == 47) break;


	for(i += 2; i < strlen(str); i++){
		if(*(str + i) != '\0'){
			*(dst+j) = *(str+i);
			j++;
		}
	}

	*(dst+j) = '\0';
	return dst;
}



// 获取注释行中的字符串 比如： [name = value # notice ....], 则获取 # 之前内容
char * get_str_in_line(char *dst, const char * str)
{
	int	i = 0;
	int	j = 0;

	if(*str == 35 || *str == 59 || (*str == 47 && *(str + 1) == 47) || (*(str + i) == 47 && *(str + i - 1) == 42))
		return NULL;
	else{
		for(i = 0; i < strlen(str) ; i++){
			if(( *(str+i) != 35 && *(str+i) != 59) && (*(str + i) != 47 || *(str + i + 1) != 47)
				       	&& (*(str + i) != 47 || *(str + i + 1) != 42)){

				*(dst+j) = *(str+i);
				j++;
			}else break;
		}
	}

	if(i) *(dst + j) = '\0';

	return dst;
}




//强制申请内存
void * malloc_data(size_t size, int len)
{
	void * p = NULL;

	while(!p) p = (void *)malloc(size * len);

	return p;
}




// 检查 "[ /* */]" 类型注释的后半部分
int check_long_end_notes(const char * str)
{
	int i;
	for(i = 0; i < strlen(str) - 1; i++){
		if(*(str + i) == 42 && *(str + i + 1) == 47)
			return true;
	}

	return false;
}






// 检查 "[ /* */]" 类型注释的前半部分
int check_long_start_notes(const char * str)
{
	int i;
	for(i = 0; i < strlen(str) - 1; i++){
		if(*(str + i) == 47 && *(str + i + 1) == 42)
			return true;
	}

	return false;
}




// 判断是否为 "[#] [;] [//]" 类型注释
int check_shot_notes(const char * str)
{
	int i;

	for(i = 0; i < strlen(str) - 1; i++){
		if(*(str + i) == 35 || (*(str + i) == 47 && *(str + i + 1) == 47) || *(str + i) == 59)
			return true;
	}

	return false;
}



//初始化数据结构(双向链表)
void init_config(const char * file_name)
{
	list = &LIST;
	list->head = NULL;
	list->tail = NULL;

	read_config(file_name);
}



//链表中添加数据
void add_key_to_list(key_type key)
{
	key_type	*new;

	new = (key_type *)malloc_data(sizeof(key_type), 1);

	new->prive = NULL;
	new->next = NULL;
	copy_data(new, key);

	if(!list->head){
		list->tail = list->head = new;
	}else{
		new->prive = list->tail;
		list->tail->next = new;
		list->tail = new;
	}
}


//复制数据到链表节点中
void copy_data(key_type * dst, key_type src)
{
	strcpy(dst->name, src.name);
	strcpy(dst->value, src.value);
}





//打印整个链表
void print_list(void)
{
	key_type * curr = list->head;

	while(curr != NULL){
		printf("name: %s\t value:%s\n", curr->name, curr->value);
		curr = curr->next;
	}
}





