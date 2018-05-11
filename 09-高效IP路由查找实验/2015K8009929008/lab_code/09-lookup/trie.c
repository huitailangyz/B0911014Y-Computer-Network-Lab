#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <endian.h>
#include <time.h>
typedef uint8_t u8;
typedef uint32_t u32;

#define MAX_CHILD 2

#define IP_FMT	"%hhu.%hhu.%hhu.%hhu"
#define LE_IP_FMT_STR(ip) ((u8 *)&(ip))[3], \
						  ((u8 *)&(ip))[2], \
 						  ((u8 *)&(ip))[1], \
					      ((u8 *)&(ip))[0]

#define BE_IP_FMT_STR(ip) ((u8 *)&(ip))[0], \
						  ((u8 *)&(ip))[1], \
 						  ((u8 *)&(ip))[2], \
					      ((u8 *)&(ip))[3]

#if __BYTE_ORDER == __LITTLE_ENDIAN
#	define HOST_IP_FMT_STR(ip)	LE_IP_FMT_STR(ip)
#elif __BYTE_ORDER == __BIG_ENDIAN
#	define HOST_IP_FMT_STR(ip)	BE_IP_FMT_STR(ip)
#endif


typedef struct Tree
{
	int match;
	struct Tree *child[MAX_CHILD];
	u32 ip;
	u8 mask_bit;
	u8 port;
}Node;





Node *CreateTrie(){
	Node *node = (Node *)malloc(sizeof(Node));
	memset(node, 0, sizeof(Node));
	//printf("Create a node.\n");
	return node;
}


void insert_node(Node *root, u32 ip, u8 mask_bit, u8 port){
	if (root == NULL)
		return ;
	Node *t = root; 
	int i = 1;
	while (i <= mask_bit)
	{
		u8 bit = (ip >> (32 - i)) & 0x01;
		if (t->child[bit] == NULL)
		{
			Node *tmp = CreateTrie();
			t->child[bit] = tmp;
		}
		t = t->child[bit];
		i++;
	}
	t->match = 1;
	t->ip = ip;
	t->mask_bit = mask_bit;
	t->port = port;
	//printf("Insert IP addr: "IP_FMT"\n", HOST_IP_FMT_STR(ip));
}




Node *search_node(Node *root, u32 ip){
	Node *now_match = NULL;
	
	if (NULL == root){
		printf("Trie is empty.\n");
		return now_match;
	}

	int i = 1;
	Node *t = root;
	while (i <= 32)
	{     
		u8 bit = (ip >> (32 - i)) & 0x01;
		if (t->child[bit] != NULL){
			t = t->child[bit];
			if (t->match)
				now_match = t;
			i++;
		}
		else
			break;
	}
	return now_match;
}


void del(Node *root){
	int i;
	for (i = 0; i < MAX_CHILD; i++)
	{
		if (root->child[i] != NULL)
			del(root->child[i]);
	}
	free(root);
}

u32 convert_ip_str_to_u32(char *ip_str){
	u32 ip = 0;
	u32 temp_int = 0;
	//printf("Begin convert.\n");
	while (*ip_str){
		if (*ip_str != '.'){
			temp_int *= 10;
			temp_int += (*ip_str) - 48; 
		}
		else{
			ip <<= 8;
			ip += temp_int;
			temp_int = 0;
		}
		ip_str++;
	}
	ip <<= 8;
	ip += temp_int;
	return ip;
}

int main()
{
	FILE *fp;
	fp = fopen("./forwarding-table.txt", "r"); 
	printf("Begin to build trie.\n");
	char ip_str[20];
	u8 mask_bit, port;
	Node *root = CreateTrie();
	while (fscanf(fp,"%s %d %d", ip_str, &mask_bit, &port) != EOF){
		//printf("Read in an entry.\n");
		u32 ip = convert_ip_str_to_u32(ip_str);
		insert_node(root, ip, mask_bit, port);
	}
	fclose(fp);
	printf("Trie has been built.\n");
	printf("Begin to query.\n");
	/*
	printf("Input a IP addr to search: ");
	while (scanf("%s", ip_str) != EOF)
	{
		Node *result = search_node(root, convert_ip_str_to_u32(ip_str));
		if (result)
			printf("IP addr: "IP_FMT"\t Mask bit: %d \t Port: %d\n", HOST_IP_FMT_STR(result->ip), result->mask_bit, result->port);
		else
			printf("Not found.\n");
		printf("Input a IP addr to search: ");
	}
	*/
	double dur;
	clock_t start, end;
	u32 *entries = (u32 *)malloc(sizeof(u32));
	*entries = 0;
	Node *result;
	fp = fopen("./forwarding-table.txt", "r"); 
	start = clock();
	while (fscanf(fp, "%s %d %d", ip_str, &mask_bit, &port) != EOF) {
		(*entries)++;
		result = search_node(root, convert_ip_str_to_u32(ip_str));
		//printf("Search for IP addr: %s\n", ip_str);
		//if (result)
		//	printf("Found IP addr: "IP_FMT"\n", HOST_IP_FMT_STR(result->ip));
		//else
		//	printf("Not found.\n");
	}
	end = clock();
	dur = (double)(end - start);
	printf("Use Time: %f us for %d time searches. Each time cost %f us.\n", dur, *entries, dur / *entries);
	fclose(fp);
	printf("End of query.\n");
	del(root);
	printf("Free the trie.\n");
	return 0;
}