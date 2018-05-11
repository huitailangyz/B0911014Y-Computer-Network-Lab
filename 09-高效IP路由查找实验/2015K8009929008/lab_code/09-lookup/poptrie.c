#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <endian.h>
#include <time.h>
typedef uint8_t u8;
typedef uint32_t u32;

#define MAX_CHILD 1 << 4

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


#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))


typedef struct leaf{
	u32 ip;
	u8 mask_bit;
	u8 port;
}Leaf;

typedef struct node{
	struct node **node;
	struct leaf **leaf;
	u8 num_leaf;
	u8 num_node;
	u8 bitarray[MAX_CHILD]; //0 NULL  1 node  2 leaf
	
	//DEBUG USE
	u32 ip;
	u8 mask_bit;
	u8 matchbit;
}Node;


Leaf *CreateLeaf(){
	Leaf *leaf = (Leaf *)malloc(sizeof(Leaf));
	memset(leaf, 0, sizeof(Leaf));
	return leaf;
}


Node *CreateNode(){
	Node *node = (Node *)malloc(sizeof(Node));
	memset(node, 0, sizeof(Node));
	return node;
}

#define CHAR_BIT 8
 
void bit_print(u32 a)
{
	int i;
	int n = sizeof(u32) * CHAR_BIT;
	u32 mask = 1 << (n - 1);
	for (i = 1; i <= n; ++i)
	{
		putchar(((a & mask) == 0) ? '0' : '1');
		a <<= 1;
		if (i % CHAR_BIT == 0 && i < n)
			putchar(' ');
	}
	printf("\n");
}

void insert_node(Node *root, u32 ip, u8 mask_bit, u8 port){
	int i = 0;
	//printf("Begin Insert.\n");
	//bit_print(ip);
	while ((4 * (i+1)) < mask_bit){
		//printf("i = %d\n",i);
		u8 now_bit = 0xf & (ip >> (28 - 4*i));
		//bit_print(now_bit);
		if (root->bitarray[now_bit] == 0)
		{
			struct node **node_arr = root->node;
			root->node = (struct node **)malloc((root->num_node + 1) * sizeof(struct node *));
			int j = 0;
			for (int i = 0; i < now_bit; i++)
				if (root->bitarray[i] == 1)
				{
					root->node[j] = node_arr[j];
					j++;
				}
			int index = j;
			root->node[j] = CreateNode();
			j++;
			for (int i = now_bit + 1; i < 16; i++)
				if (root->bitarray[i] == 1)
				{
					root->node[j] = node_arr[j - 1];
					j++;
				}
			root->num_node++;
			root->bitarray[now_bit] = 1;
			root = root->node[index];
		}
		else if (root->bitarray[now_bit] == 1)
		{
			int j = 0;
			for (int i = 0; i < now_bit; i++)
				if (root->bitarray[i] == 1)
				{
					j++;
				}
			root = root->node[j];
		}
		else {
			int j_1 = 0;
			for (int i = 0; i < now_bit; i++)
				if (root->bitarray[i] == 2)
				{
					j_1++;
				}
			struct leaf *leaf = root->leaf[j_1];
			for (int i = j_1; i < root->num_leaf; i++){
				root->leaf[j_1] = root->leaf[j_1 + 1];
			}
			root->num_leaf--;
			struct node **node_arr = root->node;
			root->node = (struct node **)malloc((root->num_node + 1) * sizeof(struct node *));
			int j_2 = 0;
			for (int i = 0; i < now_bit; i++)
				if (root->bitarray[i] == 1)
				{
					root->node[j_2] = node_arr[j_2];
					j_2++;
				}
			int index = j_2;
			root->node[j_2] = CreateNode();
			root->node[j_2]->matchbit = 1;
			root->node[j_2]->ip = leaf->ip;
			root->node[j_2]->mask_bit = leaf->mask_bit;
			j_2++;
			for (int i = now_bit + 1; i < 16; i++)
				if (root->bitarray[i] == 1)
				{
					root->node[j_2] = node_arr[j_2 - 1];
					j_2++;
				}
			root->num_node++;
			root->bitarray[now_bit] = 1;
			root = root->node[index];		
		}
		i++;
	}
	// last 1-4 bit match
	u8 matchbit = mask_bit % 4;
	u8 begin_bit, end_bit;
	if (matchbit == 0)
		matchbit = 4;
	if (matchbit == 1){
		begin_bit = 0x1 & (ip >> (32 - mask_bit));
		begin_bit <<= 3;
		end_bit = begin_bit + 7;
	}
	if (matchbit == 2){
		begin_bit = 0x3 & (ip >> (32 - mask_bit));
		begin_bit <<= 2;
		end_bit = begin_bit + 3;
	}
	if (matchbit == 3) {
		begin_bit = 0x7 & (ip >> (32 - mask_bit));
		begin_bit <<= 1;
		end_bit = begin_bit + 1;
	}
	if (matchbit == 4) {
		begin_bit = 0xf & (ip >> (32 - mask_bit));
		end_bit = begin_bit;
	}
	//printf("Begin bit :");
	//bit_print(begin_bit);
	//printf("End bit :");
	//bit_print(end_bit);

	for (int i = begin_bit; i <= end_bit; i++){
		//printf("%d\n", root->bitarray[i]);
		//for (int t = 0; t < 16; t++)
		//	printf("%d ",root->bitarray[t]);
		//printf("\n");
		if (root->bitarray[i] == 1)
		{
			int j = 0;
			for (int t = 0; t < i; t++)
				if (root->bitarray[t] == 1)
					j++;
			root->node[j]->matchbit = 1;
			root->node[j]->ip = ip;
			root->node[j]->mask_bit = mask_bit;
		}
		else if (root->bitarray[i] == 0){
			struct leaf **leaf_arr = root->leaf;
			//printf("root->num_leaf :%d\n", root->num_leaf);
			//printf("TEST POINT 1\n");
			root->leaf = (struct leaf **)malloc((root->num_leaf + 1) * sizeof(struct leaf *));
			//printf("TEST POINT 2\n");
			int j = 0;
			for (int t = 0; t < i; t++)
				if (root->bitarray[t] == 2)
				{
					root->leaf[j] = leaf_arr[j];
					j++;
				}
			int index = j;
			//printf("TEST POINT 3\n");
			root->leaf[j] = CreateLeaf();
			//printf("TEST POINT 4\n");
			root->leaf[j]->ip = ip;
			root->leaf[j]->mask_bit = mask_bit;
			root->leaf[j]->port = port;
			j++;
			for (int t = i + 1; t < 16; t++)
				if (root->bitarray[t] == 2)
				{
					root->leaf[j] = leaf_arr[j - 1];
					j++;
				}
			//printf("TEST POINT 5\n");
			root->num_leaf++;
		}
		root->bitarray[i] = 2;
	}
	//printf("Insert IP addr: "IP_FMT"\n", HOST_IP_FMT_STR(ip));
}




u32 search_node(Node *root, u32 ip){
	u32 now_match;
	
	if (NULL == root){
		printf("Trie is empty.\n");
		return now_match;
	}
	int i = 0;
	while (i < 32){
		u32 match_bit = 0xf & (ip >> (28 - i));
		if (root->bitarray[match_bit] == 0)
			return now_match;
		else if (root->bitarray[match_bit] == 1){
			int j = 0;
			for (int t = 0; t < match_bit; t++)
				if (root->bitarray[t] == 1)
					j++;
			root = root->node[j];
			if (root->matchbit == 1)
				now_match = root->ip;
		}
		else{
			int j = 0;
			for (int t = 0; t < match_bit; t++)
				if (root->bitarray[t] == 2)
					j++;
			now_match = root->leaf[j]->ip;
			return now_match;
		}
		i += 4;
	}
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
	printf("New file.\n");
	Node *root = CreateNode();
	while (fscanf(fp,"%s %d %d", ip_str, &mask_bit, &port) != EOF){
		//printf("Read in an entry.\n");
		u32 ip = convert_ip_str_to_u32(ip_str);
		insert_node(root, ip, mask_bit, port);
	}
	fclose(fp);
	printf("Trie has been built.\n");
	printf("Begin to query.\n");

	double dur;
	clock_t start, end;
	u32 *entries = (u32 *)malloc(sizeof(u32));
	*entries = 0;
	u32 result;
	fp = fopen("./forwarding-table.txt", "r"); 
	start = clock();
	while (fscanf(fp, "%s %d %d", ip_str, &mask_bit, &port) != EOF) {
		(*entries)++;
		result = search_node(root, convert_ip_str_to_u32(ip_str));
		printf("Search for IP addr: %s\n", ip_str);
		if (result)
			printf("Found IP addr: "IP_FMT"\n", HOST_IP_FMT_STR(result));
		else
			printf("Not found.\n");
	}
	end = clock();
	dur = (double)(end - start);
	printf("Use Time: %f us for %d time searches. Each time cost %f us.\n", dur, *entries, dur / *entries);
	fclose(fp);
	printf("End of query.\n");
	//del(root);
	printf("Free the trie.\n");
	return 0;
}