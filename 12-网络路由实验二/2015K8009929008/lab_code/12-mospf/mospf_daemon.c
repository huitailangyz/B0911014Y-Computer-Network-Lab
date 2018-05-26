#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"
#include "packet.h"
#include "arp.h"
#include "list.h"
#include "log.h"
#include "rtable.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <limits.h>

#define MAX_ROUTER 16
#define MAX_SUBNET 64

extern ustack_t *instance;
const u8 mospf_hello_mac[6] = { 0x10, 0x00, 0x5e, 0x00, 0x00, 0x05 };
pthread_mutex_t mospf_nbr_lock, mospf_db_lock;;


void mospf_init()
{
	pthread_mutex_init(&mospf_nbr_lock, NULL);
	pthread_mutex_init(&mospf_db_lock, NULL);
	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_db_thread(void *param);
void send_new_lsu();
void dump_mospf_db();
void update_rtable();

void mospf_run()
{
	pthread_t hello, lsu, nbr, db;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
    pthread_create(&db, NULL, checking_db_thread, NULL);
}

void *sending_mospf_hello_thread(void *param)
{
	//fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");
	while (1){
		iface_info_t *iface = NULL;
		list_for_each_entry(iface, &instance->iface_list, list) {
			char *packet = (char *)malloc(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);
			memset(packet, 0, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);
			struct mospf_hello *m_hello = (struct mospf_hello *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);
			struct mospf_hdr *m_hdr = (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
			struct iphdr *ip_hdr = (struct iphdr *)(packet + ETHER_HDR_SIZE);
			struct ether_header *ether_hdr = (struct ether_header *)packet;
			mospf_init_hdr(m_hdr, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, 0);
			mospf_init_hello(m_hello, iface->mask);
			m_hdr->checksum = mospf_checksum(m_hdr);
			ip_init_hdr(ip_hdr, iface->ip, MOSPF_ALLSPFRouters, IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, IPPROTO_MOSPF);
			ip_hdr->checksum = ip_checksum(ip_hdr);
			
			ether_hdr->ether_type = htons(ETH_P_IP);
			memcpy(&ether_hdr->ether_shost, &iface->mac, ETH_ALEN);
			memcpy(&ether_hdr->ether_dhost, &mospf_hello_mac, ETH_ALEN);
			iface_send_packet(iface, packet, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);
			log(DEBUG, "send mospf hello packet, from %x to %x", iface->ip, MOSPF_ALLSPFRouters);
		}
		sleep(MOSPF_DEFAULT_HELLOINT);
	}
	return NULL;
}

void *checking_nbr_thread(void *param)
{
	//fprintf(stdout, "TODO: neighbor list timeout operation.\n");
	while(1){
		int timeout = 0;
		iface_info_t *iface = NULL;
		pthread_mutex_lock(&mospf_nbr_lock);
		list_for_each_entry(iface, &instance->iface_list, list) {
			if (iface->num_nbr){
				mospf_nbr_t *m_nbr = NULL, *q;
				list_for_each_entry_safe(m_nbr, q, &iface->nbr_list, list) {
					if (m_nbr->alive > 3 * MOSPF_DEFAULT_HELLOINT) {
						timeout = 1;
						iface->num_nbr--;
						list_delete_entry(&(m_nbr->list));
						free(m_nbr);
						log(DEBUG, "Delete entry: mask- %x  id- %x  ip- %x",m_nbr->nbr_mask, m_nbr->nbr_id, m_nbr->nbr_ip);
					}
					else
						m_nbr->alive++;
				}
			}
		}
		if (timeout == 1)
			send_new_lsu();
		pthread_mutex_unlock(&mospf_nbr_lock);
		sleep(1);
	}
	return NULL;
}



void *checking_db_thread(void *param)
{
	//fprintf(stdout, "TODO: database timeout operation.\n");
	while(1) {
		pthread_mutex_lock(&mospf_db_lock);
		mospf_db_entry_t *m_entry = NULL, *q;

		list_for_each_entry_safe(m_entry, q, &mospf_db, list) {
			if (m_entry->alive > MOSPF_DEFAULT_HELLOINT + MOSPF_DEFAULT_LSUINT) {
				list_delete_entry(&(m_entry->list));
				free(m_entry);
			}
			else
				m_entry->alive++;
		}
		pthread_mutex_unlock(&mospf_db_lock);
		sleep(1);
	}
	return NULL;
}


void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	//fprintf(stdout, "TODO: handle mOSPF Hello message.\n");
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	struct mospf_hello *m_hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);
	log(DEBUG, "received new mospf hello, from %x to %x", ntohl(ip->saddr), iface->ip);
	mospf_nbr_t *m_nbr = NULL;
	int found = 0;
	pthread_mutex_lock(&mospf_nbr_lock);
	list_for_each_entry(m_nbr, &iface->nbr_list, list) {
		if (m_nbr->nbr_ip == ntohl(ip->saddr)){
			found = 1;
			m_nbr->alive = 0;
		}
	}
	if (found == 0)
	{
		mospf_nbr_t *new_nbr = (mospf_nbr_t *)malloc(sizeof(mospf_nbr_t));
		new_nbr->alive = 0;
		new_nbr->nbr_id = ntohl(mospf->rid);
		new_nbr->nbr_ip = ntohl(ip->saddr);
		new_nbr->nbr_mask = ntohl(m_hello->mask);
		iface->num_nbr++;
		list_add_head(&new_nbr->list, &iface->nbr_list);

		// send new LSU
		send_new_lsu();
	}
	pthread_mutex_unlock(&mospf_nbr_lock);
}

void *sending_mospf_lsu_thread(void *param)
{
	//fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");
	while(1){
		pthread_mutex_lock(&mospf_nbr_lock);
		send_new_lsu();
		pthread_mutex_unlock(&mospf_nbr_lock);
		sleep(MOSPF_DEFAULT_LSUINT);
	}
	return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	//fprintf(stdout, "TODO: handle mOSPF LSU message.\n");
	
	struct mospf_lsa *m_lsa = (struct mospf_lsa *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE);
	struct mospf_lsu *m_lsu = (struct mospf_lsu *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);
	struct mospf_hdr *m_hdr = (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	struct iphdr *ip_hdr = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	mospf_db_entry_t *m_entry = NULL;
	mospf_db_entry_t *m_found = NULL;
	log(DEBUG, "[%s:%s] received mospf lsu, from router [%x]", iface->name, iface->ip_str, ntohl(m_hdr->rid));
	if (ntohl(m_hdr->rid) == instance->router_id) {
		log(DEBUG, "Receive the lsu message from itself router.");
		return ;
	}
	pthread_mutex_lock(&mospf_db_lock);
	int found = 0;
	list_for_each_entry(m_entry, &mospf_db, list) {
		if (m_entry->rid == ntohl(m_hdr->rid)){
			found = 1;
			if (m_entry->seq < ntohs(m_lsu->seq))
				m_found = m_entry;
		}
	}
	if (found == 0 || m_found != NULL)
	{
		if (m_found)
		{
			list_delete_entry(&(m_found->list));
			free(m_found);
		}
		m_entry = (mospf_db_entry_t *) malloc(sizeof(mospf_db_entry_t));
		m_entry->alive = 0;
		m_entry->nadv = ntohl(m_lsu->nadv);
		m_entry->rid = ntohl(m_hdr->rid);
		m_entry->seq = ntohs(m_lsu->seq);
		m_entry->array = (struct mospf_lsa *)malloc(m_entry->nadv * sizeof(struct mospf_lsa));
		struct mospf_lsa *lsa_entry = m_entry->array;
		log(DEBUG, "received new mospf lsu paceet, with %d lsa from "IP_FMT, m_entry->nadv, HOST_IP_FMT_STR(m_entry->rid));
		for (int i = 0; i < m_entry->nadv; i++)
		{
			lsa_entry->mask = ntohl(m_lsa->mask);
			lsa_entry->rid = ntohl(m_lsa->rid);
			lsa_entry->subnet = ntohl(m_lsa->subnet);
			lsa_entry++;
			m_lsa++;
		}
		
		list_add_head(&m_entry->list, &mospf_db);

		update_rtable();
		pthread_mutex_unlock(&mospf_db_lock);
		dump_mospf_db();

		//forward the packet
		if(instance->router_id == ntohl(m_hdr->rid))
			return;

		if (ip_hdr->ttl == 1)
			return ;
		else 
			ip_hdr->ttl--;
		iface_info_t *iface_t = NULL;
		list_for_each_entry(iface_t, &instance->iface_list, list)
		{
			if (iface_t != iface)
			{
				mospf_nbr_t *m_nbr = NULL;
				list_for_each_entry(m_nbr, &iface_t->nbr_list, list)
				{
					//if (m_nbr->nbr_ip == 0) continue;
					char *packet_new = (char *)malloc(len);
					memcpy(packet_new, packet, len);
					struct iphdr *ip_hdr_new = (struct iphdr *)(packet_new + ETHER_HDR_SIZE);
					struct ether_header *ether_hdr_new = (struct ether_header *)packet_new;
					ip_init_hdr(ip_hdr_new, iface_t->ip, m_nbr->nbr_ip, len, IPPROTO_MOSPF);
					ip_hdr_new->checksum = ip_checksum(ip_hdr_new);
					ether_hdr_new->ether_type = htons(ETH_P_IP);
					iface_send_packet_by_arp(iface_t, m_nbr->nbr_ip, packet_new, len);
					log(DEBUG, "forward mospf lsu packet, send from %x to %x", iface->ip, m_nbr->nbr_ip);
				}
			}
		}

	}
	else {
		log(DEBUG, "has receive this mospf lsu message before, ignore it");
		pthread_mutex_unlock(&mospf_db_lock);
	}
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	// log(DEBUG, "received mospf packet, type: %d", mospf->type);

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}

void send_new_lsu(){
	u32 total_entry = 0;
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface->num_nbr)
			total_entry += iface->num_nbr;
		else 
			total_entry++;
	}
	char *packet = (char *)malloc(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + total_entry * MOSPF_LSA_SIZE);
	memset(packet, 0, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + total_entry * MOSPF_LSA_SIZE);
	struct mospf_lsa *m_lsa = (struct mospf_lsa *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE);
	struct mospf_lsu *m_lsu = (struct mospf_lsu *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);
	struct mospf_hdr *m_hdr = (struct mospf_hdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);

	mospf_init_hdr(m_hdr, MOSPF_TYPE_LSU, MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + total_entry * MOSPF_LSA_SIZE, instance->router_id, 0);
	
	m_lsu->nadv = htonl(total_entry);
	m_lsu->seq = htons(instance->sequence_num++);
	m_lsu->ttl = MOSPF_MAX_LSU_TTL;

	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface->num_nbr)
		{
			mospf_nbr_t *m_nbr = NULL;
			list_for_each_entry(m_nbr, &iface->nbr_list, list)
			{
				m_lsa->mask = htonl(m_nbr->nbr_mask);
				m_lsa->rid = htonl(m_nbr->nbr_id);
				m_lsa->subnet = htonl(m_nbr->nbr_ip & m_nbr->nbr_mask);
				m_lsa++;
			}
		}
		else{
			m_lsa->mask = htonl(iface->mask);
			m_lsa->rid = 0;
			m_lsa->subnet = htonl(iface->ip & iface->mask);
			m_lsa++;
		}
	}
	m_hdr->checksum = mospf_checksum(m_hdr);
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface->num_nbr) {
			mospf_nbr_t *m_nbr = NULL;
			list_for_each_entry(m_nbr, &iface->nbr_list, list) {
				char *packet_new = (char *)malloc(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + total_entry * MOSPF_LSA_SIZE);
				memcpy(packet_new, packet, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + total_entry * MOSPF_LSA_SIZE);
				struct iphdr *ip_hdr_new = (struct iphdr *)(packet_new + ETHER_HDR_SIZE);
				struct ether_header *ether_hdr_new = (struct ether_header *)packet_new;
				ip_init_hdr(ip_hdr_new, iface->ip, m_nbr->nbr_ip, IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + total_entry * MOSPF_LSA_SIZE, IPPROTO_MOSPF);
				ip_hdr_new->checksum = ip_checksum(ip_hdr_new);
				ether_hdr_new->ether_type = htons(ETH_P_IP);
				/*DEBUG*/
				struct mospf_lsa *m_lsa_new = (struct mospf_lsa *)(packet_new + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE);
				for (int i = 0; i < total_entry; i++)
				{
					log(DEBUG, "mask:%x  rid:%x subnet:%x", ntohl(m_lsa_new->mask), ntohl(m_lsa_new->rid), ntohl(m_lsa_new->subnet));
					m_lsa_new++;
				}
				iface_send_packet_by_arp(iface, m_nbr->nbr_ip, packet_new, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + total_entry * MOSPF_LSA_SIZE);
				log(DEBUG, "send mospf lsu packet, from %x to %x", iface->ip, m_nbr->nbr_ip);
				
			}
		}
	}
}

void dump_mospf_db(){
	printf("MOSPF Database entries:\nRID\t\tSubnet\t\tMask\t\tNeighbor\n");
	mospf_db_entry_t *m_entry = NULL;
	pthread_mutex_lock(&mospf_db_lock);
	list_for_each_entry(m_entry, &mospf_db, list) {
		struct mospf_lsa *lsa_entry = m_entry->array;
		for (int i = 0; i < m_entry->nadv; i++) {
			printf(IP_FMT"\t"IP_FMT"\t"IP_FMT"\t"IP_FMT"\n", HOST_IP_FMT_STR(m_entry->rid), HOST_IP_FMT_STR(lsa_entry->subnet), HOST_IP_FMT_STR(lsa_entry->mask), HOST_IP_FMT_STR(lsa_entry->rid));
			lsa_entry++;
		}
	}
	pthread_mutex_unlock(&mospf_db_lock);
	print_rtable();
}


typedef struct {
	u32 cost;
	u32 subnet_id; 
} graph_edge;

typedef struct {
	u32 subnet;
	u32 mask;
	int  router_id1;
	int  router_id2;
	int visited;
	int node_in;
	int nbr_zero;
	int valid;
} subnet_edge;

typedef struct {
	u32 rid;
	u32 ip;
	iface_info_t *iface;
} rid_iface_map;
rid_iface_map rid_iface_dict[MAX_SUBNET];

int num_router;
int num_subnet;
u32 router_arr[MAX_ROUTER];
subnet_edge subnet_arr[MAX_SUBNET];
graph_edge g[MAX_ROUTER][MAX_ROUTER];


int dist[MAX_ROUTER];
int visited[MAX_ROUTER];
int prev[MAX_ROUTER];



int find_router_id(u32 rid){
	for (int i = 0; i < num_router; i++)
		if (router_arr[i] == rid){
			return i;
		}
	return -1;
}

int find_subnet_id(u32 subnet) {
	for (int i = 0; i < num_subnet; i++)
		if (subnet_arr[i].subnet == subnet) {
			return i;
		}
	return -1;
}


int min_dist(int *dist, int *visited, int num_router){
	int rid = -1;
	int min_dist = INT_MAX;
	for (int i = 0; i < num_router; i++)
		if (visited[i] == 0 && dist[i] < min_dist){
			min_dist = dist[i];
			rid = i;
		}
	return rid;
}

void update_rtable()
{
	log(DEBUG, "Begin update rtable.");
	pthread_mutex_lock(&rtable_lock);
	clear_rtable();
	load_rtable_from_kernel();

	// travel all router and subset
	num_router = 0;
	memset(router_arr, 0, sizeof(router_arr));
	router_arr[num_router++] = instance->router_id;
	mospf_db_entry_t *m_entry = NULL;
	list_for_each_entry(m_entry, &mospf_db, list) {
		router_arr[num_router++] = m_entry->rid;
	}

	for (int i = 0; i < num_router; i++)
		log(DEBUG, "Found router %d -- %x", i,router_arr[i]);

	num_subnet = 0;
	memset(subnet_arr, 0, sizeof(subnet_arr));
	rt_entry_t *entry = NULL;
	list_for_each_entry(entry, &rtable, list) {
		subnet_arr[num_subnet].subnet = entry->dest;
		subnet_arr[num_subnet].mask = entry->mask;
		subnet_arr[num_subnet].router_id1 = 0;
		subnet_arr[num_subnet].router_id2 = -1;
		subnet_arr[num_subnet].nbr_zero = 1;
		subnet_arr[num_subnet].valid = 1;
		subnet_arr[num_subnet].node_in = 1;
		num_subnet++;
	}


	list_for_each_entry(m_entry, &mospf_db, list) {
		struct mospf_lsa *lsa_entry = m_entry->array;
		int t;
		for (int i = 0; i < m_entry->nadv; i++) {
			t = find_subnet_id(lsa_entry->subnet);
			if (t < 0){
				subnet_arr[num_subnet].subnet = lsa_entry->subnet;
				subnet_arr[num_subnet].mask = lsa_entry->mask;
				subnet_arr[num_subnet].router_id1 = find_router_id(m_entry->rid);
				subnet_arr[num_subnet].router_id2 = -1;
				if (lsa_entry->rid == 0) {
					subnet_arr[num_subnet].nbr_zero = 1;
					subnet_arr[num_subnet].valid = 1;
				}
				subnet_arr[num_subnet].node_in = 1;
				num_subnet++;
			}
			else{
				subnet_arr[t].router_id2 = find_router_id(m_entry->rid);
				if (lsa_entry->rid == 0)
					subnet_arr[t].nbr_zero++;
				if (subnet_arr[t].nbr_zero == 2) 
					subnet_arr[t].valid = 0;
				else
					subnet_arr[t].valid = 1;
				subnet_arr[t].node_in = 2;
			}
			lsa_entry++;
		}
	}

	for (int i = 0; i < num_subnet; i++)
		log(DEBUG,"subnet: %x mask: %x router_id1: %d router_id2: %d node_in: %d nbr_zero: %d valid : %d",subnet_arr[i].subnet,
			subnet_arr[i].mask,
			subnet_arr[i].router_id1,
			subnet_arr[i].router_id2,
			subnet_arr[i].node_in,
			subnet_arr[i].nbr_zero,
			subnet_arr[i].valid);

	// construct the graph
	memset(g, 0, sizeof(g));
	for (int i = 0; i < num_router; i++)
		for (int j = 0; j < num_router; j++){
			if (i != j)
				for (int k = 0; k < num_subnet; k++)
					if ((subnet_arr[k].router_id1 == i || subnet_arr[k].router_id1 == j) && subnet_arr[k].valid == 1 &&
						(subnet_arr[k].router_id2 == i || subnet_arr[k].router_id2 == j) && subnet_arr[k].node_in == 2){
							g[i][j].subnet_id = k;
							g[i][j].cost = 1;
							log(DEBUG,"g[%d][%d] subset_id : %d subnet : %x",i,j,k,subnet_arr[k].subnet);
					}
		}

	// calculate the Dijkstra path
	for(int i = 0 ; i < num_router ; i++){
		dist[i] = INT_MAX;
		visited[i] = 0;
		prev[i] = -1;
	}
    
	dist[0] = 0;

	for (int i = 0; i < num_router - 1; i++){
		int u = min_dist(dist, visited, num_router);
		if (u < 0) {
			log(DEBUG, "There is a router isolated.");
			break;
		}
		visited[u] = 1;
		for (int j = 0; j < num_router; j++){
			if (visited[j] == 0 && g[u][j].cost > 0 &&  dist[u] + g[u][j].cost < dist[j]) {
				dist[j] = dist[u] + g[u][j].cost;
				prev[j] = u;
			}
		}
	}

	for (int i = 0; i < num_router; i++)
		log(DEBUG,"%d dist : %d  prev : %d", i, dist[i], prev[i]);

	// sorted the dist
	int index[MAX_ROUTER];
	int	valid_router = 0;
	int t;
	for (int i = 0; i < num_router; i++)
		index[i] = i;
	for (int i = 0; i < num_router - 1; i++)
		for (int j = i + 1; j < num_router; j++){
			if (dist[i] > dist[j]){
				t = index[i];
				index[i] = index[j];
				index[j] = t;
				t = dist[i];
				dist[i] = dist[j];
				dist[j] = t;
			}
		}
	for (int i = 0; i < num_router; i++)
		if (dist[index[i]] != INT_MAX)
			valid_router++;
		else
			break;

	log(DEBUG, "Valid router: %d",valid_router);
	for (int i = 0; i < num_router; i++)
		log(DEBUG, "Index %d : %d",i,index[i]);

	// update the rtable
	int basic_rt_entry = 0;
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface->num_nbr)
		{
			mospf_nbr_t *m_nbr = NULL;
			list_for_each_entry(m_nbr, &iface->nbr_list, list)
			{
				rid_iface_dict[basic_rt_entry].rid = m_nbr->nbr_id;
				rid_iface_dict[basic_rt_entry].ip = m_nbr->nbr_ip;
				rid_iface_dict[basic_rt_entry].iface = iface;
				basic_rt_entry++;
			}
		}
	}
	
	for (int i = 0; i < basic_rt_entry; i++)
		log(DEBUG,"%d rid %x iface : %s",i,rid_iface_dict[i].rid, (rid_iface_dict[i].iface)->name);

	for(int i = 0 ; i < valid_router ; i++){
		int rid = index[i];
		for (int j = 0; j < num_subnet; j++){
			if ((subnet_arr[j].router_id1 == rid || subnet_arr[j].router_id2 == rid) && subnet_arr[j].visited == 0 && subnet_arr[j].valid == 1){
				subnet_arr[j].visited = 1;
				if (rid == 0) {
					continue;
				}
				int pre = rid;
				u32 gw;
				while (prev[pre] != 0)
					pre = prev[pre];

				for (int k = 0; k < basic_rt_entry; k++)
					if (router_arr[pre] == rid_iface_dict[k].rid) {
						iface = rid_iface_dict[k].iface;
						gw = rid_iface_dict[k].ip;
					}
				rt_entry_t * new_entry = new_rt_entry(subnet_arr[j].subnet, subnet_arr[j].mask, gw, iface);
				add_rt_entry(new_entry);
			}
		}
	}
	pthread_mutex_unlock(&rtable_lock);
}