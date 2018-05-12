#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"
#include "arp.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	//fprintf(stdout, "TODO: determine the direction of this packet.\n");
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 s_ip = ntohl(ip->saddr);
	u32 d_ip = ntohl(ip->daddr);

	rt_entry_t *s_entry = longest_prefix_match(s_ip);
	rt_entry_t *d_entry = longest_prefix_match(d_ip);
	if (s_entry->iface == nat.internal_iface && d_entry->iface == nat.external_iface)
		return DIR_OUT;
	if (s_entry->iface == nat.external_iface && d_ip == nat.external_iface->ip)
		return DIR_IN;
	return DIR_INVALID;
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	//fprintf(stdout, "TODO: do translation for this packet.\n");
	DEBUG_PRINT printf("Begin do translation. The dire is : %d.\n", dir);
	struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
	u32 s_ip = ntohl(ip_hdr->saddr);
	u32 d_ip = ntohl(ip_hdr->daddr);
	struct tcphdr *tcp_hdr = packet_to_tcp_hdr(packet);
	u16 s_port = ntohs(tcp_hdr->sport);
	u16 d_port = ntohs(tcp_hdr->dport);
	char *hash_str = (char *)malloc(6);
	
	int found = 0;
	if (dir == DIR_IN)
	{
		memcpy(hash_str, &s_ip, 4);
		memcpy(hash_str + 4, &s_port, 2);
		u8 hash_index = hash8(hash_str, 6);
		struct list_head *entry_list = &nat.nat_mapping_list[hash_index];
		struct nat_mapping *mapping_entry, *q;
		pthread_mutex_lock(&nat.lock);
		list_for_each_entry_safe(mapping_entry, q, entry_list, list){
			if (mapping_entry->external_ip == d_ip && mapping_entry->external_port == d_port){
				//update the ip, port, checksum
				found = 1;
				tcp_hdr->dport = htons(mapping_entry->internal_port);
				ip_hdr->daddr = htonl(mapping_entry->internal_ip);
				tcp_hdr->checksum = tcp_checksum(ip_hdr, tcp_hdr);
				ip_hdr->checksum = ip_checksum(ip_hdr);

				//update the mapping_entry flag
				mapping_entry->update_time = time(NULL);
				mapping_entry->conn.external_ack = tcp_hdr->ack;
				mapping_entry->conn.external_seq_end = tcp_hdr->seq;
				if (tcp_hdr->flags & TCP_FIN)
					mapping_entry->conn.external_fin = 1;
				if (mapping_entry->conn.internal_fin == 1 && tcp_hdr->flags & TCP_ACK)
					mapping_entry->conn.internal_fin = 2;
				if (tcp_hdr->flags & TCP_RST){
					nat.assigned_ports[mapping_entry->external_port] = 0;
					list_delete_entry(&mapping_entry->list);
					free(mapping_entry);
				}
			}
		}
		if (found == 0){
			DEBUG_PRINT printf("[ERROR]: DIR_IN and NOT FOUND.\n");
		}
		pthread_mutex_unlock(&nat.lock);
	}
	else{
		memcpy(hash_str, &d_ip, 4);
		memcpy(hash_str + 4, &d_port, 2);
		u8 hash_index = hash8(hash_str, 6);
		struct list_head *entry_list = &nat.nat_mapping_list[hash_index];
		struct nat_mapping *mapping_entry, *q, *found_mapping_entry;
		pthread_mutex_lock(&nat.lock);
		list_for_each_entry_safe(mapping_entry, q, entry_list, list) {
			if (mapping_entry->internal_ip == s_ip && mapping_entry->internal_port == s_port) {
				found = 1;
				found_mapping_entry = mapping_entry;
			}
		}
		if (found == 0) {
			u16 new_port = 0;
			for (u16 i = NAT_PORT_MIN; i < NAT_PORT_MAX; i++)
				if (nat.assigned_ports[i] == 0){
					new_port = i;
					nat.assigned_ports[i] = 1;
					break;
				}
			DEBUG_PRINT printf("Allocate a new port %d.\n",new_port);
			if (new_port == 0)
				printf("ERROR: No remaining port to be allocated.\n");
			found_mapping_entry = (struct nat_mapping *) malloc(sizeof(struct nat_mapping));
			memset(found_mapping_entry, 0, sizeof(struct nat_mapping));
			found_mapping_entry->external_ip = nat.external_iface->ip;
			found_mapping_entry->external_port = new_port;
			found_mapping_entry->internal_ip = s_ip;
			found_mapping_entry->internal_port = s_port;
			list_add_tail(&found_mapping_entry->list, &nat.nat_mapping_list[hash_index]);
		}
		//update the ip, port, checksum
		tcp_hdr->sport = htons(found_mapping_entry->external_port);
		ip_hdr->saddr = htonl(found_mapping_entry->external_ip);
		tcp_hdr->checksum = tcp_checksum(ip_hdr, tcp_hdr);
		ip_hdr->checksum = ip_checksum(ip_hdr);

		//update the mapping_entry flag
		found_mapping_entry->update_time = time(NULL);
		found_mapping_entry->conn.internal_ack = tcp_hdr->ack;
		found_mapping_entry->conn.internal_seq_end = tcp_hdr->seq;
		if (tcp_hdr->flags & TCP_FIN)
			found_mapping_entry->conn.internal_fin = 1;
		if (found_mapping_entry->conn.external_fin == 1 && tcp_hdr->flags & TCP_ACK)
			found_mapping_entry->conn.external_fin = 2;
		if (tcp_hdr->flags & TCP_RST) {
			nat.assigned_ports[found_mapping_entry->external_port] = 0;
			list_delete_entry(&found_mapping_entry->list);
			free(found_mapping_entry);
		}
		pthread_mutex_unlock(&nat.lock);
	}


	u32 ip_dst = ntohl(ip_hdr->daddr);
	//find the iface
	rt_entry_t *entry = longest_prefix_match(ip_dst);
	if (!entry) {
		//log(ERROR, "Could not find forwarding rule for IP (dst:"IP_FMT") packet.", 
		//		HOST_IP_FMT_STR(ip_dst));
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		return ;
	}


	//determine the next hop to forward the packet
	u32 next_hop = entry->gw;
	if (!next_hop)
		next_hop = ip_dst;
	DEBUG_PRINT printf("Next hop ip: "IP_FMT"\n", HOST_IP_FMT_STR(next_hop));
	//send the packet
	iface_send_packet_by_arp(entry->iface, next_hop, packet, len);	
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	while (1) {
		//fprintf(stdout, "TODO: sweep finished flows periodically.\n");
		DEBUG_PRINT printf("Begin sweep.\n");
		sleep(1);
		time_t now_time = time(NULL);
		pthread_mutex_lock(&nat.lock);
		for (int i = 0; i < HASH_8BITS; i++) {
			struct list_head *head = &nat.nat_mapping_list[i];
			struct nat_mapping *mapping_entry, *q;
			list_for_each_entry_safe(mapping_entry, q, head, list) {
				DEBUG_PRINT printf("Now time : %d  Update time: %d.\n",now_time, mapping_entry->update_time);
				if (now_time - mapping_entry->update_time > TCP_ESTABLISHED_TIMEOUT
					|| (mapping_entry->conn.internal_fin == 2 && mapping_entry->conn.external_fin == 2)) {
					DEBUG_PRINT printf("Delete a entry.\n");
					nat.assigned_ports[mapping_entry->external_port] = 0;
					list_delete_entry(&mapping_entry->list);
					free(mapping_entry);
				}
			}
		}
		pthread_mutex_unlock(&nat.lock);
	}

	return NULL;
}

// initialize nat table
void nat_table_init()
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	nat.internal_iface = if_name_to_iface("n1-eth0");
	nat.external_iface = if_name_to_iface("n1-eth1");
	if (!nat.internal_iface || !nat.external_iface) {
		log(ERROR, "Could not find the desired interfaces for nat.");
		exit(1);
	}

	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

// destroy nat table
void nat_table_destroy()
{
	pthread_mutex_lock(&nat.lock);

	for (int i = 0; i < HASH_8BITS; i++) {
		struct list_head *head = &nat.nat_mapping_list[i];
		struct nat_mapping *mapping_entry, *q;
		list_for_each_entry_safe(mapping_entry, q, head, list) {
			list_delete_entry(&mapping_entry->list);
			free(mapping_entry);
		}
	}

	pthread_kill(nat.thread, SIGTERM);

	pthread_mutex_unlock(&nat.lock);
}
