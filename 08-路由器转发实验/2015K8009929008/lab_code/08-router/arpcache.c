#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "packet.h"
#include "icmp.h"
#include "base.h"
#include "ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the hash table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	//fprintf(stderr, "TODO: lookup ip address in arp cache.\n");
	DEBUG_PRINT printf("\nBegin arpcache lookup.\n");
	DEBUG_PRINT arpcache_dump();
	pthread_mutex_lock(&arpcache.lock);
	for (int i = 0; i<MAX_ARP_SIZE; i++)
		if (arpcache.entries[i].valid && arpcache.entries[i].ip4 == ip4){
			memcpy(mac, &(arpcache.entries[i].mac), ETH_ALEN);
			arpcache.entries[i].added = time(NULL);
			pthread_mutex_unlock(&arpcache.lock);
			return 1;
		}
	pthread_mutex_unlock(&arpcache.lock);
	return 0;
}

// append the packet to arpcache
//
// Lookup in the hash table which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	//fprintf(stderr, "TODO: append the ip address if lookup failed, and send arp request if necessary.\n");
	DEBUG_PRINT printf("\nBegin arpcache append packet.\n");
	DEBUG_PRINT printf("The dest of packet is: "IP_FMT"\n", HOST_IP_FMT_STR(ip4));
	//char *new_packet = (char *)malloc(len);
	//memcpy(new_packet, packet, len);
	char *new_packet = packet;
	pthread_mutex_lock(&arpcache.lock);
	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		if (req_entry->ip4 == ip4){
			DEBUG_PRINT printf("Now there are packets to this IP.\n");
			struct cached_pkt *pkt_entry = (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
			pkt_entry->packet = new_packet;
			pkt_entry->len = len;
			list_add_tail(&(pkt_entry->list), &(req_entry->cached_packets));
			pthread_mutex_unlock(&arpcache.lock);
			return ;
		}
	}
	DEBUG_PRINT printf("Now there is no packet to this IP.\n");
	//malloc a new entry
	req_entry = (struct arp_req *)malloc(sizeof(struct arp_req));
	req_entry->iface = iface;
	req_entry->ip4 = ip4;
	req_entry->retries = 0;
	init_list_head(&(req_entry->cached_packets));
	list_add_tail(&(req_entry->list), &(arpcache.req_list));
	struct cached_pkt *pkt_entry = (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
	pkt_entry->packet = new_packet;
	pkt_entry->len = len;
	list_add_tail(&(pkt_entry->list), &(req_entry->cached_packets));
	
	req_entry->retries += 1;
	req_entry->sent = time(NULL);
	pthread_mutex_unlock(&arpcache.lock);
	arp_send_request(iface, ip4);
	
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	//fprintf(stderr, "TODO: insert ip->mac entry, and send all the pending packets.\n");
	DEBUG_PRINT printf("\nBegin arpcache_insert.\n");
	pthread_mutex_lock(&arpcache.lock);
	
	//insert the IP->mac mapping into arpcache
	int added = -1;
	for (int i = 0; i<MAX_ARP_SIZE; i++)
		if (!arpcache.entries[i].valid){
			added = i;
			break;
		}
	if (added == -1)
		added = time(NULL) % MAX_ARP_SIZE;
	DEBUG_PRINT printf("Add place is %d.\n", added);
	DEBUG_PRINT printf("Add entry IP: "IP_FMT, HOST_IP_FMT_STR(ip4));
	DEBUG_PRINT printf("\tMac addr: " ETHER_STRING"\n", ETHER_FMT(mac));
	arpcache.entries[added].valid = 1;
	arpcache.entries[added].added = time(NULL);
	arpcache.entries[added].ip4 = ip4;
	memcpy(&(arpcache.entries[added].mac), mac, ETH_ALEN);
	
	//send out the pending packets
	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		if (req_entry->ip4 == ip4){
			DEBUG_PRINT printf("Send out the pending packets.\n");
			struct cached_pkt *pkt_entry = NULL, *pkt_q;
			list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
				struct ether_header *eh = (struct ether_header *)pkt_entry->packet;
				memcpy(eh->ether_dhost, mac, ETH_ALEN);
				DEBUG_PRINT printf("The packet to send source Mac addr: " ETHER_STRING " \t dest Mac addr: "ETHER_STRING"\n", ETHER_FMT(eh->ether_shost), ETHER_FMT(eh->ether_dhost));
				struct iphdr *ip_hdr = packet_to_ip_hdr(pkt_entry->packet);
				DEBUG_PRINT printf("IP packet source ip: "IP_FMT"\tIP packet dest ip: "IP_FMT"\n", NET_IP_FMT_STR(ip_hdr->saddr), NET_IP_FMT_STR(ip_hdr->daddr));
				DEBUG_PRINT printf("The IP protocol: %d\tICMP flag is: %d\n", ip_hdr->protocol, IPPROTO_ICMP);
				pthread_mutex_unlock(&arpcache.lock);
				iface_send_packet(req_entry->iface, pkt_entry->packet, pkt_entry->len);
				pthread_mutex_lock(&arpcache.lock);
				list_delete_entry(&(pkt_entry->list));
				//free(pkt_entry->packet);
				free(pkt_entry);
			}
			list_delete_entry(&(req_entry->list));
			free(req_entry);
		}
	}
	
	pthread_mutex_unlock(&arpcache.lock);
	DEBUG_PRINT printf("After arpcache_insert.\n");
	DEBUG_PRINT arpcache_dump();
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{
	while (1) {
		sleep(1);
		//fprintf(stderr, "TODO: sweep arpcache periodically: remove old entries, resend arp requests .\n");
		pthread_mutex_lock(&arpcache.lock);
		DEBUG_PRINT printf("\nBegin arpcache sweep.\n");
		//check the IP->mac entry		
		time_t now = time(NULL);
		for (int i=0; i<MAX_ARP_SIZE; i++)
			if (arpcache.entries[i].valid && now - arpcache.entries[i].added > ARP_ENTRY_TIMEOUT)
				arpcache.entries[i].valid = 0;

		//check the pending packets
		struct arp_req *req_entry = NULL, *req_q;
		list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
			if (req_entry->retries == ARP_REQUEST_MAX_RETRIES){
				DEBUG_PRINT printf("Request for IP: "IP_FMT" have get limited times.\n", HOST_IP_FMT_STR(req_entry->ip4));
				struct cached_pkt *pkt_entry = NULL, *pkt_q;
				list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
					pthread_mutex_unlock(&arpcache.lock);
					icmp_send_packet(pkt_entry->packet, pkt_entry->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
					pthread_mutex_lock(&arpcache.lock);
					list_delete_entry(&(pkt_entry->list));
					//free(pkt_entry->packet);
					free(pkt_entry);
				}
				list_delete_entry(&(req_entry->list));
				free(req_entry);
			}
			else{
				DEBUG_PRINT printf("Request %d times for IP: "IP_FMT"\n", req_entry->retries, HOST_IP_FMT_STR(req_entry->ip4));
				pthread_mutex_unlock(&arpcache.lock);
				arp_send_request(req_entry->iface, req_entry->ip4);
				pthread_mutex_lock(&arpcache.lock);
				req_entry->retries += 1;			
			}
		}

		pthread_mutex_unlock(&arpcache.lock);
	}
	return NULL;
}

void arpcache_dump(){
	pthread_mutex_lock(&arpcache.lock);
	printf("Dump the arpcache.\n");
	for (int i=0; i < MAX_ARP_SIZE; i++)	
		if (arpcache.entries[i].valid) {
			printf("NO%d IP: "IP_FMT,i, HOST_IP_FMT_STR(arpcache.entries[i].ip4));
			printf("\tMac addr: " ETHER_STRING, ETHER_FMT(arpcache.entries[i].mac));
			printf("\tAdd time: %d valid: %d\n", arpcache.entries[i].added, arpcache.entries[i].valid);
		}
	pthread_mutex_unlock(&arpcache.lock);
}