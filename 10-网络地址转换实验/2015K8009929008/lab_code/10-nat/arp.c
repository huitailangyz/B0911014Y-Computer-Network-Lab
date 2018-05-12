#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "arpcache.h"
#include "ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	//fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
	DEBUG_PRINT printf("\nBegin send arp request.\n");
	char *packet = (char *) malloc(sizeof(struct ether_arp) + ETHER_HDR_SIZE);

	struct ether_header *header_hdr = (struct ether_header *)packet;
	header_hdr->ether_type = htons(ETH_P_ARP);
	memset(&(header_hdr->ether_dhost), -1, ETH_ALEN);
	memcpy(&(header_hdr->ether_shost), &(iface->mac), ETH_ALEN);
	DEBUG_PRINT printf("Request packet header source Mac addr: " ETHER_STRING "\theader dest Mac addr: "ETHER_STRING"\n", ETHER_FMT(header_hdr->ether_shost), ETHER_FMT(header_hdr->ether_dhost));

	struct ether_arp *arp_hdr = (struct ether_arp *)packet_to_ip_hdr(packet);
	arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
	arp_hdr->arp_pro = htons(ETH_P_IP);
	arp_hdr->arp_hln = 6;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(ARPOP_REQUEST);
	memcpy(&(arp_hdr->arp_sha), &(iface->mac), ETH_ALEN);
	arp_hdr->arp_spa = htonl(iface->ip); 
	memset(&(arp_hdr->arp_tha), 0, ETH_ALEN);
	arp_hdr->arp_tpa = htonl(dst_ip);
	DEBUG_PRINT printf("Local iface Mac addr: "ETHER_STRING"\n", ETHER_FMT(iface->mac));
	DEBUG_PRINT printf("Request packet source ip: "IP_FMT"\tdest ip: "IP_FMT"\n", NET_IP_FMT_STR(arp_hdr->arp_spa), NET_IP_FMT_STR(arp_hdr->arp_tpa));
	DEBUG_PRINT printf("Request packet source Mac addr: " ETHER_STRING " \t dest Mac addr: "ETHER_STRING"\n", ETHER_FMT(arp_hdr->arp_sha), ETHER_FMT(arp_hdr->arp_tha));
	iface_send_packet(iface, packet, sizeof(struct ether_arp) + ETHER_HDR_SIZE);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	//fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");
	DEBUG_PRINT printf("\nBegin send arp reply.\n");
	DEBUG_PRINT printf("Send from iface name: %d\n", iface->name);
	char *packet = (char *) malloc(sizeof(struct ether_arp) + ETHER_HDR_SIZE);
	struct ether_header *header_hdr = (struct ether_header *)packet;
	memcpy(packet+ETHER_HDR_SIZE, req_hdr, sizeof(struct ether_arp));

	req_hdr = (struct ether_arp *)packet_to_ip_hdr(packet);
	header_hdr->ether_type = htons(ETH_P_ARP);
	memcpy(&(header_hdr->ether_dhost), &(req_hdr->arp_sha), ETH_ALEN);
	memcpy(&(header_hdr->ether_shost), &(iface->mac), ETH_ALEN);
	DEBUG_PRINT printf("Reply packet header source Mac addr: " ETHER_STRING "\theader dest Mac addr: "ETHER_STRING"\n", ETHER_FMT(header_hdr->ether_shost), ETHER_FMT(header_hdr->ether_dhost));
	
	req_hdr->arp_op = htons(ARPOP_REPLY);
	memcpy(&(req_hdr->arp_sha), &(iface->mac), ETH_ALEN);
	req_hdr->arp_tpa = req_hdr->arp_spa;
	req_hdr->arp_spa = htonl(iface->ip); 
	memcpy(&(req_hdr->arp_tha), &(header_hdr->ether_dhost), ETH_ALEN);
	DEBUG_PRINT printf("Local iface Mac addr: "ETHER_STRING"\n", ETHER_FMT(iface->mac));
	DEBUG_PRINT printf("Reply packet source ip: "IP_FMT"\tdest ip: "IP_FMT"\n", NET_IP_FMT_STR(req_hdr->arp_spa), NET_IP_FMT_STR(req_hdr->arp_tpa));
	DEBUG_PRINT printf("Reply packet source Mac addr: " ETHER_STRING " \t dest Mac addr: "ETHER_STRING"\n", ETHER_FMT(req_hdr->arp_sha), ETHER_FMT(req_hdr->arp_tha));
	iface_send_packet(iface, packet, sizeof(struct ether_arp) + ETHER_HDR_SIZE);
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	//fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
	DEBUG_PRINT printf("\nBegin handle arp packet.\n");
	struct ether_arp *arp_hdr = (struct ether_arp *)packet_to_ip_hdr(packet);
	DEBUG_PRINT printf("ARP packet source ip: "IP_FMT"\n", NET_IP_FMT_STR(arp_hdr->arp_spa));
	DEBUG_PRINT printf("ARP packet source Mac addr: " ETHER_STRING " \t dest Mac addr: "ETHER_STRING"\n", ETHER_FMT(arp_hdr->arp_sha), ETHER_FMT(arp_hdr->arp_tha));
	DEBUG_PRINT printf("Local iface ip: "IP_FMT"\tARP packet dest ip: "IP_FMT"\n", HOST_IP_FMT_STR(iface->ip), NET_IP_FMT_STR(arp_hdr->arp_tpa));

	if (ntohl(arp_hdr->arp_tpa) == iface->ip && ntohs(arp_hdr->arp_op) == ARPOP_REQUEST)
		arp_send_reply(iface, arp_hdr);

	DEBUG_PRINT printf("Continue in handle arp packet.\n");
	u8 mac[ETH_ALEN];
	int found = arpcache_lookup(ntohl(arp_hdr->arp_spa), mac);
	if (!found){
		memcpy(mac, &(arp_hdr->arp_sha),ETH_ALEN);
		arpcache_insert(ntohl(arp_hdr->arp_spa), mac);		
	}	
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	DEBUG_PRINT printf("\nBegin iface send packet by arp.\n");
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		DEBUG_PRINT printf("Found the mac of ip: "IP_FMT", send this packet.\n", HOST_IP_FMT_STR(dst_ip));
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		DEBUG_PRINT printf("The packet to send source Mac addr: " ETHER_STRING " \t dest Mac addr: "ETHER_STRING"\n", ETHER_FMT(eh->ether_shost), ETHER_FMT(eh->ether_dhost));
		struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
		DEBUG_PRINT printf("IP packet source ip: "IP_FMT"\tIP packet dest ip: "IP_FMT"\n", NET_IP_FMT_STR(ip_hdr->saddr), NET_IP_FMT_STR(ip_hdr->daddr));
		DEBUG_PRINT printf("The IP protocol: %d\tICMP flag is: %d\n", ip_hdr->protocol, IPPROTO_ICMP);
		iface_send_packet(iface, packet, len);
	}
	else {
		DEBUG_PRINT printf("Not found the mac of ip: "IP_FMT", pending the packet.\n", HOST_IP_FMT_STR(dst_ip));
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
