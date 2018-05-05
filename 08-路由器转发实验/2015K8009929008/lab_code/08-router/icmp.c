#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

u32 local_mac_to_ip(const u8 mac[ETH_ALEN]){
	iface_info_t *iface = NULL;
	DEBUG_PRINT printf("Look for Mac addr: " ETHER_STRING"\n", ETHER_FMT(mac));
	list_for_each_entry(iface, &instance->iface_list, list) {
		DEBUG_PRINT printf("Iface name: %s, IP: "IP_FMT" Mac addr: "ETHER_STRING"\n", iface->name, HOST_IP_FMT_STR(iface->ip), ETHER_FMT(iface->mac));
		if (!memcmp(&iface->mac, mac, ETH_ALEN)){
			return iface->ip;
		}
	}
	return 0;
}


// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	//fprintf(stderr, "TODO: malloc and send icmp packet.\n");
	DEBUG_PRINT printf("\nBegin send icmp packet.\n");
	struct iphdr *ip_hdr_in = (struct iphdr *)packet_to_ip_hdr(in_pkt);
	
	u32 s_ip = local_mac_to_ip(((struct ether_header *)in_pkt)->ether_dhost);
	u32 d_ip = ntohl(ip_hdr_in->saddr);
	assert(s_ip != 0);
	DEBUG_PRINT printf("IP packet source ip: "IP_FMT"\tIP packet dest ip: "IP_FMT"\n", HOST_IP_FMT_STR(s_ip), HOST_IP_FMT_STR(d_ip));
	int ip_head_len = ip_hdr_in->ihl * 4;
	int packet_len, ip_len, icmp_len;
	char *packet;
	if (type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED){
		struct icmphdr *in_pkt_icmp = (struct icmphdr *)IP_DATA(ip_hdr_in);
		if (in_pkt_icmp->type == ICMP_DEST_UNREACH || in_pkt_icmp->type == ICMP_TIME_EXCEEDED)
			return ;
		//router lookup fail / arp lookup fail / ttl is zero	
		DEBUG_PRINT printf("Begin icmp error reply.\n");
		packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + ip_head_len + ICMP_COPIED_DATA_LEN;
		packet = (char *)malloc(packet_len);

		struct iphdr *ip_hdr_out = (struct iphdr *)packet_to_ip_hdr(packet);	
		u16 ip_len = IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + ip_head_len + ICMP_COPIED_DATA_LEN;
		ip_init_hdr(ip_hdr_out, s_ip, d_ip, ip_len, IPPROTO_ICMP);
		
		struct icmphdr *icmp_hdr_out = (struct icmphdr *)IP_DATA(ip_hdr_out);
		char *icmp_start = (char *)icmp_hdr_out;
		memset(icmp_start + 4, 0, 4);
		memcpy(icmp_start + ICMP_HDR_SIZE, ip_hdr_in, ip_head_len + ICMP_COPIED_DATA_LEN);		
		icmp_hdr_out->type = type;
		icmp_hdr_out->code = code;
		icmp_len = ICMP_HDR_SIZE + ip_head_len + ICMP_COPIED_DATA_LEN;
		DEBUG_PRINT printf("Packet_len: %d   IP_len: %d   ICMP_len: %d The source packet ip_hdr len: %d\n", packet_len, ip_len, icmp_len, ip_head_len);
		icmp_hdr_out->checksum  = icmp_checksum(icmp_hdr_out, icmp_len);
	}
	else{
		//ping this port
		DEBUG_PRINT printf("Begin icmp echoreply.\n");
		ip_len = ntohs(ip_hdr_in->tot_len);
		icmp_len = ip_len - ip_head_len;
		ip_len = icmp_len + IP_BASE_HDR_SIZE;
		packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_len;
		DEBUG_PRINT printf("Packet_len: %d   IP_len: %d   ICMP_len: %d\n",packet_len, ip_len, icmp_len);
		packet = (char *)malloc(packet_len);
		struct iphdr *ip_hdr_out = (struct iphdr *)packet_to_ip_hdr(packet);
		ip_init_hdr(ip_hdr_out, s_ip, d_ip, ip_len, IPPROTO_ICMP);
		
		struct icmphdr *icmp_hdr_out = (struct icmphdr *)IP_DATA(ip_hdr_out);
		struct icmphdr *icmp_hdr_in = (struct icmphdr *)IP_DATA(ip_hdr_in);
		memcpy(icmp_hdr_out, icmp_hdr_in, icmp_len);		
		icmp_hdr_out->type = type;
		icmp_hdr_out->code = code;
		icmp_hdr_out->checksum  = icmp_checksum(icmp_hdr_out, icmp_len);	
	}

	ip_send_packet(packet, packet_len);
}
