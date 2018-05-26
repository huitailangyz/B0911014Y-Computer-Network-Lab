#include "packet.h"
#include "types.h"
#include "ether.h"
#include "rtable.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <pthread.h>

extern ustack_t *instance;

// this function will emit the packet to the link practically
void _iface_send_packet(iface_info_t *iface, char *packet, int len)
{
	struct sockaddr_ll addr;
	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = iface->index;
	addr.sll_halen = ETH_ALEN;
	addr.sll_protocol = htons(ETH_P_ARP);
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(addr.sll_addr, eh->ether_dhost, ETH_ALEN);


	// check if the iface is valid
	pthread_mutex_lock(&rtable_lock);
	rt_entry_t *entry = NULL;
	int found = 0;
	list_for_each_entry(entry, &rtable, list) {
		if (entry->iface == iface){
			found = 1;
			break;
		}
	}
	pthread_mutex_unlock(&rtable_lock);
	if (!found){
		log(ERROR, "The iface %s is invalid.", iface->name);
		return ;
	}	

	if (sendto(iface->fd, packet, len, 0, (const struct sockaddr *)&addr,
				sizeof(struct sockaddr_ll)) < 0) {
 		perror("Send raw packet failed");
	}
}

// send the packet out and free the memory of the packet
void iface_send_packet(iface_info_t *iface, char *packet, int len)
{
	_iface_send_packet(iface, packet, len);
	free(packet);
}

// broadcast the packet among all the interfaces except the one receiving the
// packet, and free the memory of the packet
void broadcast_packet(iface_info_t *in_iface, char *packet, int len)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface->index == in_iface->index)
			continue;

		_iface_send_packet(iface, packet, len);
	}

	free(packet);
}
