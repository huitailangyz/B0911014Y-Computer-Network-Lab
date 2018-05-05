#include "mac.h"
#include "headers.h"
#include "log.h"

mac_port_map_t mac_port_map;

void init_mac_hash_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	pthread_mutexattr_init(&mac_port_map.attr);
	pthread_mutexattr_settype(&mac_port_map.attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mac_port_map.lock, &mac_port_map.attr);

	pthread_create(&mac_port_map.tid, NULL, sweeping_mac_port_thread, NULL);
}

void destory_mac_hash_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *tmp, *entry;
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		if (!entry) 
			continue;

		tmp = entry->next;
		while (tmp) {
			entry->next = tmp->next;
			free(tmp);
			tmp = entry->next;
		}
		free(entry);
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
	// TODO: implement the lookup process here
	//fprintf(stdout, "TODO: implement the lookup process here.\n");
	
	u8 hash_addr = hash8(mac, ETH_ALEN);
	mac_port_entry_t *entry = mac_port_map.hash_table[hash_addr];
	iface_info_t *iface = NULL;
	log(DEBUG, "Lookup Mac addr: " ETHER_STRING, ETHER_FMT(mac));
	pthread_mutex_lock(&mac_port_map.lock);
	while (entry){
		int flag = 1;
		for (int i = 0; i<ETH_ALEN; i++)
			if (mac[i] != entry->mac[i]){
				flag = 0;
				break;			
			}
		if (flag){
			iface = entry->iface;
			entry->visited = time(NULL);
			break;			
		}
		else
			entry = entry->next;	
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	if (iface)
		log(DEBUG, "Find %s.", iface->name)
	else
		log(DEBUG, "Not found.");
	return iface;
}

void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	// TODO: implement the insertion process here
	//fprintf(stdout, "TODO: implement the insertion process here.\n");
	
	u8 hash_addr = hash8(mac, ETH_ALEN);
	mac_port_entry_t *entry = (mac_port_entry_t *)malloc(sizeof(mac_port_entry_t)),*tmp;
	pthread_mutex_lock(&mac_port_map.lock);
	tmp = mac_port_map.hash_table[hash_addr];
	if (tmp)	
		entry->next = tmp->next;
	else
		entry->next = NULL;
	memcpy(&entry->mac, mac, ETH_ALEN);
	entry->iface = iface;
	entry->visited = time(NULL);
	mac_port_map.hash_table[hash_addr] = entry;
	pthread_mutex_unlock(&mac_port_map.lock);
	log(DEBUG, "Insert Mac addr: " ETHER_STRING " -> %s at Hash addr: %d", ETHER_FMT(entry->mac), \
					entry->iface->name, hash_addr);
	//dump_mac_port_table();
}

void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	//fprintf(stdout, "dumping the mac_port table:\n");
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		while (entry) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), \
					entry->iface->name, (int)(now - entry->visited));

			entry = entry->next;
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

int sweep_aged_mac_port_entry()
{
	// TODO: implement the sweeping process here
	//fprintf(stdout, "TODO: implement the sweeping process here.\n");
	int delete_num = 0;
	mac_port_entry_t *pre, *entry;
	time_t now = time(NULL);

	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		pre = NULL;
		while (entry) {
			if (now - entry->visited > 30){
				log(DEBUG, "Delete " ETHER_STRING " -> %s, %d", ETHER_FMT(entry->mac), \
					entry->iface->name, (int)(now - entry->visited));
				
				if (pre)
					pre->next = entry->next;
				else
					mac_port_map.hash_table[i] = entry->next;				
				free(entry);
				if (pre)
					entry = pre->next;
				else
					entry = mac_port_map.hash_table[i];
				delete_num++;				
			}		
			else{
				pre = entry;
				entry = entry->next;			
			}
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);

	return delete_num;
}

void *sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		int n = sweep_aged_mac_port_entry();

		if (n > 0){
			//fprintf(stdout, "After sweep\n");
	        //dump_mac_port_table();
			log(DEBUG, "%d aged entries in mac_port table are removed.", n);
		}
	}

	return NULL;
}
