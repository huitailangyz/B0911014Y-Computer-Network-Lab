#include "stp.h"

#include "base.h"
#include "ether.h"
#include "utils.h"
#include "types.h"
#include "packet.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <unistd.h>

#include <pthread.h>
#include <signal.h>
#define get_switch_id(switch_id) (int)(switch_id & 0xFFFF)
#define get_port_id(port_id) (int)(port_id & 0xFF)

stp_t *stp;

const u8 eth_stp_addr[] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x01 };

static bool stp_is_root_switch(stp_t *stp)
{
	return stp->designated_root == stp->switch_id;
}

static bool stp_port_is_designated(stp_port_t *p)
{
	return p->designated_switch == p->stp->switch_id &&
		p->designated_port == p->port_id;
}

static const char *stp_port_state(stp_port_t *p)
{
	if (p->stp->root_port && \
			p->port_id == p->stp->root_port->port_id)
		return "ROOT";
	else if (p->designated_switch == p->stp->switch_id &&
		p->designated_port == p->port_id)
		return "DESIGNATED";
	else
		return "ALTERNATE";
}

static void stp_port_send_packet(stp_port_t *p, void *stp_msg, int msg_len)
{
	int pkt_len = ETHER_HDR_SIZE + LLC_HDR_SIZE + msg_len;
	char *pkt = malloc(pkt_len);

	// ethernet header
	struct ether_header *eth = (struct ether_header *)pkt;
	memcpy(eth->ether_dhost, eth_stp_addr, 6);
	memcpy(eth->ether_shost, p->iface->mac, 6);
	eth->ether_type = htons(pkt_len - ETHER_HDR_SIZE);

	// LLC header
	struct llc_header *llc = (struct llc_header *)(pkt + ETHER_HDR_SIZE);
	llc->llc_dsap = LLC_DSAP_SNAP;
	llc->llc_ssap = LLC_SSAP_SNAP;
	llc->llc_cntl = LLC_CNTL_SNAP;

	memcpy(pkt + ETHER_HDR_SIZE + LLC_HDR_SIZE, stp_msg, msg_len);

	iface_send_packet(p->iface, pkt, pkt_len);
}

static void stp_port_send_config(stp_port_t *p)
{
	stp_t *stp = p->stp;
	bool is_root = stp_is_root_switch(stp);
	if (!is_root && !stp->root_port) {
		return;
	}

	struct stp_config config;
	memset(&config, 0, sizeof(config));
	config.header.proto_id = htons(STP_PROTOCOL_ID);
	config.header.version = STP_PROTOCOL_VERSION;
	config.header.msg_type = STP_TYPE_CONFIG;
	config.flags = 0;
	config.root_id = htonll(stp->designated_root);
	config.root_path_cost = htonl(stp->root_path_cost);
	config.switch_id = htonll(stp->switch_id);
	config.port_id = htons(p->port_id);
	config.msg_age = htons(0);
	config.max_age = htons(STP_MAX_AGE);
	config.hello_time = htons(STP_HELLO_TIME);
	config.fwd_delay = htons(STP_FWD_DELAY);

    log(DEBUG, "port %s send config packet.", p->port_name);
	stp_port_send_packet(p, &config, sizeof(config));
}

static void stp_send_config(stp_t *stp)
{
	for (int i = 0; i < stp->nports; i++) {
		stp_port_t *p = &stp->ports[i];
		if (stp_port_is_designated(p)) {
			stp_port_send_config(p);
		}
	}
}

static void stp_handle_hello_timeout(void *arg)
{
	// log(DEBUG, "hello timer expired, now = %llx.", time_tick_now());

	stp_t *stp = arg;
	stp_send_config(stp);
	stp_start_timer(&stp->hello_timer, time_tick_now());
}

static void stp_port_init(stp_port_t *p)
{
	stp_t *stp = p->stp;

	p->designated_root = stp->designated_root;
	p->designated_switch = stp->switch_id;
	p->designated_port = p->port_id;
	p->designated_cost = stp->root_path_cost;
	log(DEBUG, "port %s initial info: stp->designated_root = %04x.", p->port_name, get_switch_id(p->designated_root));
}

void *stp_timer_routine(void *arg)
{
	while (true) {
		long long int now = time_tick_now();

		pthread_mutex_lock(&stp->lock);

		stp_timer_run_once(now);

		pthread_mutex_unlock(&stp->lock);

		usleep(100);
	}

	return NULL;
}


static void stp_dump_state()
{

	pthread_mutex_lock(&stp->lock);

	bool is_root = stp_is_root_switch(stp);
	if (is_root) {
		log(INFO, "this switch is root."); 
	}
	else {
		log(INFO, "non-root switch, desinated root: %04x, root path cost: %d.", \
				get_switch_id(stp->designated_root), stp->root_path_cost);
	}

	for (int i = 0; i < stp->nports; i++) {
		stp_port_t *p = &stp->ports[i];
		log(INFO, "port id: %02d, role: %s.", get_port_id(p->port_id), \
				stp_port_state(p));
		log(INFO, "\tdesignated ->root: %04x, ->switch: %04x, " \
				"->port: %02d, ->cost: %d.", \
				get_switch_id(p->designated_root), \
				get_switch_id(p->designated_switch), \
				get_port_id(p->designated_port), \
				p->designated_cost);
	}

	pthread_mutex_unlock(&stp->lock);
}

static bool compare_priority_between_port_and_config(stp_port_t *p, struct stp_config *config){
	/* True if port has a priority */
	log(INFO, "port designated root: %04x, config desinated root: %04x.", \
				get_switch_id(p->designated_root), get_switch_id(ntohll(config->root_id)));
	log(INFO, "port designated_cost: %x, config designated_cost: %x.", \
				p->designated_cost, ntohl(config->root_path_cost));
	log(INFO, "port designated_switch: %04x, config designated_switch: %04x.", \
				get_switch_id(p->designated_switch), get_switch_id(ntohll(config->switch_id)));
	log(INFO, "port designated_port: %02x, config designated_port: %02x.", \
				get_port_id(p->designated_port), get_port_id(ntohs(config->port_id)));

	if (get_switch_id(p->designated_root) != get_switch_id(ntohll(config->root_id))){
		return get_switch_id(p->designated_root) < get_switch_id(ntohll(config->root_id));
	}
	else if (p->designated_cost != ntohl(config->root_path_cost)){
		return p->designated_cost < ntohl(config->root_path_cost);			
	}
	else if (get_switch_id(p->designated_switch) != get_switch_id(ntohll(config->switch_id))){
		return get_switch_id(p->designated_switch) < get_switch_id(ntohll(config->switch_id));	
	}
	else
		return get_port_id(p->designated_port) < get_port_id(ntohs(config->port_id));
}


static bool compare_priority_between_ports(stp_port_t *p1, stp_port_t *p2){
	/* True if port1 has a priority */
	if (p2 == NULL)
		return 1;
	if (get_switch_id(p1->designated_root) != get_switch_id(p2->designated_root)){
		return get_switch_id(p1->designated_root) < get_switch_id(p2->designated_root);
	}
	else if (p1->designated_cost != p2->designated_cost){
		return p1->designated_cost < p2->designated_cost;			
	}
	else if (get_switch_id(p1->designated_switch) != get_switch_id(p2->designated_switch)){
		return get_switch_id(p1->designated_switch) < get_switch_id(p2->designated_switch);	
	}
	else
		return get_port_id(p1->designated_port) < get_port_id(p2->designated_port);
}

static void update_switch_set(stp_t *stp, stp_port_t *p){
	stp_port_t *root_port = NULL;	
	for (int i=0; i < stp->nports; i++){
		if (stp_port_is_designated(&stp->ports[i]))
			continue;
		else if (compare_priority_between_ports(&stp->ports[i], root_port))
			root_port = &stp->ports[i];
	}
	if (root_port == NULL){
		stp->designated_root = stp->switch_id;
		stp->root_path_cost = 0;
	}
	else{		
		stp->designated_root = root_port->designated_root;
		stp->root_path_cost = root_port->designated_cost + root_port->path_cost;
		stp->root_port = root_port;
	}
}

static void update_port_set(stp_t *stp, stp_port_t *p){

	for (int i = 0; i < stp->nports; i++){
		if (stp_port_is_designated(&stp->ports[i])){
			stp->ports[i].designated_root = stp->designated_root;
			stp->ports[i].designated_cost = stp->root_path_cost;
			stp_port_send_config(&stp->ports[i]);
		}
		else if (stp->root_path_cost < stp->ports[i].designated_cost){
			stp->ports[i].designated_root = stp->designated_root;
			stp->ports[i].designated_cost = stp->designated_root;
			stp->ports[i].designated_switch = stp->switch_id;
			stp->ports[i].designated_port = p->port_id;
			stp_port_send_config(&stp->ports[i]);	
		}
	}
}

static void stp_handle_config_packet(stp_t *stp, stp_port_t *p,
		struct stp_config *config)
{
	// TODO: handle config packet here
	//fprintf(stdout, "TODO: handle config packet here.\n");
	log(DEBUG, "port %s receive config packet.", p->port_name);
	/* step 1: compare the priority */
	bool change_port_set = compare_priority_between_port_and_config(p, config);
	if (!change_port_set){
		/* step 2: update switch set */
		p->designated_root = ntohll(config->root_id);
		p->designated_switch = ntohll(config->switch_id);
		p->designated_port = ntohs(config->port_id);
		p->designated_cost = ntohl(config->root_path_cost);
		update_switch_set(stp, p);
		/* step 3: update port set */
		update_port_set(stp, p);
		/* step 4: stop timer */
		stp_stop_timer(&stp->hello_timer);
	}
	else
		stp_port_send_config(p);

	pthread_mutex_unlock(&stp->lock);
	stp_dump_state();
	pthread_mutex_lock(&stp->lock);
	log(DEBUG, "");
}



static void stp_handle_signal(int signal)
{
	if (signal == SIGTERM) {
		log(DEBUG, "received SIGTERM, terminate this program.");
		
		stp_dump_state();

		exit(0);
	}
}

void stp_init(struct list_head *iface_list)
{
	stp = malloc(sizeof(*stp));

	// set switch ID
	u64 mac_addr = 0;
	iface_info_t *iface = list_entry(iface_list->next, iface_info_t, list);
	for (int i = 0; i < sizeof(iface->mac); i++) {
		mac_addr <<= 8;
		mac_addr += iface->mac[i];
	}
	stp->switch_id = mac_addr | ((u64) STP_BRIDGE_PRIORITY << 48);

	stp->designated_root = stp->switch_id;
	stp->root_path_cost = 0;
	stp->root_port = NULL;
	stp_init_timer(&stp->hello_timer, STP_HELLO_TIME, \
			stp_handle_hello_timeout, (void *)stp);

	stp_start_timer(&stp->hello_timer, time_tick_now());

	stp->nports = 0;
	list_for_each_entry(iface, iface_list, list) {
		stp_port_t *p = &stp->ports[stp->nports];

		p->stp = stp;
		p->port_id = (STP_PORT_PRIORITY << 8) | (stp->nports + 1);
		p->port_name = strdup(iface->name);
		p->iface = iface;
		p->path_cost = 1;
		log(DEBUG, "Port Name:  %s", p->port_name);
		stp_port_init(p);

		// store stp port in iface for efficient access
		iface->port = p;

		stp->nports += 1;
	}
	log(DEBUG, "This stp has %d ports.",stp->nports);
	pthread_mutex_init(&stp->lock, NULL);
	pthread_create(&stp->timer_thread, NULL, stp_timer_routine, NULL);

	signal(SIGTERM, stp_handle_signal);
}

void stp_destroy()
{
	pthread_kill(stp->timer_thread, SIGKILL);

	for (int i = 0; i < stp->nports; i++) {
		stp_port_t *port = &stp->ports[i];
		port->iface->port = NULL;
		free(port->port_name);
	}

	free(stp);
}

void stp_port_handle_packet(stp_port_t *p, char *packet, int pkt_len)
{
	stp_t *stp = p->stp;

	pthread_mutex_lock(&stp->lock);
	
	// protocol insanity check is omitted
	struct stp_header *header = (struct stp_header *)(packet + ETHER_HDR_SIZE + LLC_HDR_SIZE);

	if (header->msg_type == STP_TYPE_CONFIG) {
		stp_handle_config_packet(stp, p, (struct stp_config *)header);
	}
	else if (header->msg_type == STP_TYPE_TCN) {
		log(ERROR, "TCN packet is not supported in this lab.\n");
	}
	else {
		log(ERROR, "received invalid STP packet.\n");
	}

	pthread_mutex_unlock(&stp->lock);
}

