#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>



void tcp_snd_buf_del_acked(struct tcp_sock *tsk, int flag)
{
	log(DEBUG, "Enter %s", __func__);
	int acked = tsk->snd_una;
	struct tcp_out_save *t, *q;
	log(DEBUG, " \tThe new ack is %d  is to reset :%d", acked - tsk->iss, !flag);
	list_for_each_entry_safe(t, q, &tsk->snd_buffer, list) {
		log(DEBUG, " \tThe packet in send buffer: seq_end is %d packet_len is %d", t->seq_end-tsk->iss, t->len);
		if (t->seq_end <= acked) {
			log(DEBUG, " \tCleared");
			free(t->packet);
			list_delete_entry(&t->list);
			free(t);
		}
	}
	if (tsk->retrans_timer_open)
		if (list_empty(&tsk->snd_buffer))
			tcp_close_timeout_retransmission(tsk);
		else if (!flag)
			tcp_reset_timeout_retransmission(tsk);
		else ;
	else ;
	if (tsk->wait_finish == 1) {
		log(DEBUG, "The snd_buffer is empty : %d", list_empty(&tsk->snd_buffer));
		if (list_empty(&tsk->snd_buffer))
			wake_up(tsk->wait_send);
	}
	//log(DEBUG, "Leave %s", __func__);
}


// handling incoming packet for TCP_LISTEN state
//
// 1. malloc a child tcp sock to serve this connection request; 
// 2. send TCP_SYN | TCP_ACK by child tcp sock;
// 3. hash the child tcp sock into established_table (because the 4-tuple 
//    is determined).
void tcp_state_listen(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	//fprintf(stdout, "TODO: implement %s.\n", __func__);
	log(DEBUG, "Enter %s", __func__);
	// [1] malloc a child tcp sock to serve this connection request
	struct tcp_sock *child_tsk = alloc_tcp_sock();
	child_tsk->sk_dip = cb->saddr;
	child_tsk->sk_dport = cb->sport;
	child_tsk->sk_sip = cb->daddr;
	child_tsk->sk_sport = cb->dport;
	child_tsk->parent = tsk;
	child_tsk->rcv_nxt = cb->seq_end;
	child_tsk->peer_iss = cb->seq;
	list_add_tail(&child_tsk->list, &tsk->listen_queue);
	log(DEBUG, "New child tcp sock: ["IP_FMT":%hu<->"IP_FMT":%hu].",\
				HOST_IP_FMT_STR(child_tsk->sk_sip), child_tsk->sk_sport,
				HOST_IP_FMT_STR(child_tsk->sk_dip), child_tsk->sk_dport);

	// [2] send TCP_SYN | TCP_ACK by child tcp sock
	tcp_send_control_packet(child_tsk, TCP_SYN | TCP_ACK);

	// [3] hash the child tcp sock into established_table (because the 4-tuple 
	//     is determined)
	tcp_set_state(child_tsk, TCP_SYN_RECV);
	tcp_hash(child_tsk);
}

// handling incoming packet for TCP_CLOSED state, by replying TCP_RST
void tcp_state_closed(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	tcp_send_reset(cb);
}

// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->ack + cb->rwnd - tsk->snd_nxt;
	log(DEBUG, "Old snd_wnd is %d new snd_wnd is %d cb->ack is %d cb->rwnd is %d tsk->snd_nxt is %d", old_snd_wnd, tsk->snd_wnd, cb->ack-tsk->iss, cb->rwnd, tsk->snd_nxt-tsk->iss);
	assert(tsk->snd_wnd >= 0 && tsk->snd_wnd <= TCP_DEFAULT_WINDOW);
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}



int tcp_recv_data(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	//fprintf(stdout, "TODO: implement %s.\n", __func__);
	pthread_mutex_lock(&tsk->lock);
	log(DEBUG, "receive packet len of %d", cb->pl_len);
	log(DEBUG, "Now the tsk->send unacked is %d, the new cb->ack is %d", tsk->snd_una - tsk->iss, cb->ack - tsk->iss);
	int flag = tsk->snd_una == cb->ack;
	tsk->snd_una = cb->ack;
	tcp_snd_buf_del_acked(tsk, flag);
	tcp_update_window_safe(tsk, cb);
	log(DEBUG, "Now the tsk->rcv_nxt is %d, the new cb->seq is %d", tsk->rcv_nxt - tsk->peer_iss, cb->seq - tsk->peer_iss);
	//if (tsk->rcv_wnd > 0)
	if(tsk->rcv_nxt == cb->seq) {
		log(DEBUG, "-***- It's a continous packet.");
		int empty = 0;
		empty = ring_buffer_empty(tsk->rcv_buf);
		log(DEBUG, "Write from %d to %d", cb->seq - tsk->peer_iss, cb->seq_end - tsk->peer_iss);
		write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
		
		if (empty) {
			wake_up(tsk->wait_recv);
		}
		tsk->rcv_wnd -= cb->pl_len;
		tsk->rcv_nxt += cb->pl_len;
		int found = 1;
		while (found) {
			found = 0;
			struct tcp_cb *t, *q;
			list_for_each_entry_safe(t, q, &tsk->rcv_ofo_buf, list) {
				if (t->seq == tsk->rcv_nxt) {
					found = 1;
					tsk->rcv_wnd -= t->pl_len;
					tsk->rcv_nxt += t->pl_len;
					//log(NOTHING, "%s", t->payload);
					log(DEBUG, "Write from %d to %d", t->seq - tsk->peer_iss, t->seq_end - tsk->peer_iss);
					write_ring_buffer(tsk->rcv_buf, t->payload, t->pl_len);
					list_delete_entry(&t->list);
					free(t->payload);
					free(t);
				}
			}
		}
		pthread_mutex_unlock(&tsk->lock);
		return 1;
	}
	else if (cb->seq_end > tsk->rcv_nxt){
		log(DEBUG, "-***-Receive discontinuous sequence. tsk->rcv_nxt is %d\t cb->seq is %d", tsk->rcv_nxt - tsk->peer_iss, cb->seq - tsk->peer_iss);

		int found = 0;
		struct tcp_cb *t, *q;
		list_for_each_entry_safe(t, q, &tsk->rcv_ofo_buf, list) {
			if (t->seq == cb->seq && t->pl_len == cb->pl_len) {
				found = 1;
				log(ERROR, "A duplicate data packet with the same seq.");
			}
			else if (t->seq == cb->seq) {
				log(ERROR, "A duplicate data packet with the same seq and different len");
			}
		}
		if (found == 0) {
			struct tcp_cb *cb_t = (struct tcp_cb *)malloc(sizeof(struct tcp_cb));
			memcpy(cb_t, cb, sizeof(struct tcp_cb));
			char *packet = (char *)malloc(cb_t->pl_len);
			memcpy(packet, cb->payload, cb->pl_len);
			cb_t->payload = packet;
			list_add_tail(&cb_t->list, &tsk->rcv_ofo_buf);
		}
		pthread_mutex_unlock(&tsk->lock);
		return 0;
	}
	else {
		pthread_mutex_unlock(&tsk->lock);
		return 1;
	}
	
	//log(DEBUG, "Leave %s", __func__);
}



// handling incoming packet for TCP_SYN_SENT state
//
// If everything goes well (the incoming packet is TCP_SYN|TCP_ACK), reply with 
// TCP_ACK, and enter TCP_ESTABLISHED state, notify tcp_sock_connect; otherwise, 
// reply with TCP_RST.
void tcp_state_syn_sent(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	//fprintf(stdout, "TODO: implement %s.\n", __func__);
	log(DEBUG, "Enter %s", __func__);
	if((cb->flags^(TCP_SYN|TCP_ACK)) == 0) {
		pthread_mutex_lock(&tsk->lock);
		tcp_update_window_safe(tsk, cb);
		tsk->rcv_nxt = cb->seq_end;
		tsk->peer_iss = cb->seq;
		int flag = tsk->snd_una == cb->ack;
		tsk->snd_una = cb->ack;
		tcp_snd_buf_del_acked(tsk, flag);
		pthread_mutex_unlock(&tsk->lock);
		tcp_send_control_packet(tsk, TCP_ACK);
		tcp_set_state(tsk, TCP_ESTABLISHED);
		wake_up(tsk->wait_connect);
	}
	else {
		log(ERROR, "A unexpected packet. ignore it");
		tcp_send_reset(cb);
	}
	//log(DEBUG, "Leave %s", __func__);
}


// handling incoming ack packet for tcp sock in TCP_SYN_RECV state
//
// 1. remove itself from parent's listen queue;
// 2. add itself to parent's accept queue;
// 3. wake up parent (wait_accept) since there is established connection in the
//    queue.
void tcp_state_syn_recv(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	//fprintf(stdout, "TODO: implement %s.\n", __func__);
	log(DEBUG, "Enter %s", __func__);
	if (cb->flags & TCP_ACK)
	{
		pthread_mutex_lock(&tsk->lock);
		//tsk->rcv_nxt = cb->seq_end;
		int flag = tsk->snd_una == cb->ack;
		tsk->snd_una = cb->ack;
		tcp_snd_buf_del_acked(tsk, flag);
		tcp_update_window_safe(tsk, cb);
		pthread_mutex_unlock(&tsk->lock);
		// [1] remove from parent's listen queue and add into parent's accept queue
		tcp_sock_accept_enqueue(tsk);

		// [2] wake up parent 
		wake_up(tsk->parent->wait_accept);

		tcp_set_state(tsk, TCP_ESTABLISHED);	
		if (cb->pl_len != 0) {
			log(ERROR, "Miss the third ack.");
			int back = tcp_recv_data(tsk, cb, packet);
			if (back)
				tcp_send_control_packet(tsk, TCP_ACK);
			return ;
		}
	}
	else if (cb->flags & TCP_SYN){
		log(DEBUG, "A timeout retransmission packet of TCP_SYN from client.")
		return ;
	}
	else
	{
		log(ERROR, "A unexpected packet. ignore it");
		return ;
	}
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	log(DEBUG, "received a new packet. tsk->rcv_nxt is %d cb->seq is %d cb->seq_end is %d rcv_end is %d", tsk->rcv_nxt-tsk->peer_iss, cb->seq-tsk->peer_iss, cb->seq_end-tsk->peer_iss, rcv_end-tsk->peer_iss);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		return 0;
	}
}


void tcp_state_established(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	log(DEBUG, "Enter %s", __func__);
	if ((cb->flags ^ (TCP_SYN | TCP_ACK)) == 0)
	{
		log(DEBUG, "A timeout transmission of packet SYN|ACK from server.");
		tcp_send_control_packet(tsk, TCP_ACK);
		return ;
	}
	else if ((cb->flags ^ (TCP_PSH | TCP_ACK)) == 0)
	{
		int back = tcp_recv_data(tsk, cb, packet);
		log(DEBUG, "The flag after recv data: %d", back);
		if (back)
			tcp_send_control_packet(tsk, TCP_ACK);
		return ;
	}
	else if ((cb->flags ^ TCP_ACK) == 0) {
		pthread_mutex_lock(&tsk->lock);
		tsk->rcv_nxt = cb->seq_end;
		int flag = tsk->snd_una == cb->ack;
		tsk->snd_una = cb->ack;
		tcp_snd_buf_del_acked(tsk, flag);
		tcp_update_window_safe(tsk, cb);
		pthread_mutex_unlock(&tsk->lock);
	
	}
	else if (cb->flags & TCP_FIN) {
		pthread_mutex_lock(&tsk->lock);
		int flag = tsk->snd_una == cb->ack;
		tsk->snd_una = cb->ack;
		tcp_snd_buf_del_acked(tsk, flag);
		tcp_set_state(tsk, TCP_CLOSE_WAIT);
		tsk->rcv_nxt = cb->seq_end;
		pthread_mutex_unlock(&tsk->lock);

		tcp_send_control_packet(tsk, TCP_ACK);
		wake_up(tsk->wait_recv);

		
	}
	else
	{
		log(ERROR, "A unexpected packet. ignore it");
		return ;
	}
}

void tcp_state_fin_wait_1(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	log(DEBUG, "Enter %s", __func__);
	if (!(cb->flags & TCP_ACK))
		return ;
	if (cb->flags & TCP_ACK){
		pthread_mutex_lock(&tsk->lock);
		//tsk->rcv_nxt = cb->seq_end;
		int flag = tsk->snd_una == cb->ack;
		tsk->snd_una = cb->ack;
		tcp_snd_buf_del_acked(tsk, flag);
		pthread_mutex_unlock(&tsk->lock);
		//if (list_empty(& tsk->snd_buffer))
		log(INFO, "In fin_wait_1: tsk->snd_nxt is %d cb->ack is %d", tsk->snd_nxt-tsk->iss, cb->ack-tsk->iss);
		if(tsk->snd_nxt == cb->ack)
		{
			log(DEBUG, "All the data sended have been processed. ack is %d", cb->ack-tsk->iss);
			tcp_set_state(tsk, TCP_FIN_WAIT_2);
		}
	}
	else
	{
		log(ERROR, "A unexpected packet. ignore it");
		return ;
	}
}

void tcp_state_fin_wait_2(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	log(DEBUG, "Enter %s", __func__);
	if (!(cb->flags & TCP_ACK))
		return ;
	if (cb->flags & TCP_FIN) {
		pthread_mutex_lock(&tsk->lock);
		int flag = tsk->snd_una == cb->ack;
		tsk->snd_una = cb->ack;
		tcp_snd_buf_del_acked(tsk, flag);
		pthread_mutex_unlock(&tsk->lock);
		
		tsk->rcv_nxt = cb->seq_end;
		tcp_set_state(tsk, TCP_TIME_WAIT);
		tcp_send_control_packet(tsk, TCP_ACK);
		tcp_set_timewait_timer(tsk);
		
	}
	else
	{
		log(ERROR, "A unexpected packet. ignore it");
		return ;
	}
}

void tcp_state_time_wait(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	log(DEBUG, "Enter %s", __func__);
	if (!(cb->flags & TCP_ACK))
		return ;
	if (cb->flags & TCP_FIN) {
		pthread_mutex_lock(&tsk->lock);
		int flag = tsk->snd_una == cb->ack;
		tsk->snd_una = cb->ack;
		tcp_snd_buf_del_acked(tsk, flag);
		pthread_mutex_unlock(&tsk->lock);
		
		tcp_reset_timewait_timer(tsk);
		tcp_send_control_packet(tsk, TCP_ACK);
	}
	else
	{
		log(ERROR, "A unexpected packet. ignore it");
		return ;
	}
}


void tcp_state_close_wait(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	log(DEBUG, "Enter %s", __func__);
	if (!(cb->flags & TCP_ACK))
		return ;
	if (cb->flags & TCP_FIN) {
		pthread_mutex_lock(&tsk->lock);
		int flag = tsk->snd_una == cb->ack;
		tsk->snd_una = cb->ack;
		tcp_snd_buf_del_acked(tsk, flag);
		pthread_mutex_unlock(&tsk->lock);
		
		if (tsk->rcv_nxt == cb->seq)
			tsk->rcv_nxt = cb->seq_end;
		tcp_set_state(tsk, TCP_CLOSE_WAIT);				
		//wake_up(tsk->wait_recv);
		tcp_send_control_packet(tsk, TCP_ACK);
	}
	else if ((cb->flags ^ (TCP_PSH | TCP_ACK)) == 0)
	{
		tcp_recv_data(tsk, cb, packet);
		tcp_send_control_packet(tsk, TCP_ACK);
		return ;
	}
	else
	{
		log(ERROR, "A unexpected packet. ignore it");
		return ;
	}
}

void tcp_state_last_ack(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	log(DEBUG, "Enter %s", __func__);
	if ((cb->flags ^ TCP_ACK) == 0) {
		pthread_mutex_lock(&tsk->lock);
		tsk->rcv_nxt = cb->seq_end;
		int flag = tsk->snd_una == cb->ack;
		tsk->snd_una = cb->ack;
		tcp_snd_buf_del_acked(tsk, flag);
		pthread_mutex_unlock(&tsk->lock);
		tcp_set_state(tsk, TCP_CLOSED);
		tcp_unhash(tsk);
	}
	else
	{
		log(ERROR, "A unexpected packet. ignore it");
		return ;
	}
}





// Process an incoming packet as follows:
// 	 1. if the state is TCP_CLOSED, hand the packet over to tcp_state_closed;
// 	 2. if the state is TCP_LISTEN, hand it over to tcp_state_listen;
// 	 3. if the state is TCP_SYN_SENT, hand it to tcp_state_syn_sent;
// 	 4. check whether the sequence number of the packet is valid, if not, drop
// 	    it;
// 	 5. if the TCP_RST bit of the packet is set, close this connection, and
// 	    release the resources of this tcp sock;
// 	 6. if the TCP_SYN bit is set, reply with TCP_RST and close this connection,
// 	    as valid TCP_SYN has been processed in step 2 & 3;
// 	 7. check if the TCP_ACK bit is set, since every packet (except the first 
//      SYN) should set this bit;
//   8. process the ack of the packet: if it ACKs the outgoing SYN packet, 
//      establish the connection; (if it ACKs new data, update the window;)
//      if it ACKs the outgoing FIN packet, switch to correpsonding state;
//   9. (process the payload of the packet: call tcp_recv_data to receive data;)
//  10. if the TCP_FIN bit is set, update the TCP_STATE accordingly;
//  11. at last, do not forget to reply with TCP_ACK if the connection is alive.
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	//fprintf(stdout, "TODO: implement %s.\n", __func__);
	log(DEBUG, "Enter %s", __func__);
	char tmp[50];
	tcp_copy_flags_to_str(cb->flags, tmp);
	log(DEBUG, "Now state is %s  The new packet flag is %s", tcp_state_to_str(tsk->state), tmp);

	// [4] check whether the sequence number of the packet is valid
	if (tsk->state > TCP_SYN_SENT && tsk->state != TCP_TIME_WAIT)
		if(!is_tcp_seq_valid(tsk, cb)) {
			log(ERROR, "Receive a unvalid seq.");
			tcp_send_control_packet(tsk, TCP_ACK);
			return;
		}


	// [5] if the TCP_RST bit of the packet is set, close this connection, and
	// 	   release the resources of this tcp sock
	if(cb->flags & TCP_RST) {
		tcp_set_state(tsk, TCP_CLOSED);
		tcp_bind_unhash(tsk);
		tcp_unhash(tsk);
		return ;
	}


	switch (tsk->state)
	{
		// [1] if the state is TCP_CLOSED, hand the packet over to tcp_state_closed
		case TCP_CLOSED:
			tcp_state_closed(tsk, cb, packet);
			return ;
		// [2] if the state is TCP_LISTEN, hand it over to tcp_state_listen
		case TCP_LISTEN:
			tcp_state_listen(tsk, cb, packet);
			return ;
		// [3] if the state is TCP_SYN_SENT, hand it to tcp_state_syn_sent
		case TCP_SYN_SENT:
			tcp_state_syn_sent(tsk, cb, packet);
			return ;
		case TCP_SYN_RECV:
			tcp_state_syn_recv(tsk, cb, packet);
			return ;
		case TCP_ESTABLISHED:
			tcp_state_established(tsk, cb, packet);
			return ;
		case TCP_FIN_WAIT_1:
			tcp_state_fin_wait_1(tsk, cb, packet);
			return ;
		case TCP_FIN_WAIT_2:
			tcp_state_fin_wait_2(tsk, cb, packet);
			return ;
		case TCP_CLOSE_WAIT:
			tcp_state_close_wait(tsk, cb, packet);
			return ;
		case TCP_LAST_ACK:
			tcp_state_last_ack(tsk, cb, packet);
			return ;
	}
}
