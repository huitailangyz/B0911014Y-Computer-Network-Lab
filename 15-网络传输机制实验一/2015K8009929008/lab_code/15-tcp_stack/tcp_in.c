#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>

// handling incoming packet for TCP_LISTEN state
//
// 1. malloc a child tcp sock to serve this connection request; 
// 2. send TCP_SYN | TCP_ACK by child tcp sock;
// 3. hash the child tcp sock into established_table (because the 4-tuple 
//    is determined).
void tcp_state_listen(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	//fprintf(stdout, "TODO: implement %s.\n", __func__);
	// [1] malloc a child tcp sock to serve this connection request
	struct tcp_sock *child_tsk = alloc_tcp_sock();
	child_tsk->sk_dip = cb->saddr;
	child_tsk->sk_dport = cb->sport;
	child_tsk->sk_sip = cb->daddr;
	child_tsk->sk_sport = cb->dport;
	child_tsk->parent = tsk;
	child_tsk->rcv_nxt = cb->seq_end;
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

// handling incoming packet for TCP_SYN_SENT state
//
// If everything goes well (the incoming packet is TCP_SYN|TCP_ACK), reply with 
// TCP_ACK, and enter TCP_ESTABLISHED state, notify tcp_sock_connect; otherwise, 
// reply with TCP_RST.
void tcp_state_syn_sent(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	//fprintf(stdout, "TODO: implement %s.\n", __func__);
	if (cb->flags & (TCP_SYN | TCP_ACK)){
		tsk->rcv_nxt = cb->seq_end;
		tsk->snd_una = cb->ack;
		tcp_send_control_packet(tsk, TCP_ACK);
		tcp_set_state(tsk, TCP_ESTABLISHED);
		wake_up(tsk->wait_connect);
	}
	else{
		tcp_send_reset(cb);
	}
	//log(DEBUG, "Leave %s", __func__);
}

// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
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
	tsk->rcv_nxt = cb->seq_end;
	tsk->snd_una = cb->ack;
	// [1] remove from parent's listen queue and add into parent's accept queue
	tcp_sock_accept_enqueue(tsk);

	// [2] wake up parent 
	wake_up(tsk->parent->wait_accept);

	tcp_set_state(tsk, TCP_ESTABLISHED);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
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
	log(DEBUG, "Now state is %s", tcp_state_to_str(tsk->state));
	char tmp[50];
	tcp_copy_flags_to_str(cb->flags, tmp);
	log(DEBUG, "The new packet flag is %s", tmp);

	// [1] if the state is TCP_CLOSED, hand the packet over to tcp_state_closed
	if(tsk->state == TCP_CLOSED) {
		tcp_state_closed(tsk, cb, packet);
		return ;
	}
	// [2] if the state is TCP_LISTEN, hand it over to tcp_state_listen
	else if(tsk->state == TCP_LISTEN) {
		tcp_state_listen(tsk, cb, packet);
		return ;
	}
	// [3] if the state is TCP_SYN_SENT, hand it to tcp_state_syn_sent
	else if(tsk->state == TCP_SYN_SENT) {
		tcp_state_syn_sent(tsk, cb, packet);
		return ;
	}

	// [4] check whether the sequence number of the packet is valid
	if (!is_tcp_seq_valid(tsk, cb))
		return ;

	// [5] if the TCP_RST bit of the packet is set, close this connection, and
	// 	   release the resources of this tcp sock
	if(cb->flags & TCP_RST){
		tcp_set_state(tsk, TCP_CLOSED);
		tcp_bind_unhash(tsk);
		tcp_unhash(tsk);
		return ;
	}

	// [6] if the TCP_SYN bit is set, reply with TCP_RST and close this connection,
	// 	   as valid TCP_SYN has been processed in step 2 & 3
	if(cb->flags & TCP_SYN){
		tcp_send_reset(cb);
		tcp_set_state(tsk, TCP_CLOSED);
		tcp_bind_unhash(tsk);
		tcp_unhash(tsk);
	}

	// [7] check if the TCP_ACK bit is set, since every packet (except the first 
	//     SYN) should set this bit
	if (!(cb->flags & TCP_ACK))
		return ;

	// [8] process the ack of the packet: if it ACKs the outgoing SYN packet, 
	//     establish the connection; (if it ACKs new data, update the window)
	//     if it ACKs the outgoing FIN packet, switch to correpsonding state
	if(tsk->state == TCP_SYN_RECV){
		tcp_state_syn_recv(tsk, cb, packet);
		return ;
	}
	else if(tsk->state == TCP_FIN_WAIT_1) {
		tsk->rcv_nxt = cb->seq_end;
		tsk->snd_una = cb->ack;
		tcp_set_state(tsk, TCP_FIN_WAIT_2);
		return ;
	}
	else if(tsk->state == TCP_LAST_ACK){
		tsk->rcv_nxt = cb->seq_end;
		tsk->snd_una = cb->ack;
		tcp_set_state(tsk, TCP_CLOSED);
		tcp_unhash(tsk);
		return ;
	}

	// [9] (process the payload of the packet: call tcp_recv_data to receive data)

	// [10] if the TCP_FIN bit is set, update the TCP_STATE accordingly
	if(cb->flags & TCP_FIN){
		tsk->rcv_nxt = cb->seq_end;
		tsk->snd_una = cb->ack;
		tcp_send_control_packet(tsk, TCP_ACK);
		switch (tsk->state) {
			case TCP_ESTABLISHED:
				tcp_set_state(tsk, TCP_CLOSE_WAIT);
				break;
			case TCP_FIN_WAIT_2:
				tcp_set_state(tsk, TCP_TIME_WAIT);
				tcp_set_timewait_timer(tsk);
				break;
		}
		return ;
	}
	// [11] at last, do not forget to reply with TCP_ACK if the connection is alive
	tcp_send_control_packet(tsk, TCP_ACK);
}
