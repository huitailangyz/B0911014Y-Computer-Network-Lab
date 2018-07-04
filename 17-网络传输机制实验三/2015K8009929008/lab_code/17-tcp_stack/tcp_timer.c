#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <unistd.h>

static struct list_head timer_list;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	struct tcp_sock *tsk;
	struct tcp_timer *t, *q;
	list_for_each_entry_safe(t, q, &timer_list, list) {
		t->timeout -= TCP_TIMER_SCAN_INTERVAL;
		if (t->timeout <= 0) {
			if (t->type == 0)
			{
				list_delete_entry(&t->list);
				// only support time wait now
				tsk = timewait_to_tcp_sock(t);
				if (!tsk->parent)
				{
					tcp_bind_unhash(tsk);
				}
				tcp_set_state(tsk, TCP_CLOSED);
				free_tcp_sock(tsk);
				tcp_unhash(tsk);
			}
			else
			{
				tsk = timeout_retrans_to_tcp_sock(t);
				t->retrans_time += 1;
				if (t->retrans_time <= 5){
					t->timeout = TCP_TIMEOUT_RETRANSMISSION << t->retrans_time;
					struct tcp_out_save *temp, *q;
					list_for_each_entry_safe(temp, q, &tsk->snd_buffer, list) {
						log(DEBUG, "Retransmission packet len of %d seq_end is %d", temp->len, temp->seq_end-tsk->iss);
						char *packet = (char *)malloc(temp->len);
						memcpy(packet, temp->packet, temp->len);
						ip_send_packet(packet, temp->len);
						break;
					}
					//struct tcp_out_save *handle = list_entry(tsk->snd_buffer.next, struct tcp_out_save, list);
					//log(DEBUG, "GO TO Retransmission packet");
					//log(DEBUG, "Retransmission packet len of %d seq_end is %d", handle->len, handle->seq_end);
					//ip_send_packet(handle->packet, handle->len);
				}
				else{
					log(ERROR, "What the fuck !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n\n\n");
				}
			}
		}
	}
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	log(DEBUG, "[Enter] %s", __func__);
	struct tcp_timer *timer = &tsk->timewait;

	timer->type = 0;
	timer->timeout = TCP_TIMEWAIT_TIMEOUT;
	list_add_tail(&timer->list, &timer_list);

	tcp_sock_inc_ref_cnt(tsk);
}


void tcp_reset_timewait_timer(struct tcp_sock *tsk)
{
	log(DEBUG, "[Enter] %s", __func__);
	struct tcp_timer *timer = &tsk->timewait;
	timer->timeout = TCP_TIMEWAIT_TIMEOUT;
}


void tcp_set_timeout_retransmission(struct tcp_sock *tsk)
{
	log(DEBUG, "[Enter] %s", __func__);
	struct tcp_timer *timer = &tsk->retrans_timer;
	timer->type = 1;
	timer->retrans_time = 0;
	timer->timeout = TCP_TIMEOUT_RETRANSMISSION;
	list_add_tail(&timer->list, &timer_list);

	tcp_sock_inc_ref_cnt(tsk);
}

void tcp_reset_timeout_retransmission(struct tcp_sock *tsk)
{
	log(DEBUG, "[Enter] %s", __func__);
	struct tcp_timer *timer = &tsk->retrans_timer;
	timer->retrans_time = 0;
	timer->timeout = TCP_TIMEOUT_RETRANSMISSION;
}

void tcp_close_timeout_retransmission(struct tcp_sock *tsk)
{	
	log(DEBUG, "[Enter] %s", __func__);
	list_delete_entry(&(tsk->retrans_timer).list);
	free_tcp_sock(tsk);
	tsk->retrans_timer_open = 0;
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
