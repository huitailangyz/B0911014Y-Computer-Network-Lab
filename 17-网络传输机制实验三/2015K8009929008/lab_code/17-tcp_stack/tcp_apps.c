#include "tcp_sock.h"

#include "log.h"
#include <time.h>
#include <unistd.h>
#define SEND_LEN_PER 4096
#define SEND_LEN_TOTAL 1024 * 1024 * 10
// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	FILE *fout;
	fout = fopen("server-output.dat", "wb");
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	time_t begin = time(NULL);
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(FINISH, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(FINISH, "accept a connection.");

	char rbuf[4097];
	int rlen = 0;
	int rlen_total = 0;
	int rlen_each = SEND_LEN_PER;
	while (1) {
		rlen = tcp_sock_read(csk, rbuf, rlen_each);
		log(DEBUG, "Receive date len : %d", rlen);
		if (rlen <= 0) {
			log(ERROR, "tcp_sock_read return negative value, finish transmission.");
			break;
		} 
		else if (rlen > 0) {
			rbuf[rlen] = '\0';
			//fprintf(stdout, "Receive date len: %d, content: %s\n", rlen, rbuf);
			fwrite(rbuf, 1, rlen, fout);
			fflush(stdout);
			fflush(fout);
		}
		//sleep(1);
		rlen_total += rlen;
		log(INFO, "Finished receive %d", rlen_total);
		usleep(100);
	}
	assert(rlen_total == SEND_LEN_TOTAL);
	//sleep(1);
	log(FINISH, "close this connection.");
	tcp_sock_close(csk);
	fclose(fout);
	time_t end = time(NULL);
	log(FINISH, "Total time: %lds.", (end - begin));
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	FILE *fin, *fout;
	fin = fopen("war_and_peace.txt", "rb");
	fout = fopen("client-output.dat", "wb");
	struct sock_addr *skaddr = arg;
	log(FINISH, "Enter tcp_client.");
	struct tcp_sock *tsk = alloc_tcp_sock();
	log(FINISH, "Finish alloc_tcp_sock.");
	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}
	log(FINISH, "Finish connected.");
	int wlen = SEND_LEN_PER;
	int sendlen = 0;
	char wbuf[4097];
	//sleep(1);
	while(sendlen < SEND_LEN_TOTAL) {
		fread(wbuf, sizeof(char), wlen, fin);
		fwrite(wbuf, sizeof(char), wlen, fout);
		if (tcp_sock_write(tsk, wbuf, wlen) < 0)
			break;
		sendlen += wlen;
		//sleep(1);
		log(INFO, "Send total len of %d.", sendlen);
		usleep(100);
	}
	log(FINISH, "Finish send 10MB file.");
	assert(sendlen == SEND_LEN_TOTAL);
	tcp_sock_close(tsk);
	log(FINISH, "Finish close.");
	fclose(fin);
	fclose(fout);
	return NULL;
}
