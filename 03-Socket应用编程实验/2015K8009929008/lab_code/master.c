/* client application */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h> 

#define n_worker 2
pthread_mutex_t mutex;
int record[26];
FILE *fp;
char file_name[50];
int filesize;
int file_name_len;



void *calculate(void *n){
	int i = *(int*) n;
	char message[1000],server_reply[1000],ip[100];
	struct sockaddr_in server;
	int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Could not create socket %d\n",i);
    }
    printf("Socket %d created\n",i);
	fscanf(fp,"%s",ip);
	server.sin_addr.s_addr = inet_addr(ip);
	server.sin_family = AF_INET;
	server.sin_port = htons(12345);
	
	//Connect to remote server
	if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		perror("connect failed. Error\n");
		return -1;
	}
	printf("Connected %s\n",ip);
		
	uint32_t *int_pointer = message;

	*int_pointer = htonl(file_name_len);
	strcpy(message+4, file_name);
	int_pointer = message+4+file_name_len;
	*int_pointer = htonl(i*filesize/n_worker);
	int_pointer++;
	*int_pointer = htonl((i==n_worker-1) ? filesize-1 : (i+1)*filesize/n_worker-1);
	send(sock, message,file_name_len+12,0);

	//Receive a reply from the server
    if (recv(sock, server_reply, 2000, 0) < 0) {
        printf("recv failed\n");
	    return -1;
    }
	printf("Receive reply\n");
	int_pointer = server_reply;
	for (int j=0; j<26; j++){
		record[j] += ntohl(*int_pointer);
		int_pointer++;
	}
	close(sock);
}


int main(int argc, char *argv[])
{
	int i;
    pthread_t thread[n_worker];
	
	strcpy(file_name,argv[1]);
	FILE *fp_read = fopen(file_name,"r");
	fseek(fp_read, 0, SEEK_END);  
    filesize = ftell(fp_read);
	file_name_len = strlen(file_name);
	fp = fopen("workers.conf","r");
	printf("The file %s has %d characters\n",file_name, filesize);
	
	memset(record,0,sizeof(record));
	pthread_mutex_init(&mutex,NULL);
	for (i=0; i < n_worker; i++){
		int *p = malloc(sizeof(int));
		*p = i;
		if (pthread_create(&thread[i],NULL,calculate,(void*)p)){
			printf("Error creating thread.\n");
			return -1;
		}
	}

	for (i=0; i < n_worker; i++)
		pthread_join(thread[i],NULL);
	pthread_mutex_destroy(&mutex);

	for (i=0; i<26; i++)
		printf("%c %d\n",'a'+i,record[i]);

	fclose(fp);
   	fclose(fp_read);

    return 0;
}

