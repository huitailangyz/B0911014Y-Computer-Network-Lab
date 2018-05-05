/* server application */
 
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
 
int main(int argc, const char *argv[])
{
    int s, cs;
    struct sockaddr_in server, client;
    char msg[2000];

    // Create socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Could not create socket");
		return -1;
    }
    printf("Socket created\n");
     
    // Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(12345);
     
    // Bind
    if (bind(s,(struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("bind failed. Error");
        return -1;
    }
    printf("bind done\n");
     
    // Listen
    listen(s, 3);
    
	 
	// Accept and incoming connection
	printf("Waiting for incoming connections...\n");
	// accept connection from an incoming client
	int c = sizeof(struct sockaddr_in);
	if ((cs = accept(s, (struct sockaddr *)&client, (socklen_t *)&c)) < 0) {
		perror("accept failed");
		return 1;
	}
	printf("Connection accepted\n");

	int msg_len = 0,file_name_len = 0,start,finish;
	int *int_pointer;
	// Receive a message from client
	msg_len = recv(cs, msg, sizeof(msg), 0);
	printf("Received %d characters\n",msg_len);
	int_pointer = msg;
	file_name_len = ntohl((int)*int_pointer);
	printf("file name len is %d\n",file_name_len);
	char file_name[100];
	strcpy(file_name,msg+4);
	printf("file_name is %s\n",file_name);
	int_pointer = msg+4+file_name_len;
	start = ntohl(*int_pointer);
	int_pointer++;
	finish = ntohl(*int_pointer);
	printf("This part should process from %d to %d\n",start,finish);	

	FILE *fp = fopen(file_name,"r");
	fseek(fp, start, SEEK_SET);
	char read_char;
	int record[26];
	memset(record,0,sizeof(record));
	for (int i=start; i<finish; i++){
		fread(&read_char,1,1,fp);
		//printf("%c",read_char);
		if (read_char>=97 && read_char<=122)
			record[read_char-97]++;
		else if(read_char>=65 && read_char<=90)
			record[read_char-65]++;
	}


	int_pointer = msg;
	for (int i=0; i<26; i++){
		//printf("%c %d\n",'a'+i,record[i]);
		*int_pointer = htonl(record[i]);
		int_pointer++;
	}
	
	send(cs, msg, 4*26, 0);
	fflush(stdout);
	fclose(fp);		
    return 0;
}
