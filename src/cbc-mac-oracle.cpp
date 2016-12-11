//EECS 475 Intro Crypto University of Michigan
// Bill Hass, Nick Gaunt, 
// Myles Pollie, Robert Minnema
//
// Performs an attack against CBC-MAC as the client in a client-server model
//
//
//
#include <stdio.h>
#include <stdlib.h>
#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <iostream>
#include <string>

#define DEBUG 1

#define PORT "3490" // the port client will be connecting to

#define BLOCKSIZE 16
#define MAXDATASIZE 1024 // max number of data bytes we will send
#define MAXHEADERSIZE 13

int packetize(unsigned char*, std::string, std::string, int, unsigned char*);
void cbc_mac_var_length(int);

void printBytes(unsigned char* buf, int len){
  for(int i = 0; i < len; i++ ) {
    putc( isprint(buf[i]) ? buf[i] : '.' , stdout );
  }
  return;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[]) {
	int sockfd, numbytes;  
    char buf[MAXDATASIZE+MAXHEADERSIZE+1];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    if (argc != 2) {
        fprintf(stderr,"usage: client hostname\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }
// loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    printf("client: connecting to %s\n", s);
    freeaddrinfo(servinfo); // all done with this structure
	
	cbc_mac_var_length(sockfd);
}

//Takes string type, enc_dec, integer length and data bytes to construct
//a client packet to send to the server socket
int packetize(unsigned char* out_buf, std::string type, std::string enc_dec, int len, unsigned char* data){
	memset(out_buf, '\0', sizeof(unsigned char)*1024);
	std::string length = std::to_string(len);
	std::string msg = type + " " + enc_dec + " " + length + " ";
	memcpy(out_buf, msg.c_str(), msg.length());
	memcpy(out_buf+msg.length(), data, len);
	DEBUG && std::cout << "Here's the final buffer: " << out_buf << std::endl;
	return MAXHEADERSIZE - 4 + length.size()+len;
}

void cbc_mac_var_length(int sockfd) {
	unsigned char out_buf[MAXDATASIZE + MAXHEADERSIZE + 1];
	unsigned char in_buf[MAXDATASIZE + MAXHEADERSIZE + 1];
	int out_len;
	int numbytes = 16;
	unsigned char tag1[17], tag2[17];
	std::string m1 = "a;lsdjkfg;lkjnop";
	std::string m2 = "1998123123lg3456"; 
	
	out_len = packetize(out_buf, "TAG", "ENC", m1.size(), (unsigned char *) m1.c_str());
        sleep(1);
	send(sockfd, out_buf, out_len, 0);
	if ((numbytes = recv(sockfd, out_buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
		perror("recv");
		exit(1);
	}
	memcpy(tag1, out_buf, 16);
	tag1[17] = '\0';
	std::cout << "Tag1 of '" << m1 << "' is '" << tag1 << "' or '";
	printBytes(tag1, 16);
	std::cout <<"'" <<std::endl;
	
	//memcpy(in_buf, m2, 16);
	out_len = packetize(out_buf, "TAG", "ENC", m2.size(), (unsigned char *) m2.c_str());
        sleep(1);
	send(sockfd, out_buf, out_len, 0);
	if ((numbytes = recv(sockfd, out_buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
		perror("recv");
		exit(1);
	}
	memcpy(tag2, out_buf, 16);
	tag2[17] = '\0';
	std::cout << "Tag2 of '" << m2 << "' is '" << tag2 << "' or '";
	printBytes(tag2, 16);
	std::cout <<"'" <<std::endl;
	
	
	
	// tag2||m1||0x16,...,0x16||m2^tag1 will verify for m1 is multiple of 16
	unsigned char mnew[3*BLOCKSIZE];
	for (int i = 0; i < 16; i++) {
		mnew[i] = m1.at(i);
		mnew[i + 16] = (unsigned char) 0x10;
		mnew[i + 16*2] = m2[i] ^ tag1[i];
	}

	memcpy(in_buf, tag2, 16);
	memcpy(in_buf + 16, mnew, 3*BLOCKSIZE);
	out_len = packetize(out_buf, "TAG", "DEC", 4*BLOCKSIZE, (unsigned char *) in_buf); 

        sleep(1);
	send(sockfd, out_buf, out_len, 0);
	if ((numbytes = recv(sockfd, out_buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
		perror("recv");
		exit(1);
	}
	out_buf[numbytes+1] = '\0';
	std::cout << "Verification of message '" <<(int*) mnew << "' with tag '" << tag2 << "': " << std::endl;
	std::cout << out_buf << std::endl;
}
