#include <stdio.h>
#include <iostream>
#include <string>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#define DEBUG 0

#define PORT "3499" // the port client will be connecting to 

#define MAXDATASIZE 1024 // max number of bytes we can get at once 
#define MAXHEADERSIZE 13

int packetize(unsigned char*, std::string, std::string, int, unsigned char*);

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
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

    unsigned char out_buf[MAXDATASIZE + MAXHEADERSIZE+1];
    int out_len = packetize(out_buf, "EAT", "ENC", 13, (unsigned char*)"HELLO CRYPTO!");
    send(sockfd, out_buf, out_len, 0);
    if ((numbytes = recv(sockfd, buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
        perror("recv");
        exit(1);
    }
    std::cout << "Recv : " << buf << std::endl;

    packetize(out_buf, "EAT", "DEC", numbytes, (unsigned char*)buf);
    send(sockfd, out_buf, out_len, 0);
    if ((numbytes = recv(sockfd, buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
        perror("recv");
        exit(1);
    }

    std::cout << "Recv : " << buf << std::endl;


    out_len = packetize(out_buf, "EAT", "ENC", 15, (unsigned char*)"GOODBYE CRYPTO!");
    send(sockfd, out_buf, out_len, 0);
    if ((numbytes = recv(sockfd, buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
        perror("recv");
        exit(1);
    }
    std::cout << "Recv : " << buf << std::endl;

    packetize(out_buf, "EAT", "DEC", numbytes, (unsigned char*)buf);
    send(sockfd, out_buf, out_len, 0);
    if ((numbytes = recv(sockfd, buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
        perror("recv");
        exit(1);
    }

    std::cout << "Recv : " << buf << std::endl;


    buf[numbytes] = '\0';
    printf("client: received '%s'\n",buf);
    close(sockfd);

    return 0;
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
	return 1024;
}
