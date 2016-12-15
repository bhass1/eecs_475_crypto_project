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
#include <sys/time.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#define DEBUG 1

#define PORT "3490" // the port client will be connecting to 

#define MAXDATASIZE 1024 // max number of data bytes we will send
#define MAXHEADERSIZE 13

int packetize(unsigned char*, std::string, std::string, int, unsigned char*);
void tag_timing_attack(char*, unsigned char*, int, int, unsigned char *);

//Helper function to print bytes that are screen-printable
//Replaces non-printable bytes with '.'
int printBytes(unsigned char* buf, int len){
  for(int i = 0; i < len; i++ ) {
    putc( isprint(buf[i]) ? buf[i] : '.' , stdout );
  }
  return 1;
}

// wrapper to get sockaddr based on IPv4 or IPv6
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//Sets up a socket connection to the hostname provided
//in argv[1]. Then it connects to that host using port PORT.
//Finally, the side channel attack, tag_timing_attack, is performed.
int main(int argc, char *argv[])
{
    int sockfd, numbytes;  
    char buf[MAXDATASIZE+MAXHEADERSIZE+1];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    if (argc != 3) {
        fprintf(stderr,"usage: client hostname [TAG/EAT]\n");
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
    unsigned char forgery[17];
    unsigned char * cipher = (unsigned char *) "Pay $1,000,000 to Bill on 1/1/2017";
    tag_timing_attack(argv[2], cipher, strlen((const char*)cipher)+1, sockfd, forgery);
    forgery[16] = '\0';
    std::cout << "FORGERY FOUND : " << forgery << std::endl;
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


//Given a message and socket, starts with an initial tag guess and constructs a forged_tag
void tag_timing_attack(char* arg, unsigned char* cipher, int cipher_bytes, int sockfd, unsigned char * forged_tag){
    double thresh_millis = 20.0;
    double diff = 0.0;
    unsigned char out_buf[MAXDATASIZE + MAXHEADERSIZE+1];
    unsigned char in_buf[MAXDATASIZE + MAXHEADERSIZE+1];
    int out_len, numbytes;
    unsigned char tag[17] = "aaaabbbbccccdddd";
    memcpy(in_buf, tag, 16);
    memcpy(in_buf+16, cipher, cipher_bytes);
    struct timeval t1, t2;
    int sweep = 0;
    while(sweep < 16) {
      for(int i = 0; i < 256; i++){
        in_buf[sweep] = (unsigned char) i;
        out_len = packetize(out_buf, arg, "DEC", cipher_bytes+16, (unsigned char*)in_buf);
        std::cout << "SENDIGN: "<< out_buf << std::endl;
        send(sockfd, out_buf, out_len, 0);
        gettimeofday(&t1, NULL);
        if ((numbytes= recv(sockfd, out_buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
            perror("recv");
            exit(1);
        }
        gettimeofday(&t2, NULL);
        diff = (double) ((t2.tv_sec*1000 + t2.tv_usec * 0.001) -(t1.tv_sec*1000 + t1.tv_usec * 0.001));
        std::cout << "time: "<< diff << " ms -- "<<i<<" -- ";
	printBytes(in_buf, 16);
	std::cout << std::endl;
        if(diff >= thresh_millis*(sweep+1)){
          std::cout <<"FOUND TAG BYTE: "<<i<<std::endl;
          std::cout << "Re-SENDING: ";
	  printBytes(in_buf, 16);
	  std::cout << std::endl;
          out_len = packetize(out_buf, arg, "DEC", cipher_bytes+16, (unsigned char*)in_buf);
          send(sockfd, out_buf, out_len, 0);
          gettimeofday(&t1, NULL);
          if ((numbytes= recv(sockfd, out_buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
              perror("recv");
              exit(1);
          }
          gettimeofday(&t2, NULL);
          diff = (double) ((t2.tv_sec*1000 + t2.tv_usec * 0.001) -(t1.tv_sec*1000 + t1.tv_usec * 0.001));
          if(diff >= thresh_millis*(sweep+1)){
            forged_tag[sweep] = (unsigned char) i;
            sweep++;
            i = 0;
	    if(sweep > 15){
	      return;
	    }
	  }
        } else if(i == 255){
	  forged_tag[sweep] = (unsigned char) 0x88;
          sweep--;
        }
      }
    }
}
