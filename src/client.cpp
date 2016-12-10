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

#define DEBUG 0

#define PORT "3490" // the port client will be connecting to 

#define MAXDATASIZE 1024 // max number of data bytes we will send
#define MAXHEADERSIZE 13

int packetize(unsigned char*, std::string, std::string, int, unsigned char*);
void tag_timing_attack(unsigned char*, int, int, unsigned char *);

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

//////////////////
    unsigned char* message = (unsigned char *)"TUBULAR TITASTIC GOOD!";
    int len = packetize(out_buf, "TAG", "ENC", 23, message);
    send(sockfd, out_buf, len, 0);
    if ((numbytes = recv(sockfd, buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
        perror("recv");
        exit(1);
    }
    std::cout << "Recv : " << buf << std::endl;

    unsigned char check[39];
    memcpy(check, buf, 16);
    memcpy(check+16, message, 23);

    len = packetize(out_buf, "TAG", "DEC", 39, (unsigned char*) check);
    send(sockfd, out_buf, len, 0);
    if ((numbytes = recv(sockfd, buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
        perror("recv");
        exit(1);
    }
    std::cout << "Recv : " << buf << std::endl;

    exit(1);
//////////////////



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

    unsigned char forgery[17];
    unsigned char * cipher = (unsigned char *) "^sc07% *g5yawc,";
    tag_timing_attack(cipher, sizeof(cipher), sockfd, forgery);
    forgery[16] = '\0';
    std::cout << "FORGERY FOUND : " << forgery << std::endl;

    packetize(out_buf, "TAG", "DEC", 16, forgery);
    send(sockfd, out_buf, 16, 0);
    if ((numbytes = recv(sockfd, buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
        perror("recv");
        exit(1);
    }
    std::cout << "Recv : " << buf << std::endl;

    exit(1);



    out_len = packetize(out_buf, "EAT", "ENC", 16, (unsigned char*)"GOOD_BYE CRYPTO!");
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

void tag_timing_attack(unsigned char* cipher, int cipher_bytes, int sockfd, unsigned char * forged_tag){
    double thresh_millis = 15.0;
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
        out_len = packetize(out_buf, "EAT", "DEC", cipher_bytes+16, (unsigned char*)in_buf);
        std::cout << "SENDIGN: "<< out_buf << std::endl;
        send(sockfd, out_buf, out_len, 0);
        gettimeofday(&t1, NULL);
        if ((numbytes= recv(sockfd, out_buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
            perror("recv");
            exit(1);
        }
        gettimeofday(&t2, NULL);
        diff = (double) ((t2.tv_sec*1000 + t2.tv_usec * 0.001) -(t1.tv_sec*1000 + t1.tv_usec * 0.001));
        std::cout << "time: "<< diff << " ms -- "<<i<<" -- " << out_buf << " --- tried: "<< in_buf << std::endl;
        if(diff >= thresh_millis*(sweep+1)){
          std::cout <<"FOUND TAG BYTE: "<<i<<std::endl;
          forged_tag[sweep] = (unsigned char) i;
          sweep++;
	  break;
        }
        else if(i == 255){
          sweep--;
        }
      }
    }
}
