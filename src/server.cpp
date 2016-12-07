//EECS 475 Intro Crypto University of Michigan
// Bill Hass, Nick Gaunt, 
// Myles Pollie, Robert Minnema
//
// Performs AES 256-bit CBC encryption on a file in 4096B chunks to produce
// a ciphertext file. Then it performs AES 256-bit CBC decryption on the 
// ciphertext file to produce a decyrpted text file.
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
#include <sys/wait.h>
#include <signal.h>
#include <iostream>
#include <sstream>
#include <string>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define PORT "3499"  // the port users will be connecting to

#define MAXDATASIZE 1024
#define MAXHEADERSIZE 13//4+4+5 : "CBC ENC 1024 "
	

#define BACKLOG 10     // how many pending connections queue will hold

void enc_and_tag(int, unsigned char *, int, unsigned char *, int*, unsigned char *, unsigned char *);
void tag_128_aes_cbc(unsigned char *, int , unsigned char *, unsigned char *);
void enc_128_aes_cbc(int, unsigned char *, int, unsigned char *, int*, unsigned char *, unsigned char *);
int handle_new_connection(int);
int handle_msg(int, unsigned char* );

void printBytes(unsigned char* buf, int len){
  for(int i = 0; i < len; i++ ) {
    putc( isprint(buf[i]) ? buf[i] : '.' , stdout );
  }
  return;
}

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(void)
{
    int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }
    printf("server: waiting for connections...\n");

    while(1) {  // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);

        if (!fork()) { // this is the child process
            close(sockfd); // child doesn't need the listener
	    handle_new_connection(new_fd);
            close(new_fd);
            exit(0);
        }
        close(new_fd);  // parent doesn't need this
    }

    return 0;
}

int handle_new_connection(int sock){
	int buffer_size = MAXDATASIZE + MAXHEADERSIZE + 1; //+1 for null byte
	int numbytes = 0;
	unsigned char buf[buffer_size];
	while(true){
    		if ((numbytes = recv(sock, buf, buffer_size-1, 0)) <= 0) {
        		perror("recv");
			return 0;
    		}
    		buf[numbytes] = '\0';
    		printf("server: received '%s'\n", (unsigned char*)buf);
		if(!handle_msg(sock,buf)){
			break;
		}
	}


	if (send(sock, "Hello, world!", 13, 0) == -1){ 
		perror("send");
		return 0;
	}
	return 1;
}

int handle_msg(int sock,unsigned char* buf){
	std::string type, encdec, len, dat;
	unsigned char data[MAXDATASIZE];
	std::string msg = std::string((const char*)buf);
	std::stringstream ss(msg);
	ss >> type >> encdec >> len;
	std::cout << "msg: "<< msg << std::endl;
	std::cout << "type: "<< type << std::endl;
	std::cout << "encdec: "<< encdec << std::endl;

	int data_len = std::stoi(len);
	std::cout << "data_len: "<< data_len << std::endl;

	int hdr_len = type.length() + encdec.length() + len.length() + 3;
	memcpy(data, buf+hdr_len, data_len);
	std::cout << "data: "<<data<<std::endl;

	unsigned char out_buf[MAXDATASIZE];

	if(type.compare("CBC") == 0) {
		//Perform AES-CBC on data
	} else if(type.compare("CTR") == 0) {
		//Perform AES-CTR on data
	} else if(type.compare("TTE") == 0) {
		//Perform Authenticate Then Encrypt
	} else if(type.compare("EAT") == 0) {
		//Perform Encrypt And Authenticate
		int out_buf_len = 0;
		enc_and_tag(encdec.compare("DEC") != 0, data, data_len, out_buf, &out_buf_len, (unsigned char *)"123456789", (unsigned char *)"123456789");
		if (send(sock, out_buf, out_buf_len, 0) == -1){ 
			perror("send");
			return 0;
		}
	} else {
		std::cout << "BAD PACKET TYPE! -- (" << type << ")"<<std::endl;
		return 0;
	}
	return 1;
}



/**
 * Encrypt or decrypt, depending on flag 'should_encrypt'
 */
void enc_and_tag(int should_encrypt, unsigned char *in_buf, int size_in, unsigned char *out_buf, int* return_len, unsigned char *ckey, unsigned char *ivec) {

  unsigned char ciphertext[MAXDATASIZE + 16];
  int cipher_len = 0;

  unsigned char in_tag[16], in_cipher[MAXDATASIZE];
  if(!should_encrypt) {
    //decryption mode - split off the tag
    memcpy(in_tag, in_buf, 16);
    memcpy(in_cipher, in_buf+16, size_in - 16);
    enc_128_aes_cbc(should_encrypt, in_cipher, size_in-16, ciphertext, &cipher_len, ckey, ivec);
    std::cout << "plain len: "<< cipher_len << std::endl;
    std::cout << "plain : "<< ciphertext << std::endl;
    std::cout << "in_tag : "<< in_tag << std::endl;
  } else {
    enc_128_aes_cbc(should_encrypt, in_buf, size_in, ciphertext, &cipher_len, ckey, ivec);
    std::cout << "cipher len: "<< cipher_len << std::endl;
    std::cout << "cipher : "<< ciphertext << std::endl;
  }
    

  //At this point ciphertext has cipher bytes if should_encrypt, else has plaintext bytes
  unsigned char tag[16];
  if(!should_encrypt) {
    tag_128_aes_cbc(ciphertext, cipher_len, tag, ckey);
    std::cout << "tag : "<< tag << std::endl;

    //VERIFY TAG!
    memcpy(out_buf, ciphertext, cipher_len);
    std::cout << "out_buf : "<< out_buf << std::endl;
    *return_len = cipher_len;

  } else {
    tag_128_aes_cbc(in_buf, size_in, tag, ckey);
    std::cout << "tag : "<< tag << std::endl;
    memcpy(out_buf, tag, 16);
    memcpy(out_buf+16, ciphertext, cipher_len);
    std::cout << "out_buf : "<< out_buf << std::endl;
    *return_len = cipher_len + 16;
  }


}

void tag_128_aes_cbc(unsigned char *in_buf, int size_in, unsigned char *tag, unsigned char *ckey) {
  //Get a new cipher envelope context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  //Initialize the cipher envelope as 128-bit ECB with ckey, iv
  unsigned char iv[16];
  memset(iv, '\0', 16);
  EVP_CipherInit(ctx, EVP_aes_128_cbc(), ckey, iv, 1);
  unsigned blocksize = EVP_CIPHER_CTX_block_size(ctx);
  unsigned char *cipher_buf = (unsigned char *) malloc(blocksize); //just hold onto the tag
  int out_len;
  //Update cipher (Uses EVP API)
  EVP_CipherUpdate(ctx, cipher_buf, &out_len, in_buf, size_in);
  memcpy(tag, cipher_buf, out_len);

  // Now cipher the final block and write it out.
  EVP_CipherFinal(ctx, cipher_buf, &out_len);
  assert(out_len == blocksize);
  memcpy(tag, cipher_buf, out_len);

  // Free memory
  free(cipher_buf);
  EVP_CIPHER_CTX_free(ctx);
}

void enc_128_aes_cbc(int should_encrypt, unsigned  char *in_buf, int size_in, unsigned char *out_buf, int* size_out, unsigned char *ckey, unsigned char *ivec) {

  unsigned char *cipher_buf;
  unsigned blocksize;
  int out_len;
  int idx = 0;

  //Get a new cipher envelope context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  //Initialize the cipher envelope as 256-bit CBC with ckey, iv, enc/dec mode
  EVP_CipherInit(ctx, EVP_aes_128_cbc(), ckey, ivec, should_encrypt);
  blocksize = EVP_CIPHER_CTX_block_size(ctx);
  cipher_buf = (unsigned char *) malloc(MAXDATASIZE + blocksize);

  while (1) {
    //Update cipher (Uses CBC mode EVP API)
    EVP_CipherUpdate(ctx, cipher_buf, &out_len, in_buf, size_in);
    memcpy(out_buf+idx, cipher_buf, out_len);
    idx += out_len;
    if (out_len <= MAXDATASIZE) { // EOF
      break;
    }
  }

  // Now cipher the final block and write it out.
  EVP_CipherFinal(ctx, cipher_buf, &out_len);
  memcpy(out_buf+idx, cipher_buf, out_len);
  *size_out = idx + out_len;

  // Free memory
  free(cipher_buf);
  EVP_CIPHER_CTX_free(ctx);
}
