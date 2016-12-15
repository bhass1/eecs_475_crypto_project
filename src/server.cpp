//EECS 475 Intro Crypto University of Michigan
// (c) Bill Hass 2016 - billhass@umich.edu
//
// Server implementation for various encryption schemes.
// Protocol:
//    '<type> <enc/dec> <length> <data>'
// <type> is CTR, CBC, TTE, EAT
// <enc/dec> is either DEC or ENC
// <length> is integer length of data less than 1024
// <data> is 
//
#include <stdio.h>
#include <cstring>
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
#include <chrono>
#include <thread>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define PORT "3490"  // the port users will be connecting to

#define MAXDATASIZE 1024
#define MAXHEADERSIZE 13//4+4+5 : "CBC ENC 1024 "

#define DEBUG 0
	

#define BACKLOG 10     // how many pending connections queue will hold

void enc_and_tag(int, unsigned char *, int, unsigned char *, int*, unsigned char *, unsigned char *);
void tag_128_aes_cbc(unsigned char *, int , unsigned char *, unsigned char *);
int enc_128_aes_cbc(int, unsigned char *, int, unsigned char *, int*, unsigned char *, unsigned char *);
int verify_tag_128(unsigned char *, unsigned char*);
int handle_new_connection(int);
int handle_msg(int, unsigned char* );

int printBytes(unsigned char* buf, int len){
  for(int i = 0; i < len; i++ ) {
    putc( isprint(buf[i]) ? buf[i] : '.' , stdout );
  }
  return 1;
}

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;
    while(waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}


// wrapper to get sockaddr based on IPv4 or IPv6
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//Set up a socket to listen on port PORT. When a client connects,
// call handle_new_connection to take care of talking with that client
int main(void)
{
    int sockfd, new_fd;  
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
    freeaddrinfo(servinfo); 

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    //REAP ALL DEAD PROCS
    sa.sa_handler = sigchld_handler; 
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }
    printf("server: waiting for connections...\n");

    // main accept() loop
    while(1) {  
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

//Handle new connection takes a socket descriptor and loops forever
//on it to handle each new incoming set of bytes.
//
//Handles recv bytes from client and passing the bytes on to handle_msg where
//they will be parsed and handled.
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
	return 1;
}

//Handle msg takes a socket descriptor (used for sending responses back
//to the client) and a buffer containing the packet to parse.
//
//The packet in buf is parsed and an action is taken based on the contents
//of that packet
int handle_msg(int sock, unsigned char* buf){
	std::string type, encdec, len, dat;
	unsigned char data[MAXDATASIZE];
	std::string msg = std::string((const char*)buf);
	std::stringstream ss(msg);
	ss >> type >> encdec >> len;
	DEBUG && std::cout << "msg: "<< msg << std::endl;
	DEBUG && std::cout << "type: "<< type << std::endl;
	DEBUG && std::cout << "encdec: "<< encdec << std::endl;

	int data_len = std::stoi(len);
	DEBUG && std::cout << "data_len: "<< data_len << std::endl;

	int hdr_len = type.length() + encdec.length() + len.length() + 3;
	memcpy(data, buf+hdr_len, data_len);
	DEBUG && std::cout << "data: "<<data<<std::endl;

	unsigned char out_buf[MAXDATASIZE];

	if(type.compare("CBC") == 0) {
		//Perform AES-CBC on data
	} else if(type.compare("CTR") == 0) {
		//Perform AES-CTR on data
		int out_buf_len = 0;
		enc_and_tag(encdec.compare("DEC") != 0, data, data_len, out_buf, &out_buf_len, (unsigned char *)"123456789", (unsigned char *)"123456789");
		if (send(sock, out_buf, out_buf_len, 0) == -1){ 
			perror("send");
			return 0;
		}
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
	} else if(type.compare("TAG") == 0) {
		//Perform message authentication
		if(encdec.compare("ENC") == 0) {
			tag_128_aes_cbc(data, data_len, out_buf, (unsigned char *)"123456789");
			out_buf[17] = '\0';
    			DEBUG && std::cout << "tag produced: "<< out_buf << std::endl;
			if (send(sock, out_buf, 16, 0) == -1){ 
				perror("send");
				return 0;
			}
		} else {
			unsigned char calc_tag[16], tag[16];
			unsigned char message[data_len-16];

			memcpy(tag, data, 16);
			memcpy(message, data+16, data_len-16);

			//calculate our own tag on the message
			tag_128_aes_cbc(message, data_len-16, calc_tag, (unsigned char *)"123456789");
    			DEBUG && std::cout << "--------------------" << std::endl;
    			DEBUG && std::cout << "Calculated the tag: ";
			DEBUG && printBytes(calc_tag,16);
    			DEBUG && std::cout << "\nReceived tag in msg: ";
			DEBUG && printBytes(tag,16);
    			DEBUG && std::cout << "\n--------------------"<< std::endl;
			//Verify the tags match
    			if(verify_tag_128(calc_tag, tag)){
				char* msg = (char*)"Tags match! Great success!";
    				memcpy(out_buf, msg, strlen(msg)+1);
    			} else {
    			    	char * msg = (char*)"ERROR, INVALID TAG";
    				memcpy(out_buf, msg, strlen(msg)+1);
    			}
			if (send(sock, out_buf, strlen((const char*)out_buf), 0) == -1){ 
				perror("send");
				return 0;
			}
		}
	} else {
		std::cout << "BAD PACKET TYPE! -- (" << type << ")"<<std::endl;
		return 0;
	}
	return 1;
}



/**
 * Implements encrypt and tag style authenticated encryption.
 * ckey : Key used for scheme
 * ivec : Initialization vector for scheme
 * should_encrypt : if 0 runs decryption on in_buf; else runs encryption on in_buf
 * out_buf : contains either tag||ciphertext or plaintext depending on should_encrypt
 */
void enc_and_tag(int should_encrypt, unsigned char *in_buf, int size_in, unsigned char *out_buf, int* return_len, unsigned char *ckey, unsigned char *ivec) {
  unsigned char ciphertext[MAXDATASIZE + 16];
  int cipher_len = 0;
  int status_flag;

  unsigned char in_tag[16], in_cipher[MAXDATASIZE];
  if(!should_encrypt) {
    //decryption mode - split off the tag
    memcpy(in_tag, in_buf, 16);
    memcpy(in_cipher, in_buf+16, size_in - 16);
    status_flag = enc_128_aes_cbc(should_encrypt, in_cipher, size_in-16, ciphertext, &cipher_len, ckey, ivec);
    DEBUG && std::cout << "plain len: "<< cipher_len << std::endl;
    DEBUG && std::cout << "plain : "<< ciphertext << std::endl;
    DEBUG && std::cout << "in_tag : "<< in_tag << std::endl;
  } else {
    status_flag = enc_128_aes_cbc(should_encrypt, in_buf, size_in, ciphertext, &cipher_len, ckey, ivec);
    DEBUG && std::cout << "cipher len: "<< cipher_len << std::endl;
    DEBUG && std::cout << "cipher : "<< ciphertext << std::endl;
  }

  //At this point ciphertext has cipher bytes if should_encrypt, else has plaintext bytes
  unsigned char tag[16];
  if(!should_encrypt) {
    tag_128_aes_cbc(ciphertext, cipher_len, tag, ckey);
    std::cout << "   tag : "<< tag << std::endl;

    if(verify_tag_128(in_tag, tag)){
    	memcpy(out_buf, ciphertext, cipher_len);
    	std::cout << "out_buf : "<< out_buf << std::endl;
    	*return_len = cipher_len;
    } else {
        char * err = (char*)"ERROR, INVALID TAG";
	int err_len = strlen(err);
    	memcpy(out_buf, err, err_len+1);
    	std::cout << "out_buf : "<< out_buf << std::endl;
    	*return_len = err_len;
    }
  } else {
    tag_128_aes_cbc(in_buf, size_in, tag, ckey);
    std::cout << "tag : "<< tag << std::endl;
    memcpy(out_buf, tag, 16);
    memcpy(out_buf+16, ciphertext, cipher_len);
    std::cout << "out_buf : "<< out_buf << std::endl;
    *return_len = cipher_len + 16;
  }
}

/**
 * Implements tag then encrypt style authenticated encryption.
 * ckey : Key used for scheme
 * ivec : Initialization vector for scheme
 * should_encrypt : if 0 runs decryption on in_buf; else runs encryption on in_buf
 * out_buf : contains either ciphertext or plaintext depending on should_encrypt
 */
void tag_then_enc(int should_encrypt, unsigned char *in_buf, int size_in, unsigned char *out_buf, int* return_len, unsigned char *ckey, unsigned char *ivec) {
  unsigned char ciphertext[MAXDATASIZE + 16];
  int cipher_len = 0;
  int status_flag;

  unsigned char in_tag[16], in_cipher[MAXDATASIZE];

  unsigned char tag[16];
  if(!should_encrypt) {
  } else {
    tag_128_aes_cbc(in_buf, size_in, tag, ckey);
    std::cout << "   tag : "<< tag << std::endl;
  }

  memcpy(ciphertext, tag, 16); //Put tag into front of buffer
  memcpy(ciphertext+16, in_buf, size_in); //Put message into back of buffer

  //At this point ciphertext has cipher bytes if should_encrypt, else has plaintext bytes
  if(!should_encrypt) {
  } else {
    status_flag = enc_128_aes_cbc(should_encrypt, ciphertext, size_in+16, out_buf, return_len, ckey, ivec);
    if(status_flag != 1) {
        unsigned char * err = (unsigned char*)"DECRYPT FAIL";
    	memcpy(out_buf, err, sizeof(err));
    	std::cout << "out_buf : "<< out_buf << std::endl;
    	*return_len = sizeof(err);
        return;
    }
  }
}

//Takes input buffer and size to produce tag given key
void tag_128_aes_cbc(unsigned char *in_buf, int size_in, unsigned char *tag, unsigned char *ckey) {
  //Get a new cipher envelope context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  //Initialize the cipher envelope as 128-bit ECB with ckey, iv
  unsigned char iv[16];
  memset(iv, '\0', 16);
  EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), nullptr, ckey, iv, 1);
  unsigned blocksize = EVP_CIPHER_CTX_block_size(ctx);
  unsigned char *cipher_buf = (unsigned char *) malloc(MAXDATASIZE); //just hold onto the tag
  int out_len;
  int idx = 0;
  //Update cipher (Uses EVP API)
  EVP_CipherUpdate(ctx, cipher_buf, &out_len, in_buf, size_in);
  if(out_len < 16){
  	memcpy(tag, cipher_buf, out_len);
	idx += out_len;
  } else {
  	memcpy(tag, cipher_buf, 16);
	idx = 0; //rewrite on call to Final
  }

  // Now cipher the final block and write it out.
  EVP_CipherFinal_ex(ctx, cipher_buf, &out_len);
  assert(out_len == blocksize);
  if(out_len < 16){
  	memcpy(tag+idx, cipher_buf, out_len);
  } else {
  	memcpy(tag, cipher_buf, 16);
  }
  // Free memory
  free(cipher_buf);
  EVP_CIPHER_CTX_free(ctx);
}

//Wrapper for libCrypto 128-bit aes cbc implementation
//should_encrypt if 0 will cause a decryption, otherwise will cause encryption
int enc_128_aes_cbc(int should_encrypt, unsigned  char *in_buf, int size_in, unsigned char *out_buf, int* size_out, unsigned char *ckey, unsigned char *ivec) {

  unsigned char *cipher_buf;
  unsigned blocksize;
  int out_len;
  int idx = 0;

  int err;

  //Get a new cipher envelope context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  //Initialize the cipher envelope as 256-bit CBC with ckey, iv, enc/dec mode
  EVP_CipherInit(ctx, EVP_aes_128_cbc(), ckey, ivec, should_encrypt);
  blocksize = EVP_CIPHER_CTX_block_size(ctx);
  cipher_buf = (unsigned char *) malloc(MAXDATASIZE + blocksize);

  //Update cipher (Uses CBC mode EVP API)
  err = EVP_CipherUpdate(ctx, cipher_buf, &out_len, in_buf, size_in);
  if(err != 1){
    return 0;
  }
  memcpy(out_buf+idx, cipher_buf, out_len);
  idx += out_len;

  // Now cipher the final block and write it out.
  err = EVP_CipherFinal(ctx, cipher_buf, &out_len);
  if(err != 1){
    return 0;
  }
  memcpy(out_buf+idx, cipher_buf, out_len);
  *size_out = idx + out_len;

  // Free memory
  free(cipher_buf);
  EVP_CIPHER_CTX_free(ctx);
}

//The canonical verifier.
//Verify tag takes two buffers, tag1 and tag2, to be compared.
//There is a 20ms sleep when the character is detected as matching
//which allows for a timing attack against this function.
int verify_tag_128(unsigned char * tag1, unsigned char * tag2){
  std::cout << "VERIFY:: ";
  printBytes(tag1, 16);
  std::cout << " =? ";
  printBytes(tag2, 16);
  std::cout << std::endl;
  for(int i = 0; i < 16; i++){
    DEBUG && std::cout << "VERIFY "<<i<<":: " << (int)tag1[i] << " =? "<<(int)tag2[i]<<std::endl;
    if((int)tag1[i] != (int)tag2[i]) {
      DEBUG && std::cout << "VERIFY:: [FAIL] " << std::endl;;
      return 0;
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  } 
  std::cout << "VERIFY:: [SUCCESS] ";
  return 1;
}

//Wrapper for libCrypto 128-bit aes ctr implementation
//should_encrypt if 0 will cause a decryption, otherwise will cause encryption
void enc_128_aes_ctr(int should_encrypt, unsigned  char *in_buf, int size_in, unsigned char *out_buf, int* size_out, unsigned char *ckey, unsigned char *ivec) {

  unsigned char *cipher_buf;
  unsigned blocksize;
  int out_len;
  int idx = 0;

  //Get a new cipher envelope context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  //Initialize the cipher envelope as 256-bit CBC with ckey, iv, enc/dec mode
  EVP_CipherInit(ctx, EVP_aes_128_ctr(), ckey, ivec, should_encrypt);
  blocksize = EVP_CIPHER_CTX_block_size(ctx);
  cipher_buf = (unsigned char *) malloc(MAXDATASIZE + blocksize);

    //Update cipher (Uses EVP API)
    EVP_CipherUpdate(ctx, cipher_buf, &out_len, in_buf, size_in);
    memcpy(out_buf+idx, cipher_buf, out_len);
    idx += out_len;

  // Now cipher the final block and write it out.
  EVP_CipherFinal(ctx, cipher_buf, &out_len);
  memcpy(out_buf+idx, cipher_buf, out_len);
  *size_out = idx + out_len;

  // Free memory
  free(cipher_buf);
  EVP_CIPHER_CTX_free(ctx);
}
