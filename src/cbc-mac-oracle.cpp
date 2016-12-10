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
#include <chrono>
#include <thread>
#include <openssl/evp.h>
#include <openssl/aes.h>

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

void cbc_mac_var_length(int sockfd, unsigned char * forged_tag) {
	unsigned char out_buf[MAXDATASIZE + MAXHEADERSIZE + 1]
	unsigned char in_buf[MAXDATASIZE + MAXHEADERSIZE + 1]
	int out_len;
	int numbytes = 16;
	unsigned char tag1[17], tag2[17]
	unsigned char m1[17] = "abcdefghijklmnop";
	unsigned char m2[17] = "1234567890123456";
	
	memcpy(in_buf, m1, 16);
	out_len = packetize(out_buf, "TAG", "ENC", 16, (unsigned char *)in_buf);
	send(sockfd, out_buf, out_len, 0);
	if ((numbytes = recv(sockfd, out_buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
		perror("recv");
		exit(1);
	}
	memcpy(tag1, out_buf, 16);
	
	memcpy(in_buf, m2, 16);
	out_len = packetize(out_buf, "TAG", "ENC", 16, (unsigned char *) in_buf);
	send(sockfd, out_buf, out_len, 0);
	if ((numbytes = recv(sockfd, out_buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
		perror("recv");
		exit(1);
	}
	memcpy(tag2, out_buf, 16);
	
	// tag2||m1||m2^tag1 should verify
	unsigned char mnew[33];
	memcpy(mnew, m1, 16);
	for (int i = 16; i < 32; i++) {
		mnew[i] = m2[i - 16] ^ tag1[i - 16];
	}
	mnew[32] = '\0';
	memcpy(in_buf, tag2, 16);
	memcpy(in_buf + 16, mnew, 32);
	out_len = packetize(out_buf, "TAG", "DEC", 48, (unsigned char *) in_buf);
	send(sockfd, out_buf, out_len, 0);
	if ((numbytes = recv(sockfd, out_buf, MAXDATASIZE+MAXHEADERSIZE, 0)) == -1) {
		perror("recv");
		exit(1);
	}
}