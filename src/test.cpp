//EECS 475 Intro Crypto University of Michigan
// Bill Hass, Nick Gaunt, 
// Myles Pollie, Robert Minnema
//
// Performs AES 256-bit CBC encryption on a file in 4096B chunks to produce
// a ciphertext file. Then it performs AES 256-bit CBC decryption on the 
// ciphertext file to produce a decyrpted text file.
//
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

void printBytes(unsigned char* buf, int len){
  for(int i = 0; i < len; i++ ) {
    putc( isprint(buf[i]) ? buf[i] : '.' , stdout );
  }
  return;
}

/**
 * Encrypt or decrypt, depending on flag 'should_encrypt'
 */
void en_de_crypt(int should_encrypt, FILE *ifp, FILE *ofp, unsigned char *ckey, unsigned char *ivec) {

  //Arbitrary BUFSIZE for chunking the target file.
  const unsigned BUFSIZE=4096;
  unsigned char *read_buf = (unsigned char*) malloc(BUFSIZE);
  unsigned char *cipher_buf;
  unsigned blocksize;
  int out_len;

  //Get a new cipher envelope context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  //Initialize the cipher envelope as 256-bit CBC with ckey, iv, enc/dec mode
  EVP_CipherInit(ctx, EVP_aes_256_cbc(), ckey, ivec, should_encrypt);
  blocksize = EVP_CIPHER_CTX_block_size(ctx);
  cipher_buf = (unsigned char *) malloc(BUFSIZE + blocksize);

  while (1) {
    //Read in data in BUFSIZE chunk
    int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
    //Update cipher (Uses CBC mode EVP API)
    EVP_CipherUpdate(ctx, cipher_buf, &out_len, read_buf, numRead);
    //Write cipher buffer to file and print to console
    fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
    printBytes(cipher_buf, out_len);
    if (numRead < BUFSIZE) { // EOF
      break;
    }
  }

  // Now cipher the final block and write it out.
  EVP_CipherFinal(ctx, cipher_buf, &out_len);
  fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
  printBytes(cipher_buf, out_len);
  std::cout << std::endl;

  // Free memory

  free(cipher_buf);
  free(read_buf);
  EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char *argv[])
{ 
  std::cout << "Hello Crypto." << std::endl;	

  unsigned char ckey[] = "thiskeyisverybad";
  unsigned char ivec[] = "dontusethisinput";
  FILE *fIN, *fOUT;

  // First encrypt the file
  fIN = fopen("plain.txt", "rb"); //File to be encrypted; plain text
  fOUT = fopen("ciphertext.txt", "wb"); //File to be written; cipher text

  std::cout << "Encrypting contents of plain.txt:" << std::endl;	
  en_de_crypt(TRUE, fIN, fOUT, ckey, ivec);

  fclose(fIN);
  fclose(fOUT);

  //Decrypt file now

  fIN = fopen("ciphertext.txt", "rb"); //File to be read; cipher text
  fOUT = fopen("decrypted.txt", "wb"); //File to be written; plain text

  std::cout << "Decrypting contents of ciphertext.txt:" << std::endl;	
  en_de_crypt(FALSE, fIN, fOUT, ckey, ivec);

  fclose(fIN);
  fclose(fOUT);

  return 0;
}

