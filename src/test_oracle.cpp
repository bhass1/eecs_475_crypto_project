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
#include <vector>
#include <istream>
#include <fstream>
#include <iterator>
#include <string>

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
void en_de_crypt(int should_encrypt, FILE *ifp, FILE *ofp, unsigned char *ckey, unsigned char *ivec, std::string mode) {

  //Arbitrary BUFSIZE for chunking the target file.
  const unsigned BUFSIZE=4096;
  unsigned char *read_buf = (unsigned char*) malloc(BUFSIZE);
  unsigned char *cipher_buf;
  unsigned blocksize;
  int out_len;

  //Get a new cipher envelope context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  //Initialize the cipher envelope as 256-bit CBC with ckey, iv, enc/dec mode
  EVP_CipherInit(ctx, EVP_aes_128_cbc(), ckey, ivec, should_encrypt);

  //Initialize the cipher envelope as 128-bit CBC with ckey, iv, enc/dec mode
  if(mode.compare("CTR") == 0) {
    EVP_CipherInit(ctx, EVP_aes_128_ctr(), ckey, ivec, should_encrypt);
  }
  else {
    EVP_CipherInit(ctx, EVP_aes_128_cbc(), ckey, ivec, should_encrypt);
  }

  blocksize = EVP_CIPHER_CTX_block_size(ctx);
  cipher_buf = (unsigned char *) malloc(BUFSIZE + blocksize);

  while (1) {
    //Read in data in BUFSIZE chunk
    int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
    std::cout << "numRead: " << numRead << std::endl;
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

int padding_oracle(std::vector<unsigned char> cipher, unsigned char *ckey, unsigned char *ivec){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const unsigned BUFSIZE=4096;
    unsigned char *read_buf = (unsigned char*) malloc(BUFSIZE);
    int out_len, err;
    unsigned blocksize;
    unsigned char *cipher_buf = (unsigned char *) malloc(BUFSIZE + blocksize);
    //Initialize the cipher envelope as 256-bit CBC with ckey, iv, enc/dec mode
    //cipher[31] = 0x2;
    EVP_CipherInit(ctx, EVP_aes_128_cbc(), ckey, ivec, 0);
    blocksize = EVP_CIPHER_CTX_block_size(ctx);


    //Update cipher (Uses CBC mode EVP API)
    
    std::cout << "cipher data: " << cipher.data() << std::endl;
    std::cout << "Size: " << cipher.size() << std::endl;
    //unsigned char s = 0x15;
    //cipher[44] = s;
    // printf("%x\n", cipher[30]);
    // printf("%x\n", cipher[31]);
    //cipher[30] = 0x02;
    //cipher[31] = 0x01;
    std::cout << std::endl;
    printf("%x\n", cipher[15]);
    //cipher[15] = cipher[15]^0x71^0x10;
    printf("%x\n", cipher[15]);
    
    //printf("%x\n", cipher[30]);
    //printf("%x\n", cipher[31]);
    err = EVP_CipherUpdate(ctx, cipher_buf, &out_len, cipher.data(), cipher.size());
    std::cout << "Output length: " << out_len << " err: " << err << std::endl;
    err = EVP_CipherFinal_ex(ctx, cipher_buf, &out_len);
    std::cout << "Output length: " << out_len << " err: " << err << std::endl;
    std::cout << "Cipher_buf " << cipher_buf << std::endl;
    EVP_CIPHER_CTX_free(ctx);
    return err;

}

void padding_oracle_attack(int should_encrypt, std::string filename, FILE *ofp, unsigned char *ckey, unsigned char *ivec){
  typedef std::istream_iterator<unsigned char> istream_iterator;
  std::ifstream file(filename);
  std::vector<unsigned char> cipher;
  file >> std::noskipws;
  std::copy(istream_iterator(file), istream_iterator(), std::back_inserter(cipher));
  int padding_start = 0;
  const unsigned BUFSIZE=4096;
  unsigned char temp;
  
  for(unsigned i = 0; i < 16; i++){
      temp = cipher[i];
      cipher[i]++;
    if(padding_oracle(cipher, ckey, ivec) == 0){
      padding_start = i;
      break;
    }
    cipher[i] = temp;
}

std::cout << "Padding starts at " << padding_start << std::endl;

  // unsigned char *read_buf = (unsigned char*) malloc(BUFSIZE);
  // unsigned char *cipher_buf;
  // unsigned blocksize;
  // int out_len;

  // fOut = fopen("paddingtesttemp.txt" , wb);
  // int paddingIndex = 0;
  // for(unsigned i = 0; i < blocksize; ++i){
  //     //Get a new cipher envelope context
  //   std::ofstream output("rotatingcipher.txt");
  //   std::ostream_iterator<std::string> output_iterator(output, "\n");
  //   std::copy(current.begin(), current.end(), output_iterator);
  //   fIn = fopen("rotatingcipher.txt");
  //   //Write cipher buffer to file and print to console
  //   fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);

  //   if(EVP_CipherUpdate(ctx, cipher_buf, &out_len, read_buf, numRead) == 0){
  //     std::cout<< "Padding Found" << std::endl;
  //     paddingIndex = i;
  //     break;
  //   }
  //   else{
  //     paddingIndex++;
  //   }
  // }

  // cout << "Padding length = " << blocksize - paddingIndex - 1 << std::endl;
  // for(unsigned i = paddingIndex; i < blocksize){
  //   for(unsigned j = 0; j < 255; j++){

  //   }
  // }
}

int main(int argc, char *argv[])
{ 
  std::cout << "Hello Crypto." << std::endl;	

  unsigned char ckey[] = "thiskeyisverybad";
  unsigned char ivec[] = "dontusethisinput";
  FILE *fIN, *fOUT;

  // First encrypt the file
  fIN = fopen("plain.txt", "rb"); //File to be encrypted; plain text
  fOUT = fopen("origcipher.txt", "wb"); //File to be written; cipher text

  std::cout << "Encrypting contents of plain.txt:" << std::endl;	
  en_de_crypt(TRUE, fIN, fOUT, ckey, ivec, "CBC");

  fclose(fIN);
  fclose(fOUT);

  //Decrypt file now
  fIN = fopen("origcipher.txt", "rb"); //File to be read; cipher text
  fOUT = fopen("decrypted.txt", "wb"); //File to be written; plain text
  padding_oracle_attack(0, "origcipher.txt", fOUT, ckey, ivec);

  std::cout << "Decrypting contents of ciphertext.txt:" << std::endl;	
  en_de_crypt(FALSE, fIN, fOUT, ckey, ivec, "CBC");

  fclose(fIN);
  fclose(fOUT);


  // // First encrypt the file
  // fIN = fopen("plain_1.txt", "rb"); //File to be encrypted; plain text
  // fOUT = fopen("ctr_cipher_1.txt", "wb"); //File to be written; cipher text
  // en_de_crypt(TRUE, fIN, fOUT, ckey, ivec, "CTR");
  // fclose(fIN);
  // fclose(fOUT);

  // fIN = fopen("plain_2.txt", "rb"); //File to be encrypted; plain text
  // fOUT = fopen("ctr_cipher_2.txt", "wb"); //File to be written; cipher text
  // en_de_crypt(TRUE, fIN, fOUT, ckey, ivec, "CTR");
  // fclose(fIN);
  // fclose(fOUT);


  return 0;
}

