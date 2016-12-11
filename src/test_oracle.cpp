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
#include <deque>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define BLOCKSIZE 16
#define BUFSIZE 4096 

int find_padding(unsigned char *, std::vector<unsigned char>);
std::vector<unsigned char> makeV1(int);
std::vector<unsigned char> makeV3(int, std::vector<unsigned char>, int);

unsigned char ckey[] = "1122334455667788";
unsigned char ivec[] = "llmmnnooppqqrrss";

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

int padding_oracle(unsigned char* ivec, std::vector<unsigned char> cipher){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *read_buf = (unsigned char*) malloc(BUFSIZE);
    int out_len, err;
    unsigned char *cipher_buf = (unsigned char *) malloc(BUFSIZE + BLOCKSIZE);
    EVP_CipherInit(ctx, EVP_aes_128_cbc(), ckey, ivec, 0);
    err = EVP_CipherUpdate(ctx, cipher_buf, &out_len, cipher.data(), cipher.size());
    err = EVP_CipherFinal_ex(ctx, cipher_buf, &out_len);
    EVP_CIPHER_CTX_free(ctx);
    return err;
}

void padding_oracle_attack(int should_encrypt, std::string filename, FILE *ofp){
  typedef std::istream_iterator<unsigned char> istream_iterator;
  std::ifstream file(filename);
  std::vector<unsigned char> cipher;
  file >> std::noskipws;
  std::copy(istream_iterator(file), istream_iterator(), std::back_inserter(cipher));
  unsigned char ivec[] = "llmmnnooppqqrrss";

  //Scan through cipher to see if changing a byte causes padding error
  std::cout << "CipherSize: " << cipher.size() << std::endl;

  int pad_start = find_padding(ivec, cipher);
  int b = BLOCKSIZE - pad_start;

  //our first guess is size of block minus pad
  std::vector<unsigned char> plaintext(BLOCKSIZE - b); 

  for(unsigned k = 16; k > 0; k--){
    std::vector<unsigned char> tempCipher = cipher;
    std::cout << "k= "<<k<<" Padding starts at " << pad_start << " b = "<< b << std::endl;
    std::vector<unsigned char> v1(BLOCKSIZE), v3(BLOCKSIZE);

    v1 = makeV1(b);

    std::cout << "v1: ";
    printBytes(v1.data(), v1.size());
    std::cout << std::endl;/* << "v2: ";
    printBytes(v2.data(), v2.size());
    std::cout << std::endl;*/

    //Begin looping to find value of i (which tells us plaintext byte at index)
    for(unsigned i = 0; i < 256; ++i){
      v3 = makeV3(b, v1, i);

      for(unsigned j = 0; j < BLOCKSIZE; ++j){
        cipher.at(j) = v3.at(j)^cipher.at(j);
      }

      unsigned char B;
      if(padding_oracle(ivec, cipher)){
        B = (unsigned char)(b+1)^(unsigned char)i;
        std::cout << "B: " << B;
        std::cout << std::endl;
        plaintext.insert(plaintext.begin(),B);
        pad_start--;
        b++;
        break;
      }
      else{
        cipher = tempCipher;
      }
    }
    if(pad_start == 0){
      std::cout << "Plaintext: ";
      printBytes(plaintext.data(), plaintext.size());
      std::cout<<std::endl;
      break;
    }
  }
}


// Returns the index where the padding starts in the ciphertext
int find_padding(unsigned char * ivec, std::vector<unsigned char> cipher){
  unsigned char temp;
  for(int i = cipher.size()-(2*BLOCKSIZE); i < cipher.size()-BLOCKSIZE; i++){
    temp = cipher.at(i);
    cipher.at(i)++; //Change cipher block at i
    //Now use padding oracle with modified cipher_block
    if(padding_oracle(ivec, cipher) == 0){
        //Padding error detected
        return  i; //0, 1, 2, etc.
    }
    cipher.at(i) = temp;
  }
}

std::vector<unsigned char> makeV1(int b){
  std::vector<unsigned char> v1(BLOCKSIZE);
  int pad_start = -1*(b - BLOCKSIZE);
    for(int i = 0; i < pad_start; ++i){ //Fill 0's up to padding
      v1.at(i) = (unsigned char)0x00;
    }
    for(int i = pad_start; i < BLOCKSIZE; ++i){ //Fill b padding bytes
      v1.at(i) = (unsigned char)b;
    }
  return v1;
}


std::vector<unsigned char> makeV3(int b, std::vector<unsigned char>v1, int guess){
    int pad_start = -1*(b - BLOCKSIZE);
    std::vector<unsigned char> v2(BLOCKSIZE), v3(BLOCKSIZE);
    for(unsigned i = 0; i < pad_start - 1; ++i){ //Pre-fill with 0's
      v2.at(i) = (unsigned char)(0x00);
    }
    v2.at(pad_start-1) = (unsigned char) guess; //Add the guess
    for(unsigned i = pad_start; i < BLOCKSIZE; ++i){
      v2.at(i) = (unsigned char) (b+1); //Post-fill with b+1 padding bytes
    }      
    for(unsigned j = 0; j < BLOCKSIZE; j++){ 
      v3.at(j) = v1.at(j)^v2.at(j);//Compute V3
    }
    return v3;
}

int main(int argc, char *argv[])
{ 
  std::cout << "Hello Crypto." << std::endl;	

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
  padding_oracle_attack(0, "origcipher.txt", fOUT);

  std::cout << "Decrypting contents of ciphertext.txt:" << std::endl;	
  en_de_crypt(FALSE, fIN, fOUT, ckey, ivec, "CBC");

  fclose(fIN);
  fclose(fOUT);
  return 0;
}

