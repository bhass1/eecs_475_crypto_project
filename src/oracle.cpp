//EECS 475 Intro Crypto University of Michigan
// Bill Hass
// Myles Pollie
//
// Performs padding oracle attack on AES 128-bit CBC encryption.
// Uses plain.txt for generating the cipher, then guesses plain-txt
// from the cipher by submitting queries to an oracle.
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
#include <algorithm>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define DEBUG 1

#define BLOCKSIZE 16
#define BUFSIZE 4096 

int find_padding(unsigned char *, std::vector<unsigned char>);
std::vector<unsigned char> makeV1(int);
std::vector<unsigned char> makeV3(int, std::vector<unsigned char>, int);
std::vector<unsigned char> blockCracker(std::vector<unsigned char> iveccipher, int b);

unsigned char ckey[] = "1122334455667788";
unsigned char ivec[] = "llmmnnooppqqrrss";

int printBytes(unsigned char* buf, int len){
  for(int i = 0; i < len; i++ ) {
    putc( isprint(buf[i]) ? buf[i] : '.' , stdout );
  }
  return 0;
}

/**
 * Encrypt or decrypt, depending on flag 'should_encrypt'
 */
void en_de_crypt(int should_encrypt, FILE *ifp, FILE *ofp, unsigned char *ckey, unsigned char *ivec, std::string mode) {
  unsigned char *read_buf = (unsigned char*) malloc(BUFSIZE);
  unsigned char *cipher_buf;
  unsigned blocksize;
  int out_len;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
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
    DEBUG && std::cout << "numRead: " << numRead << std::endl;
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

//Decrypt function that returns 0 if there was a decryption error
int padding_oracle(unsigned char* ivec, std::vector<unsigned char> cipher){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *read_buf = (unsigned char*) malloc(BUFSIZE);
    int out_len, err;
    unsigned char *cipher_buf = (unsigned char *) malloc(BUFSIZE + BLOCKSIZE);
    EVP_CipherInit(ctx, EVP_aes_128_cbc(), ckey, ivec, 0);
    err = EVP_CipherUpdate(ctx, cipher_buf, &out_len, cipher.data(), cipher.size());
    //EVP_CIPHERFINAL_ex() will set err to 0 if decryption fails meaning there is a padding error
    err = EVP_CipherFinal_ex(ctx, cipher_buf, &out_len);
    EVP_CIPHER_CTX_free(ctx);
    return err;
}

void padding_oracle_attack(int should_encrypt, std::string filename, FILE *ofp){
  //Read in the ciphertext
  typedef std::istream_iterator<unsigned char> istream_iterator;
  std::ifstream file(filename);
  std::vector<unsigned char> cipher;
  file >> std::noskipws;
  std::copy(istream_iterator(file), istream_iterator(), std::back_inserter(cipher));

  std::cout << "CipherSize: " << cipher.size() << std::endl;

  //Find padding
  int pad_start = find_padding(ivec, cipher);
  //Find value that the last block of plaintext is padded with
  int b = BLOCKSIZE-(pad_start % BLOCKSIZE);// - pad_start;

  //Get the number of blocks in the ciphertext
  int cipherBlocks = (cipher.size() / BLOCKSIZE);
  std::vector<unsigned char> iveccipher((cipherBlocks+1)*BLOCKSIZE);
  //Insert initialization vector into iveccipher
  //Allows for the first block of the message to be decrypted
  for(int i = 0; i < BLOCKSIZE; i++){
    iveccipher.at(i) = ivec[i];
  }
  //Read rest of ciphertext into iveccipher
  for(int i = 0; i < cipher.size(); i++){
    iveccipher.at(i+BLOCKSIZE) = cipher.at(i);
  }

  std::vector<unsigned char> plaintext, guess;
  for(int z = cipherBlocks; z > 0; z--){
    plaintext = blockCracker(iveccipher, b);

    //add plaintext to our guess
    for(int i = 0; i < plaintext.size(); i++){
      //Put in backwards so we can just swap at the end
      unsigned char c = *plaintext.end();
      guess.push_back((plaintext.at(plaintext.size()-1-i)));  
    }

    //Now strip off the last cipher set padding to 0 and repeat
    iveccipher.erase(iveccipher.end()-BLOCKSIZE, iveccipher.end());
    b = 0;
  }
  //Reverse our plaintext vector as they were added backwards
  std::reverse(guess.begin(), guess.end());
  std::cout << "Plaintext Guess:";
  std::cout << std::endl;
  std::cout << std::endl;
  printBytes(guess.data(), guess.size());
  std::cout << std::endl;
  std::cout << std::endl;
}

// Returns the index where the padding starts in the ciphertext
int find_padding(unsigned char * ivec, std::vector<unsigned char> cipher){
  unsigned char temp;
  if(cipher.size() <= BLOCKSIZE){ //Handle finding padding on single block cipher
    for(int i = 0; i < BLOCKSIZE; i++){
      temp = ivec[i];
      ivec[i]++; //Change IV block at i
      //Now use padding oracle with modified cipher_block
      if(padding_oracle(ivec, cipher) == 0){
          //Padding error detected
          ivec[i] = temp;
          return  i; //0, 1, 2, etc.
      }
      ivec[i] = temp;
    }
  } else {
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
}

//Takes IV||Ciphertext and padding b then cracks the last block of the ciphertext
std::vector<unsigned char> blockCracker(std::vector<unsigned char> iveccipher, int b){
  int pad_start = -1*(b - BLOCKSIZE);
  //our guess is size of block minus pad
  std::vector<unsigned char> plaintext;

  if(iveccipher.size() <= BLOCKSIZE){
    //nothing to crack, ivec is sent over wire so we know it
    return iveccipher; 
  }
  if(b == 0x10){
    //nothing to crack, full padding block, return empty plaintext
    return plaintext;
  }

  for(unsigned k = 16; k > 0; k--){
    //Save iveccipher in tempCipher to reset iveccipher if padding oracle returns error
    std::vector<unsigned char> tempCipher = iveccipher;
    DEBUG && std::cout << "k= "<<k<<" Padding starts at " << pad_start << " b = "<< b << std::endl;
    std::vector<unsigned char> v1(BLOCKSIZE), v3(BLOCKSIZE);

    //Generate vector that cahnges padding from plaintext block to 0's
    v1 = makeV1(b);

    DEBUG && std::cout << "v1: ";
    DEBUG && printBytes(v1.data(), v1.size());
    DEBUG && std::cout << std::endl;

    //Begin looping to find value of i (which tells us plaintext byte at index)
    for(unsigned i = 0; i < 256; ++i){
      //Generate vector to XOR iveccipher's values with
      v3 = makeV3(b, v1, i);
      //Now iveccipher with v3
      for(unsigned j = iveccipher.size()-2*BLOCKSIZE; j < iveccipher.size() - BLOCKSIZE; ++j){
        iveccipher.at(j) = v3.at(j-iveccipher.size()+2*BLOCKSIZE)^iveccipher.at(j);
      }

      //Process iveccipher into uchar* IV and vector<uchar> cipher
      unsigned char ivec[BLOCKSIZE];
      memcpy(ivec, iveccipher.data(), BLOCKSIZE);
      std::vector<unsigned char> cipher(iveccipher.size()-BLOCKSIZE);
      for(int j = 0; j < iveccipher.size() - BLOCKSIZE; j++){
        cipher.at(j) = iveccipher.at(j+BLOCKSIZE);
      }

      if(padding_oracle(ivec, cipher)){ //If true, found plaintext character
        //Compute B and insert it into plaintext vector
        unsigned char B = (unsigned char)(b+1)^(unsigned char)i;
        DEBUG && std::cout << "B: " << B << std::endl;
        plaintext.insert(plaintext.begin(),B);
        pad_start--;    //decrement padding start
        b++;            //increment b
        break;
      }
      else{ //Padding oracle failed. Reset iveccipher to original and try another value of i
        iveccipher = tempCipher;
      }
    }
    if(pad_start == 0){
      DEBUG && std::cout << "Plaintext Block: ";
      DEBUG && printBytes(plaintext.data(), plaintext.size());
      DEBUG && std::cout<<std::endl;
      break;
    }
  }
  //Return decrypted plaintext block
  return plaintext;
}

std::vector<unsigned char> makeV1(int b){
  std::vector<unsigned char> v1(BLOCKSIZE);
  int pad_start = -1*(b - BLOCKSIZE);
    for(int i = 0; i < pad_start; ++i){ //Fill 0's up to padding
      v1.at(i) = (unsigned char)0x00;
    }
    for(int i = pad_start; i < BLOCKSIZE; ++i){ //Fill b padding bytes with value b
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
  std::cout << std::endl;
  en_de_crypt(FALSE, fIN, fOUT, ckey, ivec, "CBC");
  std::cout << std::endl;

  fclose(fIN);
  fclose(fOUT);
  return 0;
}

