#include <stdio.h>
#include <string>
#include <string.h>

using namespace std;

#include "encryptionSnake.class.h"

void printSectionBanner(string message){
	printf("------------------------------------\n\t%s\n------------------------------------\n", message.c_str());
}

int main(void){
	EncryptionSnake encryptionSnake;
	string hash = "";
	string plaintext = "";
	string ciphertext = "";
	size_t cipherLen = 0;
	string msg = "";

	printSectionBanner("Testing SHA256. Message : 'aaa'"); 
	hash = encryptionSnake.sha256("aaa", false);	
	if(encryptionSnake.didFail()){
		printf("Failure!\n");
		encryptionSnake.printError();
		return 1;
	}
	printf("Hash : %s\n", hash.c_str());

	printSectionBanner("Testing AES 256 CBC. Message : 'What is a banana? Why do you ask me these questions?'");
	unsigned char key[32] = {
		0x34, 0x23, 0x00, 0x6d, 0xbb, 0xaa, 0x63, 0x32,
		0xff, 0x26, 0x52, 0xfb, 0xff, 0x12, 0x9f, 0x5d,
		0xaa, 0xbc, 0x33, 0x33, 0x6e, 0xee, 0xac, 0x11,
		0x99, 0x31, 0x33, 0x71, 0x01, 0xde, 0xad, 0xf0
	};
	unsigned char iv[16]{
		0xfb, 0xbf, 0x9a, 0x2a,
		0xab, 0x14, 0xa6, 0x0d,
		0xca, 0x47, 0x0c, 0x6e,
		0xe7, 0x63, 0x43, 0x63,
	};
	msg = "What is a banana? Why do you ask me these questions?";
	ciphertext = encryptionSnake.aes256cbc(true, msg, msg.length(), key, iv);
	cipherLen = encryptionSnake.getResultLen();
	if(encryptionSnake.didFail()){
		printf("Failure\n");
		encryptionSnake.printError();
		return 1;
	}
	printf("Cipher Text Len : %ld\n", (long)cipherLen);
	printf("=== Cipher text start\n%s\n=== Cipher text end\n", ciphertext.c_str());
	
	plaintext = encryptionSnake.aes256cbc(false, ciphertext, cipherLen, key, iv);
	if(encryptionSnake.didFail()){
		printf("Failure\n");
		encryptionSnake.printError();
		return 1;
	}
	printf("=== Plain text start\n%s\n=== Plain text end\n", plaintext.c_str());


	return 0;
}
