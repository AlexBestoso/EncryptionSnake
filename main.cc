#include <stdio.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

using namespace std;

#include "encryptionSnake.class.h"

void printSectionBanner(string message){
	printf("\n------------------------------------\n\t%s\n------------------------------------\n", message.c_str());
}

int main(void){
	EncryptionSnake encryptionSnake;
	string hash = "";
	string plaintext = "";
	string ciphertext = "";
	size_t cipherLen = 0;
	string msg = "";

	/*
	 * Test SHA256
	 * */
	printSectionBanner("Testing SHA256. Message : 'aaa'"); 
	hash = encryptionSnake.sha256("aaa", false);	
	if(encryptionSnake.didFail()){
		printf("Failure!\n");
		encryptionSnake.printError();
		return 1;
	}
	printf("Hash : %s\n", hash.c_str());

	/*
	 * Test AES 256 CBC
	 * */
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

	/*
	 * Test RSA Key generation to files.
	 * */
	printSectionBanner("Testing RSA Key Generation to file, PEM.");
	encryptionSnake.generateRsaKeyPairToFile(4096, false, "./PublicKey.RSA.PEM", "./PrivateKey.RSA.PEM", "MagicBanana123###");
	if(encryptionSnake.didFail()){
		printf("Keygen failure. No other error means file IO error.\n");
		encryptionSnake.printError();
		unlink("./PublicKey.RSA.PEM");unlink("./PrivateKey.RSA.PEM");
		return 1;
	}
	printf("Success! fetching private key from file.\n");
	msg = encryptionSnake.fetchRsaKeyFromFile(true, false, true, "./PrivateKey.RSA.PEM", "MagicBanana123###");
	if(encryptionSnake.didFail()){
		printf("Failed to fetch private key from file.\n");
		encryptionSnake.printError();
		printf("Deleteing generated files.\n");
		unlink("./PublicKey.RSA.PEM");unlink("./PrivateKey.RSA.PEM");
                return 1;
	}
	printf("Read the following private key: \n%s\n", msg.c_str());
	printf("fetching public key from file.\n");
        msg = encryptionSnake.fetchRsaKeyFromFile(false, false, true, "./PublicKey.RSA.PEM", "");
        if(encryptionSnake.didFail()){
                printf("Failed to fetch public key from file.\n");
                encryptionSnake.printError();
                printf("Deleteing generated files.\n");
                unlink("./PublicKey.RSA.PEM");unlink("./PrivateKey.RSA.PEM");
                return 1;
        }
	printf("Read the following public key: \n%s\n", msg.c_str());

	printf("Testing RSA encryption with public key:\n");
	encryptionSnake.fetchRsaKeyFromFile(false, false, false, "./PublicKey.RSA.PEM", "");
	if(encryptionSnake.didFail()){
		printf("Failed to load public key into usable memory.\n");
		encryptionSnake.printError();
		printf("Cleaning up.\n");
                unlink("./PublicKey.RSA.PEM");unlink("./PrivateKey.RSA.PEM");
		return 1;
	}
		msg = "What if we had a massive hotdog, right. And then we just dropped it on our enemies?";
		msg = encryptionSnake.rsa(true, msg, msg.length());
		if(encryptionSnake.didFail()){
			printf("Failed to encipher message.\n");
			encryptionSnake.printError();
			encryptionSnake.cleanOutPublicKey();
			unlink("./PublicKey.RSA.PEM");unlink("./PrivateKey.RSA.PEM");
			return 1;
		}
		cipherLen = encryptionSnake.getResultLen();
		printf("=== RSA Encryption Results\n%s\n=== RSA Encryption End\n", msg.c_str());
	encryptionSnake.cleanOutPublicKey();
	
	printf("Testing RSA decryption with private key.\n");
	encryptionSnake.fetchRsaKeyFromFile(true, false, false, "./PrivateKey.RSA.PEM", "MagicBanana123###");
	if(encryptionSnake.didFail()){
                printf("Failed to load private key into usable memory.\n");
                encryptionSnake.printError();
                printf("Cleaning up.\n");
                unlink("./PublicKey.RSA.PEM");unlink("./PrivateKey.RSA.PEM");
                return 1;
        }
		msg = encryptionSnake.rsa(false, msg, cipherLen);
                if(encryptionSnake.didFail()){
                        printf("Failed to decipher message.\n");
                        encryptionSnake.printError();
                        encryptionSnake.cleanOutPrivateKey();
                        unlink("./PublicKey.RSA.PEM");unlink("./PrivateKey.RSA.PEM");
                        return 1;
                }
                printf("=== RSA Decryption Results\n%s\n=== RSA Decryption End\n", msg.c_str());
        encryptionSnake.cleanOutPrivateKey();

	printf("Removing sample key files\n");
	unlink("./PublicKey.RSA.PEM");unlink("./PrivateKey.RSA.PEM");

	return 0;
}
