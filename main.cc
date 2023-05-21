#include <stdio.h>
#include <string>
#include <string.h>

using namespace std;

#include "encryptionSnake.class.h"

int main(void){
	EncryptionSnake encryptionSnake;
	
	string hash = encryptionSnake.sha256("aaa", false);	
	if(encryptionSnake.didFail()){
		printf("Failure!\n");
		encryptionSnake.printError();
		return 1;
	}
	printf("Hash : %s\n", hash.c_str());
	return 0;
}
