#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

class EncryptionSnake{
	private:
		/*
		 * Message Digest Variables and functions
		 * */
		EVP_MD_CTX *mdCtx = NULL;

		EVP_MD *_sha256 = NULL;
		void freeSha256(void){
			EVP_MD_free(_sha256);
			EVP_MD_CTX_free(mdCtx);
		}

		/*
		 * Cipher Variables and functions
		 * */
		EVP_CIPHER_CTX * cipherCtx = NULL;
		
		EVP_CIPHER *_aes256cbc = NULL;
		void freeAes256Cbc(void){
			EVP_CIPHER_free(_aes256cbc);
			EVP_CIPHER_CTX_free(cipherCtx);
		}

		/*
		 * Misclanious variables and functions
		 * */
		bool failed = false;
		size_t resultLen = 0;

		string binToStr(string val){
			const char convRay[16] = {
				'0', '1', '2', '3', '4', '5', '6',
				'7', '8', '9', 'A', 'B', 'C', 'D', 
				'E', 'F'
			};
			
			string ret = "";
        	        for(int i=0; i<val.length(); i++){
				char b = val[i];
				int indexA = (b>>4)&0xf;
				int indexB = b&0xf;
				ret = ret + convRay[indexA] + convRay[indexB];
        	        }
			return ret;
		}
	public:
		size_t getResultLen(){
			return resultLen;
		}
		bool didFail(void){
			return failed;
		}

		void printError(void){
			if(failed)
				ERR_print_errors_fp(stderr);
		}

		string aes256cbc(bool encrypt, string state, size_t stateLen, unsigned char key[32], unsigned char iv[16]){
			failed = false;
			string ret = "";
			unsigned char *output = NULL;
			int len = 0;
			
			cipherCtx = EVP_CIPHER_CTX_new();
			if(cipherCtx == NULL){
				failed = true;
				freeAes256Cbc();
				return "";
			}

			_aes256cbc = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
			if(_aes256cbc == NULL){
				failed = true;
				freeAes256Cbc();
				return "";
			}

			if(encrypt){
				output = new unsigned char[stateLen+16];
				if(!EVP_EncryptInit_ex(cipherCtx, _aes256cbc, NULL, key, iv)){
					failed = true;
					freeAes256Cbc();
					return "";
				}

				if(!EVP_EncryptUpdate(cipherCtx, output, &len, (unsigned char *)state.c_str(), stateLen)){
					failed = true;
					freeAes256Cbc();
					return "";
				}
				resultLen = len;

				if(!EVP_EncryptFinal_ex(cipherCtx, output+len, &len)){
					failed = true;
					freeAes256Cbc();
					return "";
				}
				resultLen += len;

				for(int i=0; i<resultLen; i++){
					ret += output[i];
				}
			}else{
				output = new unsigned char[stateLen];
				if(!EVP_DecryptInit_ex(cipherCtx, _aes256cbc, NULL, key, iv)){
                                        failed = true;
                                        freeAes256Cbc();
                                        return "";
                                }
	
                                if(!EVP_DecryptUpdate(cipherCtx, output, &len, (unsigned char *)state.c_str(), stateLen)){
                                        failed = true;
                                        freeAes256Cbc();
                                        return "";
                                }
				resultLen = len;

                                if(!EVP_DecryptFinal_ex(cipherCtx, output+len, &len)){
                                        failed = true;
                                        freeAes256Cbc();
                                        return "";
                                }
				resultLen += len;

				for(int i=0; i<resultLen; i++){
					ret += output[i];
				}
			}
			delete[] output;
			freeAes256Cbc();	

			return ret;
		}

		string sha256(string msg, bool binaryOutput){
			failed = false;
			string digest = "";
			mdCtx = EVP_MD_CTX_new();
			if(mdCtx == NULL){
				failed = true;
				freeSha256();
				return "";	
			}

			_sha256 = EVP_MD_fetch(NULL, "SHA2-256", NULL);
			if(_sha256 == NULL){
				failed = true;
        	                freeSha256();
        	                return "";
			}

			if(!EVP_DigestInit_ex(mdCtx, _sha256, NULL)){
				failed = true;
        	                freeSha256();
        	                return "";
			}

	
			if(!EVP_DigestUpdate(mdCtx, (unsigned char *)msg.c_str(), msg.length())){
				failed = true;
				freeSha256();
				return "";
			}

			unsigned int len = 0;
	    		unsigned char *outdigest = NULL;
	
			outdigest = (unsigned char *)OPENSSL_malloc(EVP_MD_get_size(_sha256));
			if(outdigest == NULL){
				failed = true;
	                        freeSha256();
	                        return "";
			}

			if(!EVP_DigestFinal_ex(mdCtx, outdigest, &len)){
				OPENSSL_free(outdigest);
				failed = true;
	                        freeSha256();
	                        return "";
			}

			//BIO_dump_fp(stdout, outdigest, len);  /*Debug line*/

			digest = (const char *)outdigest;
			OPENSSL_free(outdigest);
			freeSha256();
			
			if(!binaryOutput){
				return binToStr(digest);
			}
			return digest;
		}	
};
