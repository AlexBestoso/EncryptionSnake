#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/rand.h>

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
			_sha256 = NULL;
			mdCtx = NULL;
		}

		/*
		 * Cipher Variables and functions
		 * */
		EVP_CIPHER_CTX * cipherCtx = NULL;
		EVP_CIPHER_CTX * cipherCtrECtx = NULL;
		EVP_CIPHER_CTX * cipherCtrDCtx = NULL;
		
		EVP_CIPHER *_aes256cbc = NULL;
		void freeAes256Cbc(void){
			EVP_CIPHER_free(_aes256cbc);
			EVP_CIPHER_CTX_free(cipherCtx);
			_aes256cbc = NULL;
			cipherCtx = NULL;
		}

		EVP_CIPHER *_aes256ctr_encrypt = NULL;
		EVP_CIPHER *_aes256ctr_decrypt = NULL;
		void freeAes256Ctr(bool encrypt){
			if(encrypt){
				EVP_CIPHER_CTX_free(cipherCtrECtx);
				cipherCtrECtx = NULL;
				EVP_CIPHER_free(_aes256ctr_encrypt);
				_aes256ctr_encrypt = NULL;
			}else{
				EVP_CIPHER_CTX_free(cipherCtrDCtx);
				cipherCtrDCtx = NULL;
				EVP_CIPHER_free(_aes256ctr_decrypt);
				_aes256ctr_decrypt = NULL;
			}
                }


		/*
		 * Public Key variables and functions.
		 * */
		EVP_PKEY *keypair = NULL;
		EVP_PKEY *publicKey = NULL;
		EVP_PKEY *privateKey = NULL;
		OSSL_ENCODER_CTX *encoderCtx = NULL;
		OSSL_DECODER_CTX *decoderCtx = NULL;
		EVP_PKEY_CTX *pkeyCtx = NULL;

		void generateRSAKeyFree(void){
			EVP_PKEY_free(keypair);
			OSSL_ENCODER_CTX_free(encoderCtx);
			keypair = NULL;
			encoderCtx = NULL;
		}
		void fetchRsaKeyFromFileFree(void){
			EVP_PKEY_free(privateKey);
			EVP_PKEY_free(publicKey);
			OSSL_DECODER_CTX_free(decoderCtx);
			privateKey = NULL;
			publicKey = NULL;
			decoderCtx = NULL;
		}

		void fetchRsaKeyFromStringFree(void){
			fetchRsaKeyFromFileFree();
		}

		void rsaFree(void){
			EVP_PKEY_CTX_free(pkeyCtx);
			pkeyCtx = NULL;
		}


		/*
		 * Misclanious variables and functions
		 * */

		string convertEvpPkeyToString(bool isPrivateKey, bool useDER, EVP_PKEY *key, string keyPassword){
			unsigned char *output = NULL;
			size_t outputSize = 0;
			string ret = "";
			string format = "PEM";
			if(useDER){
				format = "DER";
			}
			if(isPrivateKey){
				encoderCtx = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, format.c_str(), NULL, NULL);
				if(encoderCtx == NULL){
					return "";
				}

				if(keyPassword != ""){
                                        OSSL_ENCODER_CTX_set_passphrase(encoderCtx, (const unsigned char *)keyPassword.c_str(), keyPassword.length());
                                }

				if(!OSSL_ENCODER_to_data(encoderCtx, &output, &outputSize)){
					OSSL_ENCODER_CTX_free(encoderCtx);
					OPENSSL_free(output);
					return "";
				}

				ret = (const char *)output;
				resultLen = outputSize;
				// Ensure no corrupt/leaked bytes are involved.
				if(ret.length() != outputSize){
					string newRet = "";
					for(int i=0; i<outputSize; i++){
						newRet = newRet + (char)output[i];
					}
                                	OSSL_ENCODER_CTX_free(encoderCtx);
                                	OPENSSL_free(output);
					return newRet;
				}
				OSSL_ENCODER_CTX_free(encoderCtx);
                                OPENSSL_free(output);
			}else{
				encoderCtx = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, format.c_str(), NULL, NULL);
                                if(encoderCtx == NULL){
                                        return "";
                                }

                                unsigned char *output = NULL;
                                size_t outputSize = 0;
                                if(!OSSL_ENCODER_to_data(encoderCtx, &output, &outputSize)){
                                        OSSL_ENCODER_CTX_free(encoderCtx);
                                        OPENSSL_free(output);
                                        return "";
                                }

                                ret = (const char *)output;
				resultLen = outputSize;
				// Ensure no corrupt/leaked bytes are involved.
				if(ret.length() != outputSize){
					string newRet = "";
					for(int i=0; i<outputSize; i++){
						newRet = newRet + (char)output[i];
					}
                                	OSSL_ENCODER_CTX_free(encoderCtx);
                                	OPENSSL_free(output);
					return newRet;
				}
                                OSSL_ENCODER_CTX_free(encoderCtx);
                                OPENSSL_free(output);
			}

			return ret;
		}

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

		void cleanOutPrivateKey(void){
			EVP_PKEY_free(privateKey);
                        privateKey = NULL;
		}

		void cleanOutPublicKey(){
                        EVP_PKEY_free(publicKey);
                        publicKey = NULL;
		}

		string rsa(bool encrypt, string msg, size_t msgLen){
			failed = false;
			string ret = "";
			
			if(encrypt){
				if(publicKey == NULL){
					failed = true;
					return "";
				}
				pkeyCtx = EVP_PKEY_CTX_new(publicKey, NULL);
				if(pkeyCtx == NULL){
					failed = true;
					return "";
				}

				if(!EVP_PKEY_encrypt_init(pkeyCtx)){
					failed = true;
					rsaFree();
					return "";
				}

				if(!EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_OAEP_PADDING)){
					failed = true;
					rsaFree();
					return "";
				}

				unsigned char *output = NULL;
				size_t outputLen = 0;
				if(!EVP_PKEY_encrypt(pkeyCtx, NULL, &outputLen, (unsigned char *)msg.c_str(), msgLen)){
					failed = true;
					rsaFree();
					return "";
				}

				resultLen = outputLen;
				output = (unsigned char *)OPENSSL_malloc(outputLen);
				if(output == NULL){
					failed = true;
					rsaFree();
					return "";
				}

				if(!EVP_PKEY_encrypt(pkeyCtx, output, &outputLen, (unsigned char *)msg.c_str(), msgLen)){
					failed = true;
					rsaFree();
					OPENSSL_free(output);
					return "";
				}

				resultLen = outputLen;
				for(int i=0; i<outputLen; i++)
					ret = ret + (char)output[i];
				rsaFree();
				OPENSSL_free(output);

			}else{
				if(privateKey == NULL){
                                        failed = true;
                                        return "";
                                }
                                pkeyCtx = EVP_PKEY_CTX_new(privateKey, NULL);
                                if(pkeyCtx == NULL){
                                        failed = true;
                                        return "";
                                }

                                if(!EVP_PKEY_decrypt_init(pkeyCtx)){
                                        failed = true;
                                        rsaFree();
                                        return "";
                                }

                                if(!EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_OAEP_PADDING)){
                                        failed = true;
                                        rsaFree();
                                        return "";
                                }

                                unsigned char *output = NULL;
                                size_t outputLen = 0;
                                if(!EVP_PKEY_decrypt(pkeyCtx, NULL, &outputLen, (unsigned char *)msg.c_str(), msgLen)){
                                        failed = true;
                                        rsaFree();
                                        return "";
                                }

				resultLen = outputLen;
                                output = (unsigned char *)OPENSSL_malloc(outputLen);
                                if(output == NULL){
                                        failed = true;
                                        rsaFree();
                                        return "";
                                }

				if(!EVP_PKEY_decrypt(pkeyCtx, output, &outputLen, (unsigned char *)msg.c_str(), msgLen)){
                                        failed = true;
                                        rsaFree();
                                        OPENSSL_free(output);
                                        return "";
                                }

                                resultLen = outputLen;
                                for(int i=0; i<outputLen; i++)
				  	ret = ret + (char)output[i];
                                rsaFree();
                                OPENSSL_free(output);
			}
			return ret;
		}

		bool fetchRsaKeyFromString(bool fetchPrivateKey, bool useDER, string key, size_t keyLen, string keyPassword){
			failed = false;
                        string format = "PEM";
                        if(useDER){
                                format = "DER";
                        }

			if(fetchPrivateKey){
				decoderCtx = OSSL_DECODER_CTX_new_for_pkey(&privateKey, format.c_str(), NULL, "RSA", OSSL_KEYMGMT_SELECT_PRIVATE_KEY, NULL, NULL);
                                if(decoderCtx == NULL){
                                        failed = true;
                                        fetchRsaKeyFromStringFree();
                                        return "";
                                }

                                if(keyPassword != ""){
                                	OSSL_DECODER_CTX_set_passphrase(decoderCtx, (const unsigned char *)keyPassword.c_str(), keyPassword.length());
                                }

				unsigned char *data = new unsigned char[key.length()];

				for(int i=0; i<key.length(); i++)
					data[i] = key[i];

				const unsigned char *doublePointer  = data;
                                if(!OSSL_DECODER_from_data(decoderCtx, &doublePointer, &keyLen)){
                                        fetchRsaKeyFromStringFree();
                                        failed = true;
					delete[] data;
                                        return "";
                                }

				delete doublePointer;
				delete[] data;
                                OSSL_DECODER_CTX_free(decoderCtx);
                                decoderCtx = NULL;
			}else{
				decoderCtx = OSSL_DECODER_CTX_new_for_pkey(&publicKey, format.c_str(), NULL, "RSA", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
                                if(decoderCtx == NULL){
                                        failed = true;
                                        fetchRsaKeyFromStringFree();
                                        return "";
                                }

				unsigned char *data = new unsigned char[key.length()];
                                for(int i=0; i<key.length(); i++)
                                        data[i] = key[i];

				const unsigned char *doublePointer = data;
                                if(!OSSL_DECODER_from_data(decoderCtx, &doublePointer, &keyLen)){
                                        fetchRsaKeyFromStringFree();
                                        failed = true;
					delete[] data;
                                       	return false;
                                }

				delete[] data;
                                OSSL_DECODER_CTX_free(decoderCtx);
                                decoderCtx = NULL;
			}
			return true;
		}

		string fetchRsaKeyFromFile(bool fetchPrivateKey, bool useDER, bool stringOutput, string keyLoc, string keyPassword){
			string ret = "";
			failed = false;
			string format = "PEM";
			if(useDER){
				format = "DER";
			}

			if(fetchPrivateKey){
				decoderCtx = OSSL_DECODER_CTX_new_for_pkey(&privateKey, format.c_str(), NULL, "RSA", OSSL_KEYMGMT_SELECT_PRIVATE_KEY, NULL, NULL);
				if(decoderCtx == NULL){
					failed = true;
					fetchRsaKeyFromFileFree();
					return "";
				}

				FILE *fp = fopen(keyLoc.c_str(), "r");
				if(fp == NULL){
					failed = true;
					fetchRsaKeyFromFileFree();
					return "";
				}

                                if(keyPassword != ""){
                              		OSSL_DECODER_CTX_set_passphrase(decoderCtx, (const unsigned char *)keyPassword.c_str(), keyPassword.length());
                                }

				if(!OSSL_DECODER_from_fp(decoderCtx, fp)){
					fclose(fp);
					fetchRsaKeyFromFileFree();
					failed = true;
					return "";
				}
				fclose(fp);

				if(stringOutput){
					// fetch the data for string conversion.
					ret = convertEvpPkeyToString(true, useDER, privateKey, keyPassword);	
					if(ret == ""){
						failed = true;
						fetchRsaKeyFromFileFree();
						return "";
					}

					fetchRsaKeyFromFileFree();
				}else{
                        		OSSL_DECODER_CTX_free(decoderCtx);
                        		decoderCtx = NULL;
				}
			}else{
				decoderCtx = OSSL_DECODER_CTX_new_for_pkey(&publicKey, format.c_str(), NULL, "RSA", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
                                if(decoderCtx == NULL){
                                        failed = true;
                                        fetchRsaKeyFromFileFree();
                                        return "";
                                }

                                FILE *fp = fopen(keyLoc.c_str(), "r");
                                if(fp == NULL){
                                        failed = true;
                                        fetchRsaKeyFromFileFree();
                                        return "";
                                }

                                if(!OSSL_DECODER_from_fp(decoderCtx, fp)){
                                        fclose(fp);
                                        fetchRsaKeyFromFileFree();
                                        failed = true;
                                        return "";
                                }
                                fclose(fp);

				if(stringOutput){
	                                // fetch the data for string conversion.
	                                ret = convertEvpPkeyToString(false, useDER, publicKey, "");
	                                if(ret == ""){
	                                        failed = true;
	                                        fetchRsaKeyFromFileFree();
	                                        return "";
	                                }
	
                                	fetchRsaKeyFromFileFree();
				}else{
                        		OSSL_DECODER_CTX_free(decoderCtx);
                        		decoderCtx = NULL;
				}
			}

			return ret;
		}
		/*
		 * NOTES: 
		 * 	Generic RSA Key Sizes : 1024 | 4096 | 8192
		 * */
		bool generateRsaKeyPairToFile(int bits, bool useDER, string publicKeyLoc, string privateKeyLoc, string keyPassword){
			failed = false;
			string format = "PEM";
			if(useDER){
				format = "DER";
			}
			keypair = EVP_RSA_gen(bits);
			if(keypair == NULL){
				failed = true;
				return false;
			}
			
			// Write out Public Key
			encoderCtx = OSSL_ENCODER_CTX_new_for_pkey(keypair, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, format.c_str(), NULL, NULL);
			if(encoderCtx == NULL){
				failed = true;
				generateRSAKeyFree();
				return false;
			}

			FILE *fp = fopen(publicKeyLoc.c_str(), "w+");
			if(fp == NULL){
				failed = true;
				generateRSAKeyFree();
				return false;
			}

			if(!OSSL_ENCODER_to_fp(encoderCtx, fp)){
				fclose(fp);
				generateRSAKeyFree();
				failed = true;
				return false;
			}
			fclose(fp);
			OSSL_ENCODER_CTX_free(encoderCtx);


			//Write out Private Key
			encoderCtx = OSSL_ENCODER_CTX_new_for_pkey(keypair, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, format.c_str(), NULL, NULL);
			if(encoderCtx == NULL){
                                failed = true;
                                generateRSAKeyFree();
                                return false;
                        }

			fp = fopen(privateKeyLoc.c_str(), "w+");
                        if(fp == NULL){
                                failed = true;
                                generateRSAKeyFree();
                                return false;
                        }

			if(keyPassword != ""){
				printf("Failing here.\n");
				OSSL_ENCODER_CTX_set_passphrase(encoderCtx, (const unsigned char *)keyPassword.c_str(), keyPassword.length());
				printf("nig\n");
                        }

                        if(!OSSL_ENCODER_to_fp(encoderCtx, fp)){
                                fclose(fp);
                                generateRSAKeyFree();
                                failed = true;
                                return false;
                        }
                        fclose(fp);
			generateRSAKeyFree();
			return true;
		}
	
		string aes256ctr_execute(bool encrypt, string state, size_t stateLen){
			failed = false;
			string ret = "";
			unsigned char *output = NULL;
			int len;

			if(encrypt){
				if(cipherCtrECtx == NULL){
                        	        failed = true;
                        	        freeAes256Ctr(encrypt);
                        	        return "";
                        	}

                        	if(_aes256ctr_encrypt == NULL){
                        	        failed = true;
                        	        freeAes256Ctr(encrypt);
                        	        return "";
                        	}
				
				output = new unsigned char[stateLen+16];
				
				if(!EVP_EncryptUpdate(cipherCtrECtx, output, &len, (unsigned char *)state.c_str(), stateLen)){
                                        failed = true;
                                        freeAes256Ctr(encrypt);
                                        return "";
                                }
                                resultLen = len;

                                if(!EVP_EncryptFinal_ex(cipherCtrECtx, output+len, &len)){
                                        failed = true;
                                        freeAes256Ctr(encrypt);
                                        return "";
                                }
                                resultLen += len;

                                for(int i=0; i<resultLen; i++){
                                        ret += output[i];
                                }
			}else{
				if(cipherCtrDCtx == NULL){
                                        failed = true;
                                        freeAes256Ctr(encrypt);
                                        return "";
                                }

                                if(_aes256ctr_decrypt == NULL){
                                        failed = true;
                                        freeAes256Ctr(encrypt);
                                        return "";
                                }

				output = new unsigned char[stateLen];
				
				if(!EVP_DecryptUpdate(cipherCtrDCtx, output, &len, (unsigned char *)state.c_str(), stateLen)){
                                        failed = true;
                                        freeAes256Ctr(encrypt);
                                        return "";
                                }
                                resultLen = len;

                                if(!EVP_DecryptFinal_ex(cipherCtrDCtx, output+len, &len)){
                                        failed = true;
                                        freeAes256Ctr(encrypt);
                                        return "";
                                }
                                resultLen += len;

                                for(int i=0; i<resultLen; i++){
                                        ret += output[i];
                                }
			}
			delete[] output;
			return ret;
		}
		
		void aes256ctr_stop(bool encrypt){
			freeAes256Ctr(encrypt);
		}
	
		bool aes256ctr_start(bool encrypt, unsigned char key[32], unsigned char iv[16]){
			failed = false;
			string ret = "";
			unsigned char *output = NULL;
			int len = 0;

			if(encrypt){
				cipherCtrECtx = EVP_CIPHER_CTX_new();
                        	if(cipherCtrECtx == NULL){
                        	        failed = true;
                        	        freeAes256Ctr(encrypt);
                        	        return false;
                        	}

                        	_aes256ctr_encrypt = EVP_CIPHER_fetch(NULL, "AES-256-CTR", NULL);
                        	if(_aes256ctr_encrypt == NULL){
                        	        failed = true;
                        	        freeAes256Ctr(encrypt);
                        	        return false;
                        	}
				if(!EVP_EncryptInit_ex(cipherCtrECtx, _aes256ctr_encrypt, NULL, key, iv)){
					failed = true;
					freeAes256Ctr(encrypt);
					return false;
				}
			}else{
				cipherCtrDCtx = EVP_CIPHER_CTX_new();
                        	if(cipherCtrDCtx == NULL){
                        	        failed = true;
                        	        freeAes256Ctr(encrypt);
                        	        return false;
                        	}

                        	_aes256ctr_decrypt = EVP_CIPHER_fetch(NULL, "AES-256-CTR", NULL);
                        	if(_aes256ctr_decrypt == NULL){
                        	        failed = true;
                        	        freeAes256Ctr(encrypt);
                        	        return false;
                        	}
				if(!EVP_DecryptInit_ex(cipherCtrDCtx, _aes256ctr_decrypt, NULL, key, iv)){
                                        failed = true;
                                        freeAes256Ctr(encrypt);
                                        return false;
                                }
			}
			delete[] output;
			return true;
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

		string sha256(string msg, size_t msgLen, bool binaryOutput){
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

	
			if(!EVP_DigestUpdate(mdCtx, (unsigned char *)msg.c_str(), msgLen)){
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

			digest = (const char *)outdigest;
			OPENSSL_free(outdigest);
			freeSha256();
			
			if(!binaryOutput){
				return binToStr(digest);
			}
			return digest;
		}	

		string randomPublic(size_t byteCount){
			failed = false;
			if(byteCount <= 0)
				return "";
			
			string ret = "";
			unsigned char *buf = new unsigned char[byteCount];
			if(RAND_bytes(buf, byteCount) != 1){
				failed = true;
				delete[] buf;
				return "";
			}
			for(int i=0; i<byteCount; i++)
				ret += buf[i];
			delete[] buf;
			return ret;
		}

		string randomPrivate(size_t byteCount){
                        failed = false;
                        if(byteCount <= 0)
                                return "";

                        string ret = "";
                        unsigned char *buf = new unsigned char[byteCount];
                        if(RAND_priv_bytes(buf, byteCount) != 1){
                                failed = true;
                                delete[] buf;
                                return "";
                        }
                        for(int i=0; i<byteCount; i++)
                                ret += buf[i];
                        delete[] buf;
                        return ret;
                }
};
