#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

class EncryptionSnake{
	private:
		EVP_MD_CTX *ctx = NULL;
		EVP_MD *_sha256 = NULL;
		
		bool failed = false;

		void freeSha256(void){
			EVP_MD_free(_sha256);
			EVP_MD_CTX_free(ctx);
		}

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
	bool didFail(void){
		return failed;
	}

	void printError(void){
		if(failed)
			ERR_print_errors_fp(stderr);
	}

	string sha256(string msg, bool binaryOutput){
		failed = false;
		string digest = "";
		ctx = EVP_MD_CTX_new();
		if(ctx == NULL){
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

		if(!EVP_DigestInit_ex(ctx, _sha256, NULL)){
			failed = true;
                        freeSha256();
                        return "";
		}


		if(!EVP_DigestUpdate(ctx, (unsigned char *)msg.c_str(), msg.length())){
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

		if(!EVP_DigestFinal_ex(ctx, outdigest, &len)){
			OPENSSL_free(outdigest);
			failed = true;
                        freeSha256();
                        return "";
		}

	//	BIO_dump_fp(stdout, outdigest, len);  /*Debug line*/

		digest = (const char *)outdigest;
		OPENSSL_free(outdigest);
		freeSha256();
		
		if(!binaryOutput){
			return binToStr(digest);
		}
		return digest;
	}	
};
