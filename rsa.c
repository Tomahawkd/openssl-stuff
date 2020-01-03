#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdint.h>

#define RSA_BITS 256

int main(int argc, char *argv[]) {
	
	uint8_t buf[RSA_BITS] = {0};
	uint8_t enout[RSA_BITS] = {0};
	RSA *rsa = RSA_generate_key(RSA_BITS, 65537, NULL, NULL);
	
	if (RSA_public_encrypt(RSA_BITS, buf, enout, rsa, RSA_NO_PADDING)) {
		printf("Encryption error");
		goto err;
	}
	
	if (RSA_private_decrypt(RSA_BITS, enout, buf, rsa, RSA_NO_PADDING)) {
		printf("Decryption error");
		goto err;
	}
	
	err:
	RSA_free(rsa);
}