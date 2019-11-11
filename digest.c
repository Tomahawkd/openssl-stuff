//
// Created by Ghost on 2019/10/11.
//

#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/evperr.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

static uint8_t text[64] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
};

void handleErrors() {
    printf(ERR_error_string(ERR_get_error(), NULL));
    printf("\n");
}

void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
    EVP_MD_CTX *mdctx;

    if((mdctx = EVP_MD_CTX_create()) == NULL)
        handleErrors();

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL))
        handleErrors();

    if(1 != EVP_DigestUpdate(mdctx, message, message_len))
        handleErrors();

    if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sm3()))) == NULL)
        handleErrors();

    if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
        handleErrors();

    EVP_MD_CTX_destroy(mdctx);
}

int main() {

    uint8_t *out;
    uint32_t i = 0;
    uint32_t ret = 0;

    ERR_load_EVP_strings();

    digest_message(text, 64, &out, &i);

    for (uint32_t j = 0; j < i; ++j) {
        printf("0x%.2X, ", out[j]);
    }
}