#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <stdint.h>
#include <string.h>

#define RSA_BYTES 256
#define CMP_BUFF_LEN RSA_BYTES
#include "file_operation.h"

RSA *generate_keys(const char *pubname, const char *priname) {

    RSA *rsa = RSA_generate_key(RSA_BYTES * 8, 0x10001, NULL, NULL);
    if (rsa == NULL) {
        printf("RSA key generation failed");
        exit(1);
    }

    BIO *bp = BIO_new_file(pubname, "w+");
    PEM_write_bio_RSAPublicKey(bp, rsa);
    BIO_flush(bp);
    BIO_free_all(bp);

    bp = BIO_new_file(priname, "w+");
    PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, NULL);
    BIO_flush(bp);
    BIO_free_all(bp);

    return rsa;
}

#define PLAIN_FILE "pkplain"
#define ENCRYPT_FILE "pkenc"
#define DECRYPT_FILE "pkdec"
#define KEY_PUBLIC "public.pem"
#define KEY_PRIVATE "private.pem"
#define FILE_SIZE 128 // bytes

int main(int argc, char *argv[]) {

    int ret;
    uint8_t buf[RSA_BYTES] = {0};
    uint8_t enout[RSA_BYTES] = {0};
    uint8_t deout[RSA_BYTES] = {0};

    gen_data(PLAIN_FILE, FILE_SIZE);

    FILE *in = fopen(PLAIN_FILE, "r");
    FILE *out = fopen(ENCRYPT_FILE, "w");
    FILE *decin = fopen(ENCRYPT_FILE, "r");
    FILE *dec = fopen(DECRYPT_FILE, "w");

    if (!in) {
        printf("File err");
        return 1;
    }
    if (!out) {
        printf("File err");
        return 1;
    }
    if (!decin) {
        printf("File err");
        return 1;
    }
    if (!dec) {
        printf("File err");
        return 1;
    }

    RSA *rsa = generate_keys(KEY_PUBLIC, KEY_PRIVATE);

    size_t real_len = fread(buf, 1, FILE_SIZE, in);
    if (real_len >= RSA_BYTES - 11) {
        printf("Data too big: %zu\n", real_len);
        goto err;
    }
    if ((ret = RSA_public_encrypt(real_len, buf, enout, rsa, RSA_PKCS1_PADDING)) == -1) {
        printf("Encryption error: %d", ret);
        goto err;
    }
    fwrite(enout, sizeof(uint8_t), RSA_BYTES, out);
    fflush(out);

    real_len = fread(buf, 1, RSA_BYTES, decin);
    if (real_len != RSA_BYTES) {
        printf("Data too small: %zu\n", real_len);
        goto err;
    }
    if ((ret = RSA_private_decrypt(real_len, enout, deout, rsa, RSA_PKCS1_PADDING)) == -1) {
        printf("Decryption error: %d", ret);
        goto err;
    }
    fwrite(deout, sizeof(uint8_t), FILE_SIZE, dec);
    fflush(dec);

    printf("Compare files: %d", compare_file(PLAIN_FILE, DECRYPT_FILE));

    err:
    RSA_free(rsa);
    fclose(in);
    fclose(out);
    fclose(decin);
    fclose(dec);
}