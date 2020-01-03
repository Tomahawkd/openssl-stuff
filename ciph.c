//
// Created by Ghost on 2019/10/11.
//

#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <openssl/err.h>
#include <string.h>

#define BUFFER_LEN 4096

void handleErrors() {
    printf("%s", ERR_error_string(ERR_get_error(), NULL));
    printf("\n");
}

void encrypt(FILE *in, FILE *out, const EVP_CIPHER *algo, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;
    int len;
    size_t real_len;
    uint8_t buf[BUFFER_LEN] = {0};
    uint8_t out_buf[BUFFER_LEN + 16] = {0};

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, algo, NULL, key, iv)) handleErrors();

    while (!feof(in)) {
        real_len = fread(buf, 1, BUFFER_LEN, in);
        len = BUFFER_LEN + 16;
        if (1 != EVP_EncryptUpdate(ctx, out_buf, &len, buf, real_len)) handleErrors();
        fwrite(out_buf, sizeof(uint8_t), len, out);
    }

    len = BUFFER_LEN + 16;
    if (1 != EVP_EncryptFinal_ex(ctx, out_buf, &len)) handleErrors();
    fwrite(out_buf, sizeof(uint8_t), len, out);
    fflush(out);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

void decrypt(FILE *in, FILE *out, const EVP_CIPHER *algo, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;
    int len;
    size_t real_len;
    uint8_t buf[BUFFER_LEN] = {0};
    uint8_t out_buf[BUFFER_LEN + 16] = {0};

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, algo, NULL, key, iv)) handleErrors();

    while (!feof(in)) {
        real_len = fread(buf, 1, BUFFER_LEN, in);
        len = BUFFER_LEN + 16;
        if (1 != EVP_DecryptUpdate(ctx, out_buf, &len, buf, real_len)) handleErrors();
        fwrite(out_buf, sizeof(uint8_t), len, out);
    }

    len = BUFFER_LEN + 16;
    if (1 != EVP_DecryptFinal_ex(ctx, out_buf, &len)) handleErrors();
    fwrite(out_buf, sizeof(uint8_t), len, out);
    fflush(out);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

void gen_data(const char *filename, int size) {

    uint8_t rand[1024];
    int left;
    FILE *in = fopen(filename,"wr");
    if (!in) printf("File err");

    for (int i = 0; i < size/1024; ++i) {
        arc4random_buf(rand,1024);
        fwrite(rand, sizeof(uint8_t), 1024, in);
    }

    left = size % 1024;
    arc4random_buf(rand, left);
    fwrite(rand, 1, left, in);

    fclose(in);
}

int compare_file(const char *f1, const char *f2) {
    FILE *ff1 = fopen(f1, "r");
    FILE *ff2 = fopen(f2, "r");
    uint8_t buf1[BUFFER_LEN];
    uint8_t buf2[BUFFER_LEN];
    size_t len1;
    size_t len2;

    while (1) {
        int cmp = 0;

        len1 = fread(buf1, 1, BUFFER_LEN, ff1);
        len2 = fread(buf2, 1, BUFFER_LEN, ff2);

        if (len1 != len2) return (int) (len1 - len2);
        if ((cmp = memcmp(buf1, buf2, len1)) != 0) return cmp;
        if ((feof(ff1) && !feof(ff2)) || (!feof(ff1) && feof(ff2))) return -1;
        if (feof(ff1) && feof(ff2)) return cmp;
    }
}

#define ALGORITHM(ALGO, MODE) \
    EVP_##ALGO##_##MODE()

static uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static uint8_t k[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

#define PLAIN_FILE "1.png"
#define ENCRYPT_FILE "enc"
#define DECRYPT_FILE "1dec.png"
#define FILE_SIZE 8192 // bytes

int main() {

    //gen_data(PLAIN_FILE, FILE_SIZE);

    FILE *in = fopen(PLAIN_FILE, "r");
    FILE *out = fopen(ENCRYPT_FILE, "w");
    FILE *decin = fopen(ENCRYPT_FILE,"r");
    FILE *dec = fopen(DECRYPT_FILE, "w");

    if (!in) { printf("File err"); return 1; }
    if (!out) { printf("File err"); return 1; }
    if (!decin) { printf("File err"); return 1; }
    if (!dec) { printf("File err"); return 1; }
    ERR_load_EVP_strings();

    encrypt(in, out, ALGORITHM(aes_128, cbc), k, iv);
    decrypt(decin, dec, ALGORITHM(aes_128, cbc), k, iv);

    printf("Compare files: %d", compare_file(PLAIN_FILE,DECRYPT_FILE));
    fclose(in);
    fclose(out);
    fclose(decin);
    fclose(dec);
}