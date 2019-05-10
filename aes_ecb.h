//
// Created by Ghost on 2018/11/13.
//

#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#define KEY_SIZE 16
#define BUFFER_SIZE 16

#define USAGE \
"Usage: aes_ecb <key file path> <data file path> [<operation>]\n"\
"Operations:\n"\
"\t-e\tencrypt\n"\
"\t-d\tdecrypt\n"\
"Note: Encrypt by default"

typedef struct {
#define ENCRYPT 0
#define DECRYPT 1
    int mode;
    char *file_path;
    char *key_path;
} crypto_data;

void arg_process(int argc, char *argv[], crypto_data *info);

void encrypt(const unsigned char *__data,
             const unsigned char *__key, int __mode, unsigned char *__result);

#endif //CRYPTO_AES_H
