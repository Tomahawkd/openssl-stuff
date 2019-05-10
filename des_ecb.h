//
// Created by Ghost on 2018/11/12.
//

#ifndef CRYPTO_DES_H
#define CRYPTO_DES_H

#include <stdio.h>
#include <openssl/des.h>
#include <string.h>

#define KEY_SIZE 8
#define BUFFER_SIZE 8

#define USAGE \
"Usage: des_ecb <key file path> <data file path> [<operation>]\n"\
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

#endif //CRYPTO_DES_H
