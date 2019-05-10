//
// Created by Ghost on 2018/11/25.
//

#ifndef CRYPTO_RC4_H
#define CRYPTO_RC4_H

#include <stdio.h>
#include <string.h>
#include <openssl/rc4.h>
#include <stdlib.h>

#define KEY_SIZE 16
#define BUFFER_SIZE 16

#define USAGE "Usage: rc4 <key file path> <data file path>\n"

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

#endif //CRYPTO_RC4_H
