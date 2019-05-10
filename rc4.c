//
// Created by Ghost on 2018/11/25.
//

#include "rc4.h"

void arg_process(int argc, char *argv[], crypto_data *info) {

    info->mode = ENCRYPT;
    info->file_path = NULL;

    if (argc < 2 || argc > 4) {
        printf(USAGE);
        exit(0);
    } else if (argc == 2) {
        printf(USAGE);
        if (!strcmp("-h", argv[1])) { exit(0); }
        else { exit(1); }
    } else if (argc == 3) {
        info->key_path = argv[1];
        info->file_path = argv[2];
    } else {
        if (!strcmp("-d", argv[3])) { info->mode = DECRYPT; }
        else if (!strcmp("-e", argv[3])) { info->mode = ENCRYPT; }
        else {
            printf("Invalid argument\n%s", USAGE);
            exit(1);
        }
        info->key_path = argv[1];
        info->file_path = argv[2];
    }
}

void encrypt(const unsigned char *__data,
             const unsigned char *__key, int __mode, unsigned char *__result) {

    RC4_KEY schedule;
    RC4_set_key(&schedule, KEY_SIZE, __key);

    unsigned char* result = (unsigned char *) malloc(sizeof(unsigned char)* (BUFFER_SIZE+1));
    RC4(&schedule, BUFFER_SIZE, __data, result);
    memcpy(__result, result, BUFFER_SIZE);
}