//
// Created by Ghost on 2018/11/12.
//

#include "des_ecb.h"

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

    const_DES_cblock cblock;
    const_DES_cblock key;

    memcpy(cblock, __data, BUFFER_SIZE);
    memcpy(key, __key, KEY_SIZE);
    int mode = __mode == DECRYPT ? DES_DECRYPT : DES_ENCRYPT;


    DES_key_schedule schedule;
    DES_set_key(&key, &schedule);

    DES_cblock result;
    DES_ecb_encrypt(&cblock, &result, &schedule, mode);
    memcpy(__result, result, BUFFER_SIZE);
}