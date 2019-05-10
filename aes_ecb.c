//
// Created by Ghost on 2018/11/13.
//

#include "aes_ecb.h"

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

    AES_KEY key;
    if (__mode == DECRYPT) {
        AES_set_decrypt_key(__key, KEY_SIZE * 8, &key);
    } else {
        AES_set_encrypt_key(__key, KEY_SIZE * 8, &key);
    }

    int mode = __mode == DECRYPT ? AES_DECRYPT : AES_ENCRYPT;

    AES_ecb_encrypt(__data, __result, &key, mode);
}