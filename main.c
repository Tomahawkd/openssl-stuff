//
// Created by Ghost on 2018/11/13.
//

#include "common_ecb.h"

int main(int argc, char *argv[]) {
    crypto_data info;
    arg_process(argc, argv, &info);

    FILE *in_file = fopen(info.file_path, "r");
    FILE *key_file = fopen(info.key_path, "r");
    FILE *out_file = NULL;

    if (!in_file) {
        printf("Cannot open data file");
        exit(1);
    }
    if (!key_file) {
        printf("Cannot open or create key file");
        exit(1);
    }

    if (info.mode == ENCRYPT) {
        out_file = fopen(strcat(info.file_path, ".enc"), "w");
    } else if (info.mode == DECRYPT) {
        out_file = fopen(strcat(info.file_path, ".origin"), "w");
    } else {
        printf("Something bad occurred");
        exit(1);
    }

    if (!out_file) {
        printf("Cannot create output file");
        exit(1);
    }

    file_encrypt(info, in_file, key_file, out_file);

    return 0;
}