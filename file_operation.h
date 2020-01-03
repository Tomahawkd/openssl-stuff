//
// Created by Ghost on 2020/1/3.
//

#ifndef CRYPTO_FILE_OPERATION_H
#define CRYPTO_FILE_OPERATION_H

#include <stdio.h>
#include <string.h>

#ifndef CMP_BUFF_LEN
# error "Buffer length must be defined"
#endif

int compare_file(const char *f1, const char *f2) {
    FILE *ff1 = fopen(f1, "r");
    FILE *ff2 = fopen(f2, "r");
    uint8_t buf1[CMP_BUFF_LEN];
    uint8_t buf2[CMP_BUFF_LEN];
    size_t len1;
    size_t len2;

    while (1) {
        int cmp = 0;

        len1 = fread(buf1, 1, CMP_BUFF_LEN, ff1);
        len2 = fread(buf2, 1, CMP_BUFF_LEN, ff2);

        if (len1 != len2) return (int) (len1 - len2);
        if ((cmp = memcmp(buf1, buf2, len1)) != 0) return cmp;
        if ((feof(ff1) && !feof(ff2)) || (!feof(ff1) && feof(ff2))) return -1;
        if (feof(ff1) && feof(ff2)) return cmp;
    }
}

void gen_data(const char *filename, int size) {

    uint8_t rand[1024];
    int left;
    FILE *in = fopen(filename, "wr");
    if (!in) printf("File err");

    for (int i = 0; i < size / 1024; ++i) {
        arc4random_buf(rand, 1024);
        fwrite(rand, sizeof(uint8_t), 1024, in);
    }

    left = size % 1024;
    arc4random_buf(rand, left);
    fwrite(rand, 1, left, in);

    fclose(in);
}

#endif //CRYPTO_FILE_OPERATION_H
