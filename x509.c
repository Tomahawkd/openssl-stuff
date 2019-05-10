//
// Created by Ghost on 2019-04-29.
//

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

void parse_cert(X509 *x509);

int main(int argc, char *argv[]) {
    OpenSSL_add_all_algorithms();

    char filename[11] = "./cert.pem";

    struct stat st;
    stat(filename, &st);
    size_t size = st.st_size;

    char *buffer = malloc(size);

    FILE *cert = fopen("./cert.pem", "r");
    if (!cert) {
        printf("Cannot open data file");
        exit(1);
    }

    int count = 0;
    while (feof(cert) == 0) {
        buffer[count++] = (unsigned char) fgetc(cert);
        if (buffer[count] == -1) {
            break;
        }
    }
    fclose(cert);

    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, buffer);
    X509 *x509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    parse_cert(x509);

    free(buffer);
    return 0;
}

void parse_cert(X509 *x509) {
    printf("\n\n");
    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    long l = X509_get_version(x509);
    BIO_printf(bio_out, "Version: %ld\n", l + 1);

    ASN1_INTEGER *bs = X509_get_serialNumber(x509);
    BIO_printf(bio_out, "Serial: ");
    for (int i = 0; i < bs->length; i++) {
        BIO_printf(bio_out, "%02x", bs->data[i]);
    }
    BIO_printf(bio_out, "\n");

    X509_signature_print(bio_out, x509->sig_alg, NULL);

    BIO_printf(bio_out, "Issuer: ");
    X509_NAME_print(bio_out, X509_get_issuer_name(x509), 0);
    BIO_printf(bio_out, "\n");

    BIO_printf(bio_out, "Valid From: ");
    ASN1_TIME_print(bio_out, X509_get_notBefore(x509));
    BIO_printf(bio_out, "\n");

    BIO_printf(bio_out, "Valid Until: ");
    ASN1_TIME_print(bio_out, X509_get_notAfter(x509));
    BIO_printf(bio_out, "\n");

    BIO_printf(bio_out, "Subject: ");
    X509_NAME_print(bio_out, X509_get_subject_name(x509), 0);
    BIO_printf(bio_out, "\n");

    EVP_PKEY *pkey = X509_get_pubkey(x509);
    EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
    EVP_PKEY_free(pkey);

    X509_CINF *ci = x509->cert_info;
    X509V3_extensions_print(bio_out, (char *) "X509v3 extensions", ci->extensions, X509_FLAG_COMPAT, 0);

    X509_signature_print(bio_out, x509->sig_alg, x509->signature);
    BIO_free(bio_out);
}
