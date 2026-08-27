#include "shim.h"

int X_EVP_Digest(const EVP_MD *md, const unsigned char *data, size_t count,
                 unsigned char *md_out, unsigned int *size)
{
    return EVP_Digest(data, count, md_out, size, md, NULL);
}

EVP_PKEY *X_EVP_PKEY_Q_keygen_sm2(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
}

EVP_PKEY *X_PEM_read_bio_PrivateKey(BIO *bp)
{
    return PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
}

int X_PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x)
{
    return PEM_write_bio_PrivateKey(bp, x, NULL, NULL, 0, NULL, NULL);
}

EVP_PKEY *X_PEM_read_bio_PUBKEY(BIO *bp)
{
    return PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
}

int X_PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x)
{
    return PEM_write_bio_PUBKEY(bp, x);
}

X509 *X_PEM_read_bio_X509(BIO *bp)
{
    return PEM_read_bio_X509(bp, NULL, NULL, NULL);
}

int X_PEM_write_bio_X509(BIO *bp, X509 *x)
{
    return PEM_write_bio_X509(bp, x);
}

X509_REQ *X_PEM_read_bio_X509_REQ(BIO *bp)
{
    return PEM_read_bio_X509_REQ(bp, NULL, NULL, NULL);
}

int X_PEM_write_bio_X509_REQ(BIO *bp, X509_REQ *x)
{
    return PEM_write_bio_X509_REQ(bp, x);
}
