#ifndef CMS_PKI_CIPHER_H_INCLUDED
#define  CMS_PKI_CIPHER_H_INCLUDED

#include <openssl/evp.h>

#include "../common/common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef SIZE
#undef BSIZE

#define SIZE	(512)
#define BSIZE	(8*1024)

class CTWRAPPER_API Cipher;

static const char magic[] = "Salted__";

class Cipher{

public:
	Cipher(Handle<std::string> CipherAlgorithm);

	void encrypt(Handle<Bio> inSource, Handle<Bio> outEnc);
	void decrypt(Handle<Bio> inEnc, Handle<Bio> outDec);

public:
	void setDigest(Handle<std::string>  md);
	void setSalt(Handle<std::string> saltP);
	void setPass(Handle<std::string> password);
	void setIV(Handle<std::string> iv);
	void setKey(Handle<std::string> key);

	Handle<std::string> getSalt();
	Handle<std::string> getIV();
	Handle<std::string> getKey();

	Handle<std::string> getAlgorithm();
	Handle<std::string> getMode();
	Handle<std::string> getDigestAlgorithm();

protected:
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	unsigned char salt[PKCS5_SALT_LEN];
	char *hkey = NULL, *hiv = NULL, *hsalt = NULL, *hmd = NULL;
	const EVP_MD *dgst = NULL;
	const EVP_CIPHER *cipher = NULL;
	char *hpass = NULL;
	unsigned char *buff = NULL, *bufsize = NULL;
	int bsize = BSIZE;
	int inl;
	char mbuf[sizeof magic - 1];

	BIO *benc = NULL, *rbio = NULL, *wbio = NULL;
	EVP_CIPHER_CTX *ctx = NULL;

private:
	int setHex(char *in, unsigned char *out, int size);
};

#endif