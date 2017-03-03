#ifndef CMS_PKI_CIPHER_H_INCLUDED
#define  CMS_PKI_CIPHER_H_INCLUDED

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/cms.h>

#include "../common/common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "certs.h"
#include "cert.h"
#include "key.h"
#include "../cms/cmsRecipientInfos.h"

#undef SIZE
#undef BSIZE

#define SIZE	(512)
#define BSIZE	(8*1024)

class CryptoMethod
{
public:
	enum Crypto_Method {
		SYMMETRIC,
		ASSYMETRIC
	};

	static CryptoMethod::Crypto_Method get(int value){
		switch (value){
		case CryptoMethod::SYMMETRIC:
			return CryptoMethod::SYMMETRIC;
		case CryptoMethod::ASSYMETRIC:
			return CryptoMethod::ASSYMETRIC;
		default:
			THROW_EXCEPTION(0, CryptoMethod, NULL, ERROR_DATA_FORMAT_UNKNOWN_FORMAT, value);
		}
	}
};

class CTWRAPPER_API Cipher;

static const char magic[] = "Salted__";

class Cipher{

public:
	Cipher();

	/*Symetric or assymetric(default)*/
	void setCryptoMethod(CryptoMethod::Crypto_Method method);

	void encrypt(Handle<Bio> inSource, Handle<Bio> outEnc, DataFormat::DATA_FORMAT format);
	void decrypt(Handle<Bio> inEnc, Handle<Bio> outDec, DataFormat::DATA_FORMAT format);

public:
	Handle<std::string> getAlgorithm();
	Handle<std::string> getMode();

//********************************************************************* 
// Functions for assymetric method
//*********************************************************************
public:
	/*Add recipints certificates for encrypted*/
	void addRecipientsCerts(Handle<CertificateCollection> certs);

	/*Set private key for decrypted*/
	void setPrivKey(Handle<Key> privkey);

	/*Set recipient certificate for decrypted*/
	void setRecipientCert(Handle<Certificate> cert);

	/*Get recipients*/
	Handle<CmsRecipientInfoCollection> getRecipientInfos(Handle<Bio> inEnc, DataFormat::DATA_FORMAT format);

//*********************************************************************
// Functions for symetric method
//*********************************************************************
public:
	void setDigest(Handle<std::string>  md);
	void setSalt(Handle<std::string> saltP);
	void setPass(Handle<std::string> password);
	void setIV(Handle<std::string> iv);
	void setKey(Handle<std::string> key);

	Handle<std::string> getSalt();
	Handle<std::string> getIV();
	Handle<std::string> getKey();

	Handle<std::string> getDigestAlgorithm();

protected:
	CryptoMethod::Crypto_Method hmethod = CryptoMethod::ASSYMETRIC;

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

	STACK_OF(X509) *encerts = NULL;
	X509 *rcert = NULL;
	CMS_ContentInfo *cms = NULL;
	int flags = CMS_STREAM;
	EVP_PKEY *rkey = NULL;

private:
	int setHex(char *in, unsigned char *out, int size);
};

#endif