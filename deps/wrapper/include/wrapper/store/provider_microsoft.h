#pragma once

#include "../common/common.h"

#include <string.h>

#ifndef OPENSSL_NO_CTGOSTCP
	#include <openssl/opensslconf.h>
	#include <openssl/crypto.h>
	#include <openssl/ctgostcp.h>
	#include <openssl/ctcrypto.h>
#endif

#include "pkistore.h"

class ProviderMicrosoft : public Provider{
public:
	ProviderMicrosoft();
	~ProviderMicrosoft(){};

public:
	Handle<Certificate> static getCert(Handle<std::string> hash, Handle<std::string> category);
	Handle<CRL> static getCRL(Handle<std::string> hash, Handle<std::string> category);
	Handle<Key> static getKey(Handle<Certificate> cert);

private:
	void init();
	void enumCertificates(HCERTSTORE hCertStore, std::string *category);
	void enumCrls(HCERTSTORE hCertStore, std::string *category);
	Handle<PkiItem> objectToPKIItem(Handle<Certificate> cert);
	Handle<PkiItem> objectToPKIItem(Handle<CRL> crl);

	int static char2int(char input);
	void static hex2bin(const char* src, char* target);
};

