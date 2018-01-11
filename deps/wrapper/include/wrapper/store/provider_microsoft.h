#pragma once

#include "../common/common.h"
#include "../utils/csp.h"

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

	static void addPkiObject(Handle<Certificate> cert, Handle<std::string> category);
	static void deletePkiObject(Handle<Certificate> cert, Handle<std::string> category);

	bool static hasPrivateKey(Handle<Certificate> cert);

private:
	Handle<std::string> static nameToStr(
		IN DWORD dwCertEncodingType,
		IN const CERT_NAME_BLOB *pName,
		IN DWORD dwStrType = CERT_SIMPLE_NAME_STR
		);

	void init();
	void enumCertificates(HCERTSTORE hCertStore, std::string *category);
	void enumCrls(HCERTSTORE hCertStore, std::string *category);
	Handle<PkiItem> objectToPKIItem(Handle<Certificate> cert);
	Handle<PkiItem> objectToPKIItem(Handle<CRL> crl);

	int static char2int(char input);
	void static hex2bin(const char* src, char* target);
};

