#pragma once

#include "../common/common.h"

#include <string.h>

#if defined(OPENSSL_SYS_WINDOWS) 
	#include <windows.h>
	#include <wincrypt.h>
	#include <tchar.h> 
	#include <strsafe.h>
#endif
#if defined(OPENSSL_SYS_UNIX)
	#include "../../CPROCSP/WinCryptEx.h"
#endif

#include "pkistore.h"

class ProviderMicrosoft : public Provider{
public:
	ProviderMicrosoft();
	~ProviderMicrosoft(){};

public:
	Handle<Certificate> static getCert(Handle<std::string> hash, Handle<std::string> category);
	Handle<CRL> static getCRL(Handle<std::string> hash, Handle<std::string> category);

private:
	void init();
	void enumCertificates(HCERTSTORE hCertStore, std::string *category);
	void enumCrls(HCERTSTORE hCertStore, std::string *category);
	Handle<PkiItem> objectToPKIItem(Handle<Certificate> cert);
	Handle<PkiItem> objectToPKIItem(Handle<CRL> crl);

	int static char2int(char input);
	void static hex2bin(const char* src, char* target);
};

