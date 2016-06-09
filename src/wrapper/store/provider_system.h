#ifndef PROVIDER_SYSTEM_H_INCLUDED
#define PROVIDER_SYSTEM_H_INCLUDED

#include "../common/common.h"

#include <stdio.h>
#include <string>

#if defined(OPENSSL_SYS_WINDOWS) 
	#include <tchar.h> 
	#include <strsafe.h>
	#include <direct.h>
#endif
#if defined(OPENSSL_SYS_UNIX)
	#include <dirent.h>
	#include <sys/types.h>
	#include <sys/stat.h>
#endif

#include "pkistore.h"

class Provider_System : public Provider{
public:
	Provider_System(){};
	Provider_System(Handle<std::string> folder);
	~Provider_System(){};

	Handle<Certificate> static getCertFromURI(Handle<std::string> uri, Handle<std::string> format);
	Handle<CRL> static getCRLFromURI(Handle<std::string> uri, Handle<std::string> format);
	Handle<CertificationRequest> static getCSRFromURI(Handle<std::string> uri, Handle<std::string> format);
	Handle<Key> static getKeyFromURI(Handle<std::string> uri, Handle<std::string> format, bool enc);

	static void addPkiObject(Handle<std::string> uri, Handle<Certificate> cert, unsigned int flags);
	static void addPkiObject(Handle<std::string> uri, Handle<CRL> crl, unsigned int flags);
	static void addPkiObject(Handle<std::string> uri, Handle<CertificationRequest> csr);
	static void addPkiObject(Handle<std::string> uri, Handle<Key> key, Handle<std::string> password);

	Handle<PkiItem> objectToPKIItem(Handle<std::string> URI);

private:
	void init(Handle<std::string> folder);	
	
	/*
	* Check file for pkcs#8 private key headers.
	* Only pkcs#8 key in PEM format.
	*/
	bool itPrivateKey(Handle<std::string> uri, int *enc);

	/*
	* Search (object filename).key in curent folder, if can find it return key filename.
	* Key's filename  must be SHA1 hash and length 40.
	* Use for certificate or request pki object.
	*/
	Handle<std::string> getKey(Handle<std::string> objectPatch);
};

#endif //PROVIDER_SYSTEM_H_INCLUDED