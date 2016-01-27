//#ifndef CMS_PKI_KEY_H_INCLUDED
//#define  CMS_PKI_KEY_H_INCLUDED

#pragma once
#include <openssl/x509.h>
//#include <openssl/cryptlib.h>
#include "../common/common.h"
#include <string.h>

#if defined(OPENSSL_SYS_WINDOWS) 
	#define CROSSPLATFORM_SLASH       "\\"
#endif
#if defined(OPENSSL_SYS_UNIX) 
	#define CROSSPLATFORM_SLASH       "/"
#endif

using namespace std;

class CTWRAPPER_API CertStore;
class CTWRAPPER_API CertStoreProvider;
class CTWRAPPER_API ProviderSystem;
class CTWRAPPER_API ProviderTCL;
class CTWRAPPER_API ProviderMSCrypto;
class CTWRAPPER_API ProviderCryptoPRO;
class CTWRAPPER_API ProviderTrustedNET;
class CTWRAPPER_API ProviderPKCS11;

class CertStoreProvider {
public:
	CertStoreProvider(){};
	~CertStoreProvider(){};
public:
	string pvdType;
	string pvdURI;

	string getPvdType();

	void fillingCache(const char* cacheURI, const char* pvdURI);
	void fillingCache(const char* pvdURI);
	void reloadCertStoreByCache(const char* cacheURI, const char* pvdType);
	void reloadCertStoreByCache(const char* cacheURI);
};

class Certificate;
class CRL;

class CertStore {
	public:
		vector<CertStoreProvider*> cache_providers;
	public:
		void addCertStore(const char* pvdType);
		void addCertStore(const char* pvdType, const char* pvdURI);

		void removeCertStore(const char* pvdType);

		void createCache(const char* cacheURI);
		void addCacheSection(const char* cacheURI, const char* pvdType);

		Handle<std::string> getCertStore();
		bool getPrvTypePresent(const char* pvdType);
		
	public:
		CertStore();
		CertStore(const char* pvdType);
		CertStore(const char* pvdType, const char* pvdURI);
		~CertStore(){};
};

//#endif //  comment this --->   CMS_PKI_KEY_H_INCLUDED