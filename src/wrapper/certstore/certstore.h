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
};

class Certificate;
class CRL;

class CertStore {
	public:
		vector<CertStoreProvider*> cache_providers;
	public:
		void CERT_STORE_NEW(char* pvdType); //Создание нового хранилища сертификатов
		void CERT_STORE_NEW(char* pvdType, string pvdURI); //Создание нового хранилища сертификатов
		void CERT_STORE_FREE(CertStoreProvider* store_provider); //Освобождение (удаление) хранилища
		void CERT_STORE_CLEANUP(CertStoreProvider* store_provider); //Очистка содержимого хранилища

		void newJSON(const char *pvdURI);
	public:
		CertStore();
		~CertStore(){};
};