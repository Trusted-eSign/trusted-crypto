#pragma once
#include <openssl/x509.h>
#include "../common/common.h"
#include <string.h>
#include "certstore.h"
using namespace std;


class ProviderPKCS11: public CertStoreProvider{
public:
	const string nameProviderType = "providerPKCS11";
public:
	ProviderPKCS11(){};
	//ProviderPKCS11(pair<providerType, providerURI>* providersParam){};
	~ProviderPKCS11(){};

};

