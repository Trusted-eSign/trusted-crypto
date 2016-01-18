#pragma once
#include <openssl/x509.h>
#include "../common/common.h"
#include <string.h>
#include "certstore.h"
using namespace std;


class ProviderMSCrypto : public CertStoreProvider{
public:
	const string nameProviderType = "providerMSCrypto";
public:
	ProviderMSCrypto(){};
	~ProviderMSCrypto(){};

};

