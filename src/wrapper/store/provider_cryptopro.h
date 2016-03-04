#pragma once
#include <openssl/x509.h>
#include "../common/common.h"
#include <string.h>
#include "certstore.h"
using namespace std;


class ProviderCryptoPRO : public CertStoreProvider{
public:
	const string nameProviderType = "providerCryptoPRO";
public:
	ProviderCryptoPRO(){};
	~ProviderCryptoPRO(){};

};

