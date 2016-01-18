#pragma once
#include <openssl/x509.h>
#include "../common/common.h"
#include <string.h>
#include "certstore.h"
using namespace std;


class ProviderTrustedNET : public CertStoreProvider{
public:
	const string nameProviderType = "providerTrustedNET";
public:
	ProviderTrustedNET(){};
	//ProviderTrustedNET(pair<providerType, providerURI>* providersParam){};
	~ProviderTrustedNET(){};

};

