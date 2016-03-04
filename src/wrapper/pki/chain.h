#ifndef CMS_PKI_CHAIN_H_INCLUDED
#define  CMS_PKI_CHAIN_H_INCLUDED

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/x509.h>

#include "../common/common.h"

#include "../store/pkistore.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "certs.h"
#include "cert.h"
#include "revocation.h"

#include "../pki/crl.h"
#include "../store/provider_system.h"

class CTWRAPPER_API Chain;

class Chain{

public:
	Chain(){};
	~Chain(){};

	/* Build chain relative certificate collection */
	Handle<CertificateCollection> buildChain(Handle<Certificate> cert, Handle<CertificateCollection> certs);

	/* Build chain relative provider certificates store */
//	Handle<CertificateCollection> buildChain(Handle<Certificate> cert, ProviderStore::PVD_STORE pvdStore);

	/* Check cerificates in chain */
//	bool verifyChain(Handle<CertificateCollection> chain, Handle<ProviderSystem> prvSys);

private:
	Handle<Certificate> getIssued(Handle<CertificateCollection> certs, Handle<Certificate> cert);
	bool checkIssued(Handle<Certificate> issuer, Handle<Certificate> cert);



	int checkTrust(Handle<Certificate> cert);
};

#endif //!CMS_PKI_CHAIN_H_INCLUDED
