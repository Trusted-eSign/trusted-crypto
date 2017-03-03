#ifndef CMS_PKI_CHAIN_H_INCLUDED
#define  CMS_PKI_CHAIN_H_INCLUDED

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/x509.h>

#include "../common/common.h"

#include "../store/pkistore.h"

#include "certs.h"
#include "cert.h"
#include "crls.h"
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

	/* Check cerificates in chain */
	bool verifyChain(Handle<CertificateCollection> chain, Handle<CrlCollection> crls);

private:
	Handle<Certificate> getIssued(Handle<CertificateCollection> certs, Handle<Certificate> cert);
	bool checkIssued(Handle<Certificate> issuer, Handle<Certificate> cert);
};

#endif //!CMS_PKI_CHAIN_H_INCLUDED
