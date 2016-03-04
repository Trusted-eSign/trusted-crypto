#ifndef PKISTORE_H_INCLUDED
#define PKISTORE_H_INCLUDED

#include "../stdafx.h"

#include "../common/common.h"

#include "../pki/cert.h"
#include "../pki/certs.h"
#include "../pki/crl.h"
#include "../pki/key.h"
#include "../pki/csr.h"
#include "../pki/certReg.h"

#include "storehelper.h"
#include "cashjson.h"

class CTWRAPPER_API PkiStore;

class PkiStore {
public:
	PkiStore(){};
	PkiStore(Handle<std::string> json);
	~PkiStore(){};

public:
	Handle<CashJson> cash;

	Handle<PkiItemCollection> getItems();

	Handle<ProviderCollection> providers;

	void addProvider(Provider* provider);
	void deleteProvider(Handle<std::string> typeProvider);
	
	Handle<PkiItemCollection> find(Handle<Filter> filter);
	Handle<PkiItem> findKey(Handle<Filter> filter);

	Handle<Certificate> getItemCert(Handle<PkiItem> item);
	Handle<CRL> getItemCrl(Handle<PkiItem> item);
	Handle<Key> getItemKey(Handle<PkiItem> item);
	Handle<CertificationRequest> getItemReq(Handle<PkiItem> item);
};

#endif //PKISTORE_H_INCLUDED