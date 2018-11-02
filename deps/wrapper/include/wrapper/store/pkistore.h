#ifndef PKISTORE_H_INCLUDED
#define PKISTORE_H_INCLUDED

#include "../stdafx.h"

#include "../common/common.h"

#include "../pki/cert.h"
#include "../pki/certs.h"
#include "../pki/crl.h"
#include "../pki/key.h"
#include "../pki/cert_request.h"

#include "storehelper.h"
#include "cashjson.h"

class CTWRAPPER_API PkiStore;

class PkiStore {
public:
	PkiStore(Handle<std::string> json);
	~PkiStore(){};

public:
	Handle<CertificateCollection> getCerts();
	Handle<PkiItemCollection> getItems();

	void addProvider(Handle<Provider> provider);
	void deleteProvider(Handle<std::string> typeProvider);
	
	Handle<PkiItemCollection> find(Handle<Filter> filter);
	Handle<PkiItem> findKey(Handle<Filter> filter);

	Handle<Certificate> getItemCert(Handle<PkiItem> item);
	Handle<CRL> getItemCrl(Handle<PkiItem> item);
	Handle<Key> getItemKey(Handle<PkiItem> item);
	Handle<CertificationRequest> getItemReq(Handle<PkiItem> item);

	Handle<std::string> addPkiObject(Handle<Provider> provider, Handle<std::string> category, Handle<Certificate> cert, Handle<std::string> contName = new std::string(), int provType = NULL);
	Handle<std::string> addPkiObject(Handle<Provider> provider, Handle<std::string> category, Handle<CRL> crl);
	Handle<std::string> addPkiObject(Handle<Provider> provider, Handle<std::string> category, Handle<CertificationRequest> csr);
	Handle<std::string> addPkiObject(Handle<Provider> provider, Handle<Key> key, Handle<std::string> password);

	void deletePkiObject(Handle<Provider> provider, Handle<std::string> category, Handle<Certificate> cert);
	void deletePkiObject(Handle<Provider> provider, Handle<std::string> category, Handle<CRL> crl);

	static void bin_to_strhex(unsigned char *bin, unsigned int binsz, char **result);

private:
	Handle<ProviderCollection> providers;
	Handle<PkiItemCollection> storeItemCollection;
};

#endif //PKISTORE_H_INCLUDED