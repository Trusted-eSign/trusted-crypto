#include "../stdafx.h"

#include "wrapper/store/pkistore.h"

#include "wrapper/store/provider_system.h"
#if defined(OPENSSL_SYS_WINDOWS)
	#include "wrapper/store/provider_microsoft.h"
#endif
#if defined(CPROCSP)
	#include "wrapper/store/provider_cryptopro.h"
#endif

PkiStore::PkiStore(Handle<std::string> json){
	LOGGER_FN();
	
	try{
		if (json.isEmpty()){
			THROW_EXCEPTION(0, PkiStore, NULL, "json empty");
		}
		
		providers = new ProviderCollection();
		storeItemCollection = new PkiItemCollection();
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, PkiStore, e, "Cannot be constructed PkiStore(Handle<std::string> json)");
	}	
}

Handle<PkiItemCollection> PkiStore::find(Handle<Filter> filter){
	LOGGER_FN();

	try{
		if (storeItemCollection.isEmpty()){
			THROW_EXCEPTION(0, PkiStore, NULL, "Store no have pki elements");
		}

		return storeItemCollection->find(filter);
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, PkiStore, e, "Error search object");
	}
}

Handle<PkiItem> PkiStore::findKey(Handle<Filter> filter){
	LOGGER_FN();

	try{
		if (filter->hash.isEmpty()){
			THROW_EXCEPTION(0, PkiStore, NULL, "Need hash certificate\request for search key");
		}

		if (storeItemCollection.isEmpty()){
			THROW_EXCEPTION(0, PkiStore, NULL, "Store no have pki elements");
		}

		Handle<PkiItem> key = new PkiItem();

		for (int i = 0, c = storeItemCollection->length(); i < c; i++){
			bool result = 1;

			if (strcmp(storeItemCollection->items(i)->hash->c_str(), filter->hash->c_str()) == 0){
				result = 1;				
			}
			else{
				result = 0;
				continue;
			}

			if (result){
				Handle<std::string> keyHash;

				if (!(storeItemCollection->items(i)->certKey.isEmpty())){
					keyHash = storeItemCollection->items(i)->certKey;
				}
				else if (!(storeItemCollection->items(i)->csrKey.isEmpty())){
					keyHash = storeItemCollection->items(i)->csrKey;
				}
				else{
					THROW_EXCEPTION(0, PkiStore, NULL, "Object no have key");
				}

				for (int j = 0; j < storeItemCollection->length(); j++){
					if ((strcmp(storeItemCollection->items(j)->type->c_str(), "KEY") == 0) &&
						((strcmp(storeItemCollection->items(j)->hash->c_str(), keyHash->c_str()) == 0))){
						key = storeItemCollection->items(j);
						break;
					}
				}

				break;
			}
		}

		return key;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, PkiStore, e, "Error search key");
	}
}


Handle<Certificate> PkiStore::getItemCert(Handle<PkiItem> item){
	LOGGER_FN();

	try{
		if (storeItemCollection.isEmpty()){
			THROW_EXCEPTION(0, PkiStore, NULL, "Store no have pki elements");
		}

		Handle<Certificate> cert = NULL;

		if (strcmp(item->provider->c_str(), "SYSTEM") == 0){
			cert = Provider_System::getCertFromURI(item->uri, item->format);
		}
#if defined(OPENSSL_SYS_WINDOWS)
		else  if (strcmp(item->provider->c_str(), "MICROSOFT") == 0) {
			for (int i = 0, c = storeItemCollection->length(); i < c; i++){
				bool result = 1;

				if ((strcmp(storeItemCollection->items(i)->hash->c_str(), item->hash->c_str()) == 0) &&
					(strcmp(storeItemCollection->items(i)->provider->c_str(), item->provider->c_str()) == 0)){
					result = 1;
				}
				else{
					result = 0;
					continue;
				}

				if (result){
					if (!storeItemCollection->items(i)->certificate->isEmpty()) {
						cert = storeItemCollection->items(i)->certificate;
						break;
					}
				}
			}
		}
#endif
#if defined(CPROCSP)
		else  if (strcmp(item->provider->c_str(), "CRYPTOPRO") == 0){
			for (int i = 0, c = storeItemCollection->length(); i < c; i++){
				bool result = 1;

				if ((strcmp(storeItemCollection->items(i)->hash->c_str(), item->hash->c_str()) == 0) &&
					(strcmp(storeItemCollection->items(i)->provider->c_str(), item->provider->c_str()) == 0)){
					result = 1;
				}
				else{
					result = 0;
					continue;
				}

				if (result){
					if (!storeItemCollection->items(i)->certificate->isEmpty()) {
						cert = storeItemCollection->items(i)->certificate;
						break;
					}
				}
			}
		}
#endif
		else{
			THROW_EXCEPTION(0, PkiStore, NULL, "Provider type unsoported")
		}

		if (cert->isEmpty()) {
			THROW_EXCEPTION(0, PkiStore, NULL, "Error get certificate")
		}

		return cert;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, PkiStore, e, "Error get cert from store");
	}	
}

Handle<CRL> PkiStore::getItemCrl(Handle<PkiItem> item){
	LOGGER_FN();

	try{
		Handle<CRL> crl = new CRL();

		if (strcmp(item->provider->c_str(), "SYSTEM") == 0){
			crl = Provider_System::getCRLFromURI(item->uri, item->format);
		}
#if defined(OPENSSL_SYS_WINDOWS)
		else  if (strcmp(item->provider->c_str(), "MICROSOFT") == 0){
			crl = ProviderMicrosoft::getCRL(item->hash, item->category);
		}
#endif
#if defined(CPROCSP)
		else  if (strcmp(item->provider->c_str(), "CRYPTOPRO") == 0){
			crl = ProviderCryptopro::getCRL(item->hash, item->category);
		}
#endif
		else{
			THROW_EXCEPTION(0, PkiStore, NULL, "Provider type unsoported")
		}

		return crl;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, PkiStore, e, "Error get crl from store");
	}
}

Handle<CertificationRequest> PkiStore::getItemReq(Handle<PkiItem> item){
	LOGGER_FN();

	try{
		Handle<CertificationRequest> csr = new CertificationRequest();

		if (strcmp(item->provider->c_str(), "SYSTEM") == 0){
			csr = Provider_System::getCSRFromURI(item->uri, item->format);
		}
		else{
			THROW_EXCEPTION(0, PkiStore, NULL, "Provider type unsoported")
		}

		return csr;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, PkiStore, e, "Error get crl from store");
	}
}

Handle<Key> PkiStore::getItemKey(Handle<PkiItem> item){
	LOGGER_FN();

	try{
		Handle<Key> key = new Key();

		if (strcmp(item->provider->c_str(), "SYSTEM") == 0){
			key = Provider_System::getKeyFromURI(item->uri, item->format, item->keyEncrypted);
		}
		else{
			THROW_EXCEPTION(0, PkiStore, NULL, "Provider type unsoported")
		}

		return key;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, PkiStore, e, "Error get key from store");
	}
}


Handle<PkiItemCollection> PkiStore::getItems(){
	LOGGER_FN();

	return this->storeItemCollection;	
}

Handle<CertificateCollection> PkiStore::getCerts(){
	LOGGER_FN();

	try{
		Handle<CertificateCollection> result = new CertificateCollection();

		if (providers->length() == 0){
			THROW_EXCEPTION(0, PkiStore, NULL, "Collection providers empty");
		}

		for (int i = 0; i < providers->length(); i++){
			Handle<PkiItemCollection> tempColl;

			tempColl = providers->items(i)->getProviderItemCollection();

			for (int j = 0; j < tempColl->length(); j++){
				if (strcmp(tempColl->items(j)->type->c_str(), "CERTIFICATE") == 0){
					Handle<Certificate> cert = getItemCert(tempColl->items(j));
					result->push(cert);
				}
			}
		}

		return result;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, PkiStore, e, "Error get certs from store");
	}
}

void PkiStore::addProvider(Handle<Provider> provider) {
	LOGGER_FN();
	
	providers->push(provider);

	Handle<PkiItemCollection> tempColl = provider->getProviderItemCollection();
	for (int i = 0; i < tempColl->length(); i++) {
		this->storeItemCollection->push(tempColl->items(i));
	}
}

Handle<std::string> PkiStore::addPkiObject(Handle<Provider> provider, Handle<std::string> category, Handle<Certificate> cert){
	LOGGER_FN();

	try{
		if (strcmp(provider->type->c_str(), "SYSTEM") == 0){
			std::string uri = (std::string)provider->path->c_str() + CROSSPLATFORM_SLASH + (std::string)category->c_str() + CROSSPLATFORM_SLASH;

			char * hexHash;
			Handle<std::string> hhash = cert->getThumbprint();
			bin_to_strhex((unsigned char *)hhash->c_str(), hhash->length(), &hexHash);

			uri = uri + std::string(hexHash) + "_";

			EVP_PKEY *pkey;
			LOGGER_OPENSSL(BIO_new);
			BIO * bioBN = BIO_new(BIO_s_mem());
			LOGGER_OPENSSL(X509_get_pubkey);
			pkey = X509_get_pubkey(cert->internal());
			if (pkey == NULL) {
				THROW_OPENSSL_EXCEPTION(0, PkiStore, NULL, "Modulus=unavailable", NULL);
			}

			#ifndef OPENSSL_NO_RSA
			if (pkey->type == EVP_PKEY_RSA)
				BN_print(bioBN, pkey->pkey.rsa->n);
			else
			#endif
			#ifndef OPENSSL_NO_DSA
				if (pkey->type == EVP_PKEY_DSA)
					BN_print(bioBN, pkey->pkey.dsa->pub_key);
				else
#ifndef OPENSSL_NO_CTGOSTCP
					if (pkey->type == NID_id_GostR3410_94 || pkey->type == NID_id_GostR3410_2001
						|| pkey->type == NID_id_tc26_gost3410_12_256 || pkey->type == NID_id_tc26_gost3410_12_512)
					{
						EC_KEY *tkey;
						const EC_POINT *pubkey = NULL;
						LOGGER_OPENSSL(BN_CTX_new);
						BN_CTX *ctx = BN_CTX_new();
						if (!ctx) {
							THROW_OPENSSL_EXCEPTION(0, PkiStore, NULL, "Allocating memory failed", NULL);
						}
						BIGNUM *X = NULL, *Y = NULL;
						const EC_GROUP *group = NULL;
						EC_POINT *pub_key;

						LOGGER_OPENSSL(BN_CTX_start);
						BN_CTX_start(ctx);
						LOGGER_OPENSSL(BN_CTX_get);
						X = BN_CTX_get(ctx);
						LOGGER_OPENSSL(BN_CTX_get);
						Y = BN_CTX_get(ctx);

						tkey = pkey->pkey.ec;
						LOGGER_OPENSSL(EC_KEY_get0_public_key);
						pubkey = EC_KEY_get0_public_key(tkey);
						LOGGER_OPENSSL(EC_KEY_get0_group);
						group = EC_KEY_get0_group(tkey);
						LOGGER_OPENSSL(EC_POINT_get_affine_coordinates_GFp);
						if (!EC_POINT_get_affine_coordinates_GFp(group, pubkey, X, Y, ctx)) {
							THROW_OPENSSL_EXCEPTION(0, PkiStore, NULL, "Key is absent(not set)", NULL); 
						}
						LOGGER_OPENSSL(BN_print);
						BN_print(bioBN, X);
						LOGGER_OPENSSL(BN_print);
						BN_print(bioBN, Y);

						LOGGER_OPENSSL(BN_CTX_end);
						BN_CTX_end(ctx);
					}
					else{
						THROW_EXCEPTION(0, PkiStore, NULL, "Wrong Algorithm type");
					}
#endif
#ifdef OPENSSL_NO_CTGOSTCP
			THROW_EXCEPTION(0, PkiStore, NULL, "Wrong Algorithm type");
#endif
#endif
			LOGGER_OPENSSL(EVP_PKEY_free);
			EVP_PKEY_free(pkey);
			
			int contlen;
			char * cont;
			LOGGER_OPENSSL(BIO_get_mem_data);
			contlen = BIO_get_mem_data(bioBN, &cont);

			unsigned char tmphash[SHA_DIGEST_LENGTH];
			LOGGER_OPENSSL(SHA1);
			SHA1((const unsigned char *)cont, contlen, tmphash);
			bin_to_strhex(tmphash, SHA_DIGEST_LENGTH, &hexHash);

			uri = uri + std::string(reinterpret_cast<char*>(hexHash)) + ".crt";

			Handle<std::string> huri = new std::string(uri);

			LOGGER_OPENSSL(BIO_free_all);
			BIO_free_all(bioBN);

 			Provider_System::addPkiObject(huri, cert);
			return huri;
		}
#if defined(OPENSSL_SYS_WINDOWS)
		else if (strcmp(provider->type->c_str(), "MICROSOFT") == 0){
			ProviderMicrosoft::addPkiObject(cert, category);
			return new std::string("");
		}
#endif
#if defined(CPROCSP)
		else if (strcmp(provider->type->c_str(), "CRYPTOPRO") == 0){
			ProviderCryptopro::addPkiObject(cert, category);
			return new std::string("");
		}
#endif
		else{
			THROW_EXCEPTION(0, PkiStore, NULL, "Provider type unsoported")
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, PkiStore, e, "Error add certificate to store");
	}
}

Handle<std::string> PkiStore::addPkiObject(Handle<Provider> provider, Handle<std::string> category, Handle<CRL> crl){
	LOGGER_FN();

	try{
		if (strcmp(provider->type->c_str(), "SYSTEM") == 0){
			std::string uri = (std::string)provider->path->c_str() + CROSSPLATFORM_SLASH + (std::string)category->c_str() + CROSSPLATFORM_SLASH;

			char * hexHash;
			Handle<std::string> hhash = crl->getThumbprint();
			bin_to_strhex((unsigned char *)hhash->c_str(), hhash->length(), &hexHash);

			uri = uri + std::string(hexHash) + ".crl";

			Handle<std::string> huri = new std::string(uri);
			Provider_System::addPkiObject(huri, crl);
			return huri;
		}
		else{
			THROW_EXCEPTION(0, PkiStore, NULL, "Provider type unsoported")
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, PkiStore, e, "Error add crl to store");
	}
}

Handle<std::string> PkiStore::addPkiObject(Handle<Provider> provider, Handle<std::string> category, Handle<CertificationRequest> csr){
	LOGGER_FN();

	try{
		if (strcmp(provider->type->c_str(), "SYSTEM") == 0){
			std::string uri = (std::string)provider->path->c_str() + CROSSPLATFORM_SLASH + (std::string)category->c_str() + CROSSPLATFORM_SLASH;

			unsigned char hash[EVP_MAX_MD_SIZE] = { 0 };
			unsigned int hashlen = 0;
			LOGGER_OPENSSL(X509_digest);
			if (!X509_REQ_digest(csr->internal(), EVP_sha1(), hash, &hashlen)) {
				THROW_OPENSSL_EXCEPTION(0, Provider_System, NULL, "X509_REQ_digest");
			}
			Handle<std::string> hhash = new std::string((char *)hash, hashlen);

			char * hexHash;
			bin_to_strhex((unsigned char *)hhash->c_str(), hhash->length(), &hexHash);

			uri = uri + std::string(reinterpret_cast<char*>(hexHash)) + "_";

			EVP_PKEY *pkey;
			LOGGER_OPENSSL(BIO_new);
			BIO * bioBN = BIO_new(BIO_s_mem());
			LOGGER_OPENSSL(X509_REQ_get_pubkey);
			pkey = X509_REQ_get_pubkey(csr->internal());
			if (pkey == NULL) {
				THROW_OPENSSL_EXCEPTION(0, PkiStore, NULL, "Modulus=unavailable", NULL);
			}

			#ifndef OPENSSL_NO_RSA
			if (pkey->type == EVP_PKEY_RSA)
				BN_print(bioBN, pkey->pkey.rsa->n);
			else
				#endif
			#ifndef OPENSSL_NO_DSA
				if (pkey->type == EVP_PKEY_DSA)
					BN_print(bioBN, pkey->pkey.dsa->pub_key);
				else
			#endif

			LOGGER_OPENSSL(EVP_PKEY_free);
			EVP_PKEY_free(pkey);

			int contlen;
			char * cont;
			LOGGER_OPENSSL(BIO_get_mem_data);
			contlen = BIO_get_mem_data(bioBN, &cont);

			unsigned char tmphash[SHA_DIGEST_LENGTH];
			LOGGER_OPENSSL(SHA1);
			SHA1((const unsigned char *)cont, contlen, tmphash);
			bin_to_strhex(tmphash, SHA_DIGEST_LENGTH, &hexHash);

			uri = uri + std::string(reinterpret_cast<char*>(hexHash)) + ".csr";

			Handle<std::string> huri = new std::string(uri);

			LOGGER_OPENSSL(BIO_free_all);
			BIO_free_all(bioBN);

			Provider_System::addPkiObject(huri, csr);
			return huri;
		}
		else{
			THROW_EXCEPTION(0, PkiStore, NULL, "Provider type unsoported")
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, PkiStore, e, "Error add csr to store");
	}
}

Handle<std::string> PkiStore::addPkiObject(Handle<Provider> provider, Handle<Key> key, Handle<std::string> password){
	LOGGER_FN();

	try{
		EVP_PKEY *pkey = key->internal();

		if (strcmp(provider->type->c_str(), "SYSTEM") == 0) {
			std::string uri = (std::string)provider->path->c_str() + CROSSPLATFORM_SLASH + "MY" + CROSSPLATFORM_SLASH;

			char * hexHash;
			int contlen;
			char * cont;

			LOGGER_OPENSSL(BIO_new);
			BIO * bioBN = BIO_new(BIO_s_mem());

#ifndef OPENSSL_NO_RSA
			if (pkey->type == EVP_PKEY_RSA)
				BN_print(bioBN, key->internal()->pkey.rsa->n);
			else
#endif
#ifndef OPENSSL_NO_DSA
				if (key->internal()->type == EVP_PKEY_DSA)
					BN_print(bioBN, pkey->pkey.dsa->pub_key);
				else
#ifndef OPENSSL_NO_CTGOSTCP
					if (pkey->type == NID_id_GostR3410_94 || pkey->type == NID_id_GostR3410_2001
						|| pkey->type == NID_id_tc26_gost3410_12_256 || pkey->type == NID_id_tc26_gost3410_12_512)
					{
						Handle<Bio> pPub = new Bio(BIO_TYPE_MEM, "");

						LOGGER_OPENSSL(PEM_write_bio_PUBKEY);
						if (!PEM_write_bio_PUBKEY(pPub->internal(), pkey)){
							THROW_OPENSSL_EXCEPTION(0, Key, NULL, "PEM_write_bio_PUBKEY 'Unable writes PUBKEY to BIO'");
						}

						EVP_PKEY *pubEvpPkey = PEM_read_bio_PUBKEY(pPub->internal(), NULL, 0, NULL);

						EC_KEY *tkey;
						const EC_POINT *pubkey = NULL;
						LOGGER_OPENSSL(BN_CTX_new);
						BN_CTX *ctx = BN_CTX_new();
						if (!ctx) {
							THROW_OPENSSL_EXCEPTION(0, PkiStore, NULL, "Allocating memory failed", NULL);
						}
						BIGNUM *X = NULL, *Y = NULL;
						const EC_GROUP *group = NULL;
						EC_POINT *pub_key;

						LOGGER_OPENSSL(BN_CTX_start);
						BN_CTX_start(ctx);
						LOGGER_OPENSSL(BN_CTX_get);
						X = BN_CTX_get(ctx);
						LOGGER_OPENSSL(BN_CTX_get);
						Y = BN_CTX_get(ctx);

						tkey = pubEvpPkey->pkey.ec;
						LOGGER_OPENSSL(EC_KEY_get0_public_key);
						pubkey = EC_KEY_get0_public_key(tkey);
						LOGGER_OPENSSL(EC_KEY_get0_group);
						group = EC_KEY_get0_group(tkey);
						LOGGER_OPENSSL(EC_POINT_get_affine_coordinates_GFp);
						if (!EC_POINT_get_affine_coordinates_GFp(group, pubkey, X, Y, ctx)) {
							THROW_OPENSSL_EXCEPTION(0, PkiStore, NULL, "Key is absent(not set)", NULL);
						}
						LOGGER_OPENSSL(BN_print);
						BN_print(bioBN, X);
						LOGGER_OPENSSL(BN_print);
						BN_print(bioBN, Y);

						LOGGER_OPENSSL(BN_CTX_end);
						BN_CTX_end(ctx);
					}
					else {
						THROW_EXCEPTION(0, PkiStore, NULL, "Wrong Algorithm type");
					}

					
#endif
#ifdef OPENSSL_NO_CTGOSTCP
				THROW_EXCEPTION(0, PkiStore, NULL, "Wrong Algorithm type");
#endif
#endif
				LOGGER_OPENSSL(BIO_get_mem_data);
				contlen = BIO_get_mem_data(bioBN, &cont);

				unsigned char tmphash[SHA_DIGEST_LENGTH];
				LOGGER_OPENSSL(SHA1);
				SHA1((const unsigned char *)cont, contlen, tmphash);
				bin_to_strhex(tmphash, SHA_DIGEST_LENGTH, &hexHash);

				Handle<std::string> res = new std::string(reinterpret_cast<char*>(hexHash));

				LOGGER_OPENSSL(BIO_free_all);
				BIO_free_all(bioBN);

				uri = uri + std::string(reinterpret_cast<char*>(hexHash)) + ".key";

				Handle<std::string> huri = new std::string(uri);

				Provider_System::addPkiObject(huri, key, password);
				return huri;
		}
		else{
			THROW_EXCEPTION(0, PkiStore, NULL, "Provider type unsoported")
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, PkiStore, e, "Error add key to store");
	}
}

void PkiStore::deletePkiObject(Handle<Provider> provider, Handle<std::string> category, Handle<Certificate> cert){
	LOGGER_FN();

	try{
		if (strcmp(provider->type->c_str(), "SYSTEM") == 0){
			THROW_EXCEPTION(0, PkiStore, NULL, "Provider type unsoported")
		}
#if defined(OPENSSL_SYS_WINDOWS)
		else if (strcmp(provider->type->c_str(), "MICROSOFT") == 0){
			ProviderMicrosoft::deletePkiObject(cert, category);
		}
#endif
#if defined(CPROCSP)
		else if (strcmp(provider->type->c_str(), "CRYPTOPRO") == 0){
			ProviderCryptopro::deletePkiObject(cert, category);
		}
#endif
		else{
			THROW_EXCEPTION(0, PkiStore, NULL, "Provider type unsoported")
		}
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, PkiStore, e, "Error delete certificate from store");
	}
}

void PkiStore::bin_to_strhex(unsigned char *bin, unsigned int binsz, char **result){
	LOGGER_FN();

	char hex_str[] = "0123456789abcdef";
	unsigned int  i;

	*result = (char *)malloc(binsz * 2 + 1);
	(*result)[binsz * 2] = 0;

	if (!binsz)	return;

	for (i = 0; i < binsz; i++){
		(*result)[i * 2 + 0] = hex_str[(bin[i] >> 4) & 0x0F];
		(*result)[i * 2 + 1] = hex_str[(bin[i]) & 0x0F];
	}
}