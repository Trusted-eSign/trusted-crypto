#include "../stdafx.h"

#include "chain.h"

Handle<CertificateCollection> Chain::buildChain(Handle<Certificate> cert, Handle<CertificateCollection> certs){
	LOGGER_FN();

	try{
		Handle<Certificate> issuer = new Certificate();

		Handle<CertificateCollection> chain = new CertificateCollection();
		//chain->push(cert);

		Handle<Certificate> xtemp = cert;

		do{
			if ((issuer = getIssued(certs, xtemp)).isEmpty()){
				THROW_EXCEPTION(0, Chain, NULL, "Undefined issuer certificate");
			}

			if (xtemp->compare(issuer) == 0){
				issuer.empty();
			}
			else{
				chain->push(issuer);
				xtemp = issuer;
			}

		} while (!issuer.isEmpty());

		return chain;
	
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Chain, e, "Error build chain (certificate collection)");
	}
}

/*Handle<CertificateCollection> Chain::buildChain(Handle<Certificate> cert, ProviderStore::PVD_STORE pvdStore){
	LOGGER_FN();

	try{
		switch (pvdStore){
		case ProviderStore::SYSTEM:

			break;
		case ProviderStore::MSCRYPTO:

			break;
		case ProviderStore::CRYPTOPRO:

			break;
		case ProviderStore::TCL:

			break;
		default:
			THROW_EXCEPTION(0, Chain, NULL, "Unknown provider");
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Chain, e, "Error build chain (provider store)");
	}
}*/

/*bool Chain::verifyChain(Handle<CertificateCollection> chain, Handle<ProviderSystem> prvSys){
	LOGGER_FN();

	try{
		Handle<CRL> crl;
		STACK_OF(X509_CRL) *crls = sk_X509_CRL_new_null();

		for (int i = 0, c = chain->length(); i < c; i++){
			Revocation *rv = new Revocation();
			crl = rv->getCRL(chain->items(i), prvSys);

			LOGGER_OPENSSL(sk_X509_CRL_push);
			sk_X509_CRL_push(crls, crl->internal());
		}

		X509_STORE_CTX *ctx;

		X509_STORE *st = X509_STORE_new();
		for (int i = 0, c = chain->length(); i < c; i++){
			X509_STORE_add_cert(st, chain->items(0)->internal());
		}

		for (int i = 0, c = sk_X509_CRL_num(crls); i < c; i++){
			X509_STORE_add_crl(st, sk_X509_CRL_value(crls, i));
		}

		

		LOGGER_OPENSSL(X509_STORE_CTX_init);
		X509_STORE_CTX_init(ctx, st, chain->items(0)->internal(), chain->internal());

		LOGGER_OPENSSL(X509_STORE_CTX_set0_crls);
		X509_STORE_CTX_set0_crls(ctx, crls);

		LOGGER_OPENSSL(X509_STORE_CTX_set_flags);
		X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK);
		X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK_ALL);

		LOGGER_OPENSSL(X509_verify_cert);
		if (X509_verify_cert(ctx) <= 0){
			THROW_OPENSSL_EXCEPTION(0, Chain, NULL, "Bad chain");
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Chain, e, "Error verify chain (provider store)");
	}	
}*/

Handle<Certificate> Chain::getIssued(Handle<CertificateCollection> certs, Handle<Certificate> cert){
	LOGGER_FN();

	try{
		int ret;

		for (int i = 0, c = certs->length(); i < c; i++){
			if (checkIssued(certs->items(i), cert)){
				return certs->items(i);
			}
		}

		return NULL;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Chain, e, "Error get issued");
	}
}

bool Chain::checkIssued(Handle<Certificate> issuer, Handle<Certificate> cert){
	LOGGER_FN();

	try{
		int ret;

		X509 *iss = NULL;
		iss = issuer->internal();
		if (!iss){
			THROW_EXCEPTION(0, Chain, NULL, "iss");
		}
		X509 *sub = NULL;
		sub = cert->internal();
		if (!sub){
			THROW_EXCEPTION(0, Chain, NULL, "sub");
		}

		LOGGER_OPENSSL(X509_check_issued);
		ret = X509_check_issued(iss, sub);
		if (ret == X509_V_OK){
			return 1;
		}
		else{
			return 0;
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Chain, e, "checkIssued");
	}	
}

