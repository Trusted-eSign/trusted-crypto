#include "../stdafx.h"

#include "revocation.h"
#include "csr.h"

Handle<CRL> Revocation::getCRL(Handle<Certificate> cert, Handle<PkiStore> pkiStore){
	LOGGER_FN();

	try{
		if (cert.isEmpty()){
			THROW_EXCEPTION(0, Revocation, NULL, ERROR_PARAMETER_NULL, 1);
		}

		Handle<CRL> hcrl;
		if (!getCrlLocal(hcrl, cert, pkiStore)) {
			if (hcrl.isEmpty()){
				THROW_EXCEPTION(0, Revocation, NULL, "crl is empty");
			}
		}	

		return hcrl;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Revocation, e, "Error get CRL");
	}
}

boolean Revocation::getCrlLocal(Handle<CRL> &outCrl, Handle<Certificate> cert, Handle<PkiStore> pkiStore){
	LOGGER_FN();

	try{
		int ret;
		Handle<Filter> filter = new Filter();
		filter->types.push_back(new std::string("CRL"));

		Handle<PkiItemCollection> filteredItems = new PkiItemCollection();	
		filteredItems = pkiStore->find(filter);

		STACK_OF(X509_CRL) *skCRL = NULL;

		LOGGER_OPENSSL(sk_X509_CRL_new_null);
		if (skCRL == NULL && (skCRL = sk_X509_CRL_new_null()) == NULL){
			THROW_OPENSSL_EXCEPTION(0, Revocation, NULL, "Error init stack of X509_CRL");
		}

		for (int i = 0; i < filteredItems->length(); i++) {
			X509_CRL *dupCrl = NULL;
			LOGGER_OPENSSL(X509_CRL_dup);
			dupCrl = X509_CRL_dup((pkiStore->getItemCrl(filteredItems->items(i)))->internal());
			if (!dupCrl) {
				THROW_OPENSSL_EXCEPTION(0, Revocation, NULL, "Error duplicate CRl");
			}
			LOGGER_OPENSSL(sk_X509_CRL_push);		
			if (!sk_X509_CRL_push(skCRL, dupCrl)) {
				THROW_OPENSSL_EXCEPTION(0, Revocation, NULL, "sk_X509_CRL_push 'Error push CRL'");
			}
		}

		X509_CRL *xtempCRL = NULL;
		X509_NAME *certIss = NULL, *crlIss = NULL;

		LOGGER_OPENSSL(sk_X509_CRL_num);
		for (int i = 0, c = sk_X509_CRL_num(skCRL); i < c; i++){
			LOGGER_OPENSSL(sk_X509_CRL_value);
			xtempCRL = sk_X509_CRL_value(skCRL, i);
			if (xtempCRL == NULL){
				THROW_OPENSSL_EXCEPTION(0, Revocation, NULL, "sk_X509_CRL_value 'Unable get element of STACK_OF(X509_CRL)'");
			}

			LOGGER_OPENSSL(X509_get_issuer_name);
			certIss = X509_get_issuer_name(cert->internal());
			if (!certIss){
				THROW_OPENSSL_EXCEPTION(0, Revocation, NULL, "X509_get_issuer_name 'Unable get cert issuer name'");
			}

			LOGGER_OPENSSL(X509_CRL_get_issuer);
			crlIss = X509_CRL_get_issuer(xtempCRL);
			if (!crlIss){
				THROW_OPENSSL_EXCEPTION(0, Revocation, NULL, "X509_CRL_get_issuer 'Unable get CRL issuer name'");
			}

			LOGGER_OPENSSL(X509_NAME_cmp);
			if (X509_NAME_cmp(certIss, crlIss) == 0){
				LOGGER_OPENSSL(X509_check_akid);
				ret = X509_check_akid(cert->internal(), xtempCRL->akid);
				if (ret == X509_V_OK){
					outCrl = new CRL(xtempCRL);
					return true;
				}
			}
		}

		return false;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Revocation, e, "Error get CRL local");
	}
}
