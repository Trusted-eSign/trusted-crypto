#include "../stdafx.h"

#include "wrapper/pki/revocation.h"

Handle<CRL> Revocation::getCrlLocal(Handle<Certificate> cert, Handle<PkiStore> pkiStore){
	LOGGER_FN();

	try{
		int ret;
		Handle<Filter> filter = new Filter();
		filter->types.push_back(new std::string("CRL"));

		Handle<PkiItemCollection> filteredItems = pkiStore->find(filter);

		STACK_OF(X509_CRL) *skCRL = NULL;

		LOGGER_OPENSSL(sk_X509_CRL_new_null);
		if ((skCRL = sk_X509_CRL_new_null()) == NULL){
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
					return new CRL(xtempCRL);
				}
			}
		}

		return new CRL();
	}
	catch (Handle<Exception> &e){
		THROW_EXCEPTION(0, Revocation, e, "Error get CRL local");
	}
}

bool Revocation::checkCrlTime(Handle<CRL> hcrl) {
	LOGGER_FN();

	try{
		X509_CRL *crl = hcrl->internal();
		if (!crl) {
			THROW_EXCEPTION(0, Revocation, NULL, "Unable get current machine time");
		}

		time_t ptime;
		int i;

		ptime = time(0);
		if (!ptime){
			THROW_EXCEPTION(0, Revocation, NULL, "Unable get current machine time");
		}

		LOGGER_OPENSSL(X509_cmp_time);
		i = X509_cmp_time(X509_CRL_get_lastUpdate(crl), &ptime);
		if (i == 0){
			THROW_OPENSSL_EXCEPTION(0, Revocation, NULL, "X509_cmp_time 'Error in CRL last update field'");
		}

		if (i > 0){
			THROW_OPENSSL_EXCEPTION(0, Revocation, NULL, "X509_cmp_time 'CRL not yet valid'");
		}

		LOGGER_OPENSSL(X509_CRL_get_nextUpdate);
		if (X509_CRL_get_nextUpdate(crl)){
			LOGGER_OPENSSL(X509_cmp_time);
			i = X509_cmp_time(X509_CRL_get_nextUpdate(crl), &ptime);

			if (i == 0){
				THROW_OPENSSL_EXCEPTION(0, Revocation, NULL, "X509_cmp_time 'Error in CRL next update field'");
			}

			if (i < 0){
				THROW_OPENSSL_EXCEPTION(0, Revocation, NULL, "X509_cmp_time 'CRL has expired'");
			}
		}
	}
	catch (Handle<Exception> &e){
		return 0;
	}

	return 1;
}

std::vector<std::string> Revocation::getCrlDistPoints(Handle<Certificate> cert){
	LOGGER_FN();

	std::vector<std::string> res;
	const char *crlsUrl = NULL;

	try{
		STACK_OF(DIST_POINT)* pStack = NULL;
		LOGGER_OPENSSL(X509_get_ext_d2i);
		pStack = (STACK_OF(DIST_POINT)*) X509_get_ext_d2i(cert->internal(), NID_crl_distribution_points, NULL, NULL);
		if (pStack){
			LOGGER_OPENSSL(sk_DIST_POINT_num);
			for (int j = 0; j < sk_DIST_POINT_num(pStack); j++){
				LOGGER_OPENSSL(sk_DIST_POINT_value);
				DIST_POINT *pRes = (DIST_POINT *)sk_DIST_POINT_value(pStack, j);
				if (pRes != NULL){
					STACK_OF(GENERAL_NAME) *pNames = pRes->distpoint->name.fullname;
					if (pNames){
						LOGGER_OPENSSL(sk_GENERAL_NAME_num);
						for (int i = 0; i < sk_GENERAL_NAME_num(pNames); i++){
							LOGGER_OPENSSL(sk_GENERAL_NAME_value);
							GENERAL_NAME *pName = sk_GENERAL_NAME_value(pNames, i);
							if (pName != NULL && pName->type == GEN_URI){
								LOGGER_OPENSSL(ASN1_STRING_data);
								crlsUrl = (const char *)ASN1_STRING_data(pName->d.uniformResourceIdentifier);
								res.push_back(crlsUrl);
								break;
							}
						}
						LOGGER_OPENSSL(sk_GENERAL_NAME_free);
						sk_GENERAL_NAME_free(pNames);
					}
				}
			}
			LOGGER_OPENSSL(sk_DIST_POINT_free);
			sk_DIST_POINT_free(pStack);
		}
	}
	catch (Handle<Exception> &e){
		THROW_EXCEPTION(0, Revocation, e, "Error get DP");
	}

	return res;
}
