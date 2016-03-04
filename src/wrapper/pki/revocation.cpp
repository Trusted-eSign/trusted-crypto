#include "../stdafx.h"

#include "revocation.h"
#include "csr.h"

Handle<CRL> Revocation::getCRL(Handle<Certificate> cert, Handle<Provider_System> prvSys){
	LOGGER_FN();

	try{
		if (cert.isEmpty()){
			THROW_EXCEPTION(0, Revocation, NULL, ERROR_PARAMETER_NULL, 1);
		}

		X509_CRL *crl;
	//	if (!getCrlLocal(hcrl, cert, prvSys)){
			const char *crlURL = NULL;
			crlURL = getCRLDistPoint(cert);
			if (crlURL){
				//	hcrl = downloadCRL(crlURL);
			}
			if (hcrl.isEmpty()){
				THROW_EXCEPTION(0, Revocation, NULL, "Download crl is empty");
			}
	//	}
	
		if (hcrl.isEmpty()){
			THROW_EXCEPTION(0, Revocation, NULL, "crl is empty");
		}

		return hcrl;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Revocation, e, "Error get CRL");
	}
}

void Revocation::write(Handle<Bio> out, DataFormat::DATA_FORMAT format) {
	LOGGER_FN();

	try{
		if (out.isEmpty()){
			THROW_EXCEPTION(0, Revocation, NULL, ERROR_PARAMETER_NULL, 1);
		}
			
		switch (format){
		case DataFormat::DER:
			LOGGER_OPENSSL(i2d_X509_CRL_bio);
			if (!i2d_X509_CRL_bio(out->internal(), this->hcrl->internal())){
				THROW_OPENSSL_EXCEPTION(0, Revocation, NULL, "i2d_X509_CRL_bio");
			}				
			break;
		case DataFormat::BASE64:
			LOGGER_OPENSSL(PEM_write_bio_X509_CRL);
			if (!PEM_write_bio_X509_CRL(out->internal(), this->hcrl->internal())){
				THROW_OPENSSL_EXCEPTION(0, Revocation, NULL, "PEM_write_bio_X509_CRL");
			}				
			break;
		}
		out->flush();
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Revocation, e, "Error write CRL to file");
	}	
}

/*int Revocation::getCrlLocal(Handle<CRL> &crl, Handle<Certificate> cert, Handle<Provider_System> prvSys){
	LOGGER_FN();

	int ok = 0;

	try{
		int ret;
		STACK_OF(X509_CRL) *skCRL = prvSys->cert_store_system.crls;
		X509_CRL *xtempCRL = NULL;
		X509_NAME *certIss = NULL, *crlIss = NULL;

		LOGGER_OPENSSL(sk_X509_CRL_num);
		for (int i = 0, c = sk_X509_CRL_num(skCRL); i < c; i++){
			LOGGER_OPENSSL(sk_X509_CRL_value);
			xtempCRL = sk_X509_CRL_value(skCRL, i);
			if (!xtempCRL){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "sk_X509_CRL_value 'Unable get element of STACK_OF(X509_CRL)'");
			}

			LOGGER_OPENSSL(X509_get_issuer_name);
			certIss = X509_get_issuer_name(cert->internal());
			if (!certIss){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_get_issuer_name 'Unable get cert issuer name'");
			}

			LOGGER_OPENSSL(X509_CRL_get_issuer);
			crlIss = X509_CRL_get_issuer(xtempCRL);
			if (!crlIss){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_CRL_get_issuer 'Unable get CRL issuer name'");
			}

			LOGGER_OPENSSL(X509_NAME_cmp);
			if (X509_NAME_cmp(certIss, crlIss) == 0){
				LOGGER_OPENSSL(X509_check_akid);
				ret = X509_check_akid(cert->internal(), xtempCRL->akid);
				if (ret == X509_V_OK){
					crl = new CRL(xtempCRL);
					ok = 1;
					break;
				}
			}
		}
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return ok;
}*/


const char* Revocation::getCRLDistPoint(Handle<Certificate> cert){
	LOGGER_FN();

	const char *crlsUrl = NULL;
	bool bFound = false;

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
								bFound = true;
								break;
							}
						}
						LOGGER_OPENSSL(sk_GENERAL_NAME_free);
						sk_GENERAL_NAME_free(pNames);
						if (bFound) break;
					}
				}
			}
			LOGGER_OPENSSL(sk_DIST_POINT_free);
			sk_DIST_POINT_free(pStack);
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, Revocation, e, "Error get DP");
	}

	if (bFound){
		return crlsUrl;
	}
	else{
		return NULL;
	}
}