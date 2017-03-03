#include "../stdafx.h"

#include "wrapper/cms/cmsRecipientInfo.h"

DECLARE_STACK_OF(CMS_RecipientInfo)

void CmsRecipientInfo::setValue(CMS_RecipientInfo *ri) {
	LOGGER_FN();

	try{
		if (!ri) {
			THROW_EXCEPTION(0, CmsRecipientInfo, NULL, "RecipientInfo cannot be empty");
		}
		this->ri = ri;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CmsRecipientInfo, e, "Cannot be constructed CmsRecipientInfo(CMS_RecipientInfo *ri)");
	}	
}

Handle<std::string> CmsRecipientInfo::getIssuerName() {
	LOGGER_FN();

	try{
		X509_NAME *issuer = NULL;

		LOGGER_OPENSSL(CMS_RecipientInfo_ktri_get0_signer_id);
		if (!CMS_RecipientInfo_ktri_get0_signer_id(this->ri, NULL, &issuer, NULL)) {
			THROW_OPENSSL_EXCEPTION(0, CmsRecipientInfo, NULL, "CMS_RecipientInfo_ktri_get0_signer_id");
		}

		if (!issuer) {
			THROW_EXCEPTION(0, CmsRecipientInfo, NULL, "X509_NAME is NULL");
		}

		LOGGER_OPENSSL(X509_NAME_oneline_ex);
		std::string str_name = X509_NAME_oneline_ex(issuer);

		Handle<std::string> res = new std::string(str_name.c_str(), str_name.length());

		return res;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CmsRecipientInfo, e, "Error get issuer name");
	}
}

Handle<std::string> CmsRecipientInfo::getSerialNumber() {
	LOGGER_FN();

	try {
		ASN1_INTEGER *sno = NULL;

		LOGGER_OPENSSL(CMS_RecipientInfo_ktri_get0_signer_id);
		if (!CMS_RecipientInfo_ktri_get0_signer_id(this->ri, NULL, NULL, &sno)) {
			THROW_OPENSSL_EXCEPTION(0, CmsRecipientInfo, NULL, "CMS_RecipientInfo_ktri_get0_signer_id");
		}

		if (!sno) {
			THROW_EXCEPTION(0, CmsRecipientInfo, NULL, "ASN1_INTEGER is NULL");
		}

		LOGGER_OPENSSL(BIO_new);
		BIO * bioSerial = BIO_new(BIO_s_mem());
		LOGGER_OPENSSL(i2a_ASN1_INTEGER);
		if (i2a_ASN1_INTEGER(bioSerial, sno) < 0){
			THROW_OPENSSL_EXCEPTION(0, CmsRecipientInfo, NULL, "i2a_ASN1_INTEGER", NULL);
		}

		int contlen;
		char * cont;
		LOGGER_OPENSSL(BIO_get_mem_data);
		contlen = BIO_get_mem_data(bioSerial, &cont);

		Handle<std::string> res = new std::string(cont, contlen);

		BIO_free(bioSerial);

		return res;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CmsRecipientInfo, e, "Error get serial number");
	}	
}

int CmsRecipientInfo::ktriCertCmp(Handle<Certificate> cert){
	LOGGER_FN();

	LOGGER_OPENSSL(CMS_RecipientInfo_ktri_cert_cmp);
	int res = CMS_RecipientInfo_ktri_cert_cmp(this->ri, cert->internal());

	return res;
}
