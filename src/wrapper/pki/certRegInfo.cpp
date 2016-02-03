#include "../stdafx.h"

#include "certRegInfo.h"
#include "key.h"

void CertificationRequestInfo::setSubject(Handle<std::string> xName) {
	LOGGER_FN();

	try{
		if (xName.isEmpty()){
			THROW_EXCEPTION(0, CertificationRequestInfo, NULL, "Parameter 1 can not be NULL");
		}

		LOGGER_OPENSSL(X509_NAME_new);
		X509_NAME *name = X509_NAME_new();

		std::string strName = xName->c_str();
		strName = strName + "/";

		std::string sl = "/";
		std::string eq = "=";

		size_t pos = 0, posInBuf = 0;

		std::string buf, field, param;

		while ((pos = strName.find(sl)) != std::string::npos)  {
			buf = strName.substr(0, pos);
			if (buf.length() > 0){
				posInBuf = buf.find(eq);
				field = buf.substr(0, posInBuf);
				param = buf.substr(posInBuf + 1, buf.length());

				LOGGER_OPENSSL(X509_NAME_add_entry_by_txt);
				if (!X509_NAME_add_entry_by_txt(name, field.c_str(), MBSTRING_ASC, (const unsigned char *)param.c_str(), -1, -1, 0)){
					THROW_OPENSSL_EXCEPTION(0, CertificationRequestInfo, NULL, "X509_NAME_add_entry_by_txt 'Unable add param to X509_NAME'");
				}
			}
			strName.erase(0, pos + sl.length());
		}
		
		LOGGER_OPENSSL(X509_NAME_dup);
		this->internal()->subject = X509_NAME_dup(name);
		if (name){
			LOGGER_OPENSSL(X509_NAME_free);
			X509_NAME_free(name);
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CertificationRequestInfo, e, "Error set subject to X509_REQ_info");
	}
}

void CertificationRequestInfo::setSubjectPublicKey(Handle<Key> key){
	LOGGER_FN();

	if (key.isEmpty()){
		THROW_EXCEPTION(0, CertificationRequestInfo, NULL, "Error set subject to X509_REQ_info");
	}

	LOGGER_OPENSSL(X509_PUBKEY_set);
	if (!X509_PUBKEY_set(&(this->internal()->pubkey), key->internal())){
		THROW_OPENSSL_EXCEPTION(0, CertificationRequestInfo, NULL, "X509_PUBKEY_set");
	}
}

void CertificationRequestInfo::setVersion(long version){
	LOGGER_FN();

	if (this->internal() == NULL){
		THROW_EXCEPTION(0, CertificationRequestInfo, NULL, "X509_REQ_info cannot be NULL");
	}

	LOGGER_OPENSSL(ASN1_INTEGER_set);
	if(!ASN1_INTEGER_set(this->internal()->version, version)){
		THROW_EXCEPTION(0, CertificationRequestInfo, NULL, "Error set version to X509_REQ_info");
	}
}