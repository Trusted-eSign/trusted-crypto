#include "../stdafx.h"

#include "signer.h"

void Signer::setCertificate(Handle<Certificate> cert){
	LOGGER_FN();

	LOGGER_OPENSSL("CMS_SignerInfo_set1_signer_cert");
	CMS_SignerInfo_set1_signer_cert(this->internal(), cert->internal());
}

Handle<Certificate> Signer::getCertificate(){
	LOGGER_FN();

	X509 *cert;

	LOGGER_OPENSSL("CMS_SignerInfo_get0_algs");
	CMS_SignerInfo_get0_algs(this->internal(), NULL, &cert, NULL, NULL);

	if (!cert){
		THROW_EXCEPTION(0, Signer, NULL, "Signer hasn't got Certificate");
	}

	return new Certificate(cert, this->handle());
}

Handle<std::string> Signer::getSignature(){
	LOGGER_FN();

	
#ifndef CMS_SignerInfo_get0_signature
	THROW_EXCEPTION(0, Signer, NULL, "Mehtod is not implemented for current version of OpenSSL");
#else
	// Метод поддерживается начиная с версии OpenSSL v1.0.2
	LOGGER_OPENSSL("CMS_SignerInfo_get0_signature");
	ASN1_OCTET_STRING *sign = CMS_SignerInfo_get0_signature(this->internal());
	if (!sign){
		THROW_EXCEPTION(0, Signer, NULL, "Has no signature value");
	}

	char *buf = reinterpret_cast<char*>(sign->data);

	return new std::string(buf, sign->length);
#endif
}

Handle<SignerAttributeCollection> Signer::signedAttributes(){
	LOGGER_FN();

	Handle<SignerAttributeCollection> attrs = new SignerAttributeCollection(this, true);

	return attrs;
}

Handle<Attribute> Signer::signedAttributes(int index){
	LOGGER_FN();

	return this->signedAttributes()->items(index);
}

Handle<Attribute> Signer::signedAttributes(int index, int location){
	LOGGER_FN();

	return this->signedAttributes()->items(index, location);
}

Handle<Attribute> Signer::signedAttributes(Handle<OID> oid){
	LOGGER_FN();

	return this->signedAttributes()->items(oid);
}

Handle<Attribute> Signer::signedAttributes(Handle<OID> oid, int location){
	LOGGER_FN();

	return this->signedAttributes()->items(oid, location);
}

Handle<SignerAttributeCollection> Signer::unsignedAttributes(){
	LOGGER_FN();

	Handle<SignerAttributeCollection> attrs = new SignerAttributeCollection(this, false);

	return attrs;
}

Handle<Attribute> Signer::unsignedAttributes(int index){
	LOGGER_FN();

	return this->unsignedAttributes()->items(index);
}

Handle<Attribute> Signer::unsignedAttributes(int index, int location){
	LOGGER_FN();

	return this->unsignedAttributes()->items(index, location);
}

Handle<Attribute> Signer::unsignedAttributes(Handle<OID> oid){
	LOGGER_FN();

	return this->unsignedAttributes()->items(oid);
}

Handle<Attribute> Signer::unsignedAttributes(Handle<OID> oid, int location){
	LOGGER_FN();

	return this->unsignedAttributes()->items(oid, location);
}

void Signer::sign(){
	LOGGER_FN();

	LOGGER_OPENSSL("CMS_SignerInfo_sign");
	if (CMS_SignerInfo_sign(this->internal()) < 1){
		THROW_OPENSSL_EXCEPTION(0, Signer, NULL, "CMS_SignerInfo_sign");
	}
}

bool Signer::verify(){
	LOGGER_FN();

	LOGGER_OPENSSL("CMS_SignerInfo_verify");
	int res = CMS_SignerInfo_verify(this->internal());
	if (res == -1){
		THROW_OPENSSL_EXCEPTION(0, Signer, NULL, "CMS_SignerInfo_verify");
	}

	return res == 1;
}

bool Signer::verify(Handle<Bio> content){
	LOGGER_FN();

	LOGGER_OPENSSL("CMS_SignerInfo_verify_content");
	int res = CMS_SignerInfo_verify_content(this->internal(), content->internal());
	if (res == -1){
		THROW_OPENSSL_EXCEPTION(0, Signer, NULL, "CMS_SignerInfo_verify_content");
	}

	return res == 1;
}

Handle<CertificateId> Signer::getCertificateId(){
	LOGGER_FN();

	ASN1_OCTET_STRING *keyid = NULL;
	ASN1_INTEGER *sn = NULL;
	X509_NAME *issuerName = NULL;

	LOGGER_OPENSSL("CMS_SignerInfo_get0_signer_id");
	if (CMS_SignerInfo_get0_signer_id(this->internal(), &keyid, &issuerName, &sn) < 1){
		THROW_OPENSSL_EXCEPTION(0, Signer, NULL, "CMS_SignerInfo_get0_signer_id");
	}

	Handle<CertificateId> certId = new CertificateId();
	if (keyid){
		//convert ASN1_OCTET_STRING to String
		Handle<std::string> keyid_str = new std::string((char*)keyid->data, keyid->length);

		certId->setKeyId(keyid_str);
	}
	if (sn){
		//convert ASN1_INTEGER to String
		Handle<std::string> sn_str = new std::string((char*)sn->data, sn->length);

		certId->setSerialNumber(sn_str);
	}

	if (issuerName){
		//wrap X509_NAME to X509Name
		Handle<X509Name> name = new X509Name(issuerName, this->handle());

		certId->setIssuerName(name);
	}

	return certId;
}

Handle<Algorithm> Signer::getSignatureAlgorithm(){
	LOGGER_FN();

	X509_ALGOR *alg;

	LOGGER_OPENSSL("CMS_SignerInfo_get0_algs");
	CMS_SignerInfo_get0_algs(this->internal(), NULL, NULL, NULL, &alg);

	if (!alg){
		THROW_EXCEPTION(0, Signer, NULL, "Signer hasn't got signature algorithm");
	}

	return new Algorithm(alg, this->handle());
}

Handle<Algorithm> Signer::getDigestAlgorithm(){
	LOGGER_FN();

	X509_ALGOR *alg;

	LOGGER_OPENSSL("CMS_SignerInfo_get0_algs");
	CMS_SignerInfo_get0_algs(this->internal(), NULL, NULL, &alg, NULL);

	if (!alg){
		THROW_EXCEPTION(0, Signer, NULL, "Signer hasn't got digest algorithm");
	}

	return new Algorithm(alg, this->handle());
}