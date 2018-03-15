#ifndef CMS_SIGNER_H_INCLUDED
#define  CMS_SIGNER_H_INCLUDED

#include "common.h"
#include "./signer_id.h"

static void CMS_SignerInfo_free_ex(void *si){};

class Signer : public SSLObject < CMS_SignerInfo > {
public:
	//Constructor
	Signer(CMS_SignerInfo *data, Handle<SObject> parent)
		: SSLObject<CMS_SignerInfo>(data, &CMS_SignerInfo_free_ex, parent){}

	//Properties
	void setCertificate(Handle<Certificate> cert);
	Handle<Certificate> getCertificate();
	Handle<std::string> getSignature();
	Handle<Algorithm> getSignatureAlgorithm();
	Handle<Algorithm> getDigestAlgorithm();

	//Methods
	Handle<SignerAttributeCollection> signedAttributes();
	Handle<Attribute> signedAttributes(int index);
	Handle<Attribute> signedAttributes(int index, int location);
	Handle<Attribute> signedAttributes(Handle<OID> oid);
	Handle<Attribute> signedAttributes(Handle<OID> oid, int location);
	Handle<SignerAttributeCollection> unsignedAttributes();
	Handle<Attribute> unsignedAttributes(int index);
	Handle<Attribute> unsignedAttributes(int index, int location);
	Handle<Attribute> unsignedAttributes(Handle<OID> oid);
	Handle<Attribute> unsignedAttributes(Handle<OID> oid, int location);
	Handle<std::string> getSigningTime();
	void sign();
	bool verify();
	bool verify(Handle<Bio> content);
	Handle<SignerId> getSignerId();

protected:

};

#endif  //!CMS_SIGNER_H_INCLUDED

