#include "../stdafx.h"

#include "wrapper/cms/signer_attrs.h"

SignerAttributeCollection::SignerAttributeCollection(Handle<Signer> signer, bool signed_attr){
	this->signer = signer;
	this->signed_attr = signed_attr;
}

int SignerAttributeCollection::length(){
	LOGGER_FN();

	int res = 0;

	if (this->signed_attr){
		LOGGER_OPENSSL("CMS_signed_get_attr_count");
		res = CMS_signed_get_attr_count(this->signer->internal());
	}
	else{
		LOGGER_OPENSSL("CMS_unsigned_get_attr_count");
		res = CMS_unsigned_get_attr_count(this->signer->internal());
	}

	return res;
}

Handle<Attribute> SignerAttributeCollection::items(int index, int location){
	LOGGER_FN();

	X509_ATTRIBUTE *attr;

	if (this->signed_attr){
		LOGGER_OPENSSL("CMS_signed_get_attr_count");
		attr = CMS_signed_get_attr(this->signer->internal(), index);
		if (!attr){
			THROW_OPENSSL_EXCEPTION(0, SignerAttributeCollection, NULL, "CMS_signed_get_attr_count");
		}
	}
	else{
		LOGGER_OPENSSL("CMS_unsigned_get_attr_count");
		attr = CMS_unsigned_get_attr(this->signer->internal(), index);
		if (!attr){
			THROW_OPENSSL_EXCEPTION(0, SignerAttributeCollection, NULL, "CMS_unsigned_get_attr_count");
		}
	}

	Handle<Attribute> res = new Attribute(attr, this->signer->handle());

	return res;
}

Handle<Attribute> SignerAttributeCollection::items(int index){
	LOGGER_FN();

	return this->items(index, 0);
}

Handle<Attribute> SignerAttributeCollection::items(Handle<OID> oid, int location){
	LOGGER_FN();

	int index;

	if (this->signed_attr){
		LOGGER_OPENSSL("CMS_signed_get_attr_by_OBJ");
		index = CMS_signed_get_attr_by_OBJ(this->signer->internal(), oid->internal(), location);
	}
	else{
		LOGGER_OPENSSL("CMS_unsigned_get_attr_by_OBJ");
		index = CMS_unsigned_get_attr_by_OBJ(this->signer->internal(), oid->internal(), location);
	}

	return this->items(index, location);
}

Handle<Attribute> SignerAttributeCollection::items(Handle<OID> oid){
	LOGGER_FN();

	return this->items(oid, 0);
}

void SignerAttributeCollection::push(Handle<Attribute> attr){
	LOGGER_FN();

	if (this->signed_attr){
		LOGGER_OPENSSL("CMS_signed_add1_attr");
		if (CMS_signed_add1_attr(this->signer->internal(), attr->internal()) < 1){
			THROW_OPENSSL_EXCEPTION(0, SignerAttributeCollection, NULL, "CMS_signed_add1_attr");
		}
	}
	else{
		LOGGER_OPENSSL("CMS_unsigned_add1_attr");
		if (CMS_unsigned_add1_attr(this->signer->internal(), attr->internal()) < 1){
			THROW_OPENSSL_EXCEPTION(0, SignerAttributeCollection, NULL, "CMS_unsigned_add1_attr");
		}
	}
}

void SignerAttributeCollection::removeAt(int index){
	LOGGER_FN();

	X509_ATTRIBUTE *attr;

	if (this->signed_attr){
		LOGGER_OPENSSL("CMS_signed_delete_attr");
		attr = CMS_signed_delete_attr(this->signer->internal(), index);
		if (!attr){
			THROW_OPENSSL_EXCEPTION(0, SignerAttributeCollection, NULL, "CMS_signed_delete_attr");
		}
	}
	else{
		LOGGER_OPENSSL("CMS_ãòsigned_delete_attr");
		attr = CMS_unsigned_delete_attr(this->signer->internal(), index);
		if (!attr){
			THROW_OPENSSL_EXCEPTION(0, SignerAttributeCollection, NULL, "CMS_unsigned_delete_attr");
		}
	}

	X509_ATTRIBUTE_free(attr);
}