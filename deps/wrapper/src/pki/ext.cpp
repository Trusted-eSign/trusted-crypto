#include "../stdafx.h"

#include "wrapper/pki/ext.h"

Extension::Extension(Handle<OID> oid, Handle<std::string> value)
	:SSLObject<X509_EXTENSION>(X509_EXTENSION_new(), &so_X509_EXTENSION_free) {
	LOGGER_FN();

	try {
		X509_EXTENSION *ex = NULL;

		X509V3_CTX ctx;
		X509V3_set_ctx_test(&ctx);

		LOGGER_OPENSSL(X509V3_EXT_conf_nid);
		if (!(ex = X509V3_EXT_conf_nid(NULL, &ctx, oid->toNid(), (char *)value->c_str()))) {
			THROW_OPENSSL_EXCEPTION(0, Extension, NULL, "X509V3_EXT_conf_nid");
		}

		this->setData(ex);
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, Extension, e, "Error Extension constructor");
	}	
}

Handle<OID> Extension::getTypeId() {
	LOGGER_FN();

	if (this->internal() && this->internal()->object) {
		Handle<OID> res = new OID(this->internal()->object);
		return res;
	}
	return NULL;
}

void Extension::setTypeId(Handle<OID> &oid) {
	LOGGER_FN();

	LOGGER_OPENSSL(X509_EXTENSION_set_object);
	if (!X509_EXTENSION_set_object(this->internal(), oid->internal())) {
		THROW_OPENSSL_EXCEPTION(0, Extension, NULL, "X509_EXTENSION_set_object");
	}
}

void Extension::setTypeId(std::string oid) {
	LOGGER_FN();

	try {
		Handle<OID> _oid = new OID(oid);
		this->setTypeId(_oid);
	}
	catch (Handle<Exception> e) {
		THROW_EXCEPTION(0, Extension, e, "Error set typeId");
	}
}

bool Extension::getCritical() {
	LOGGER_FN();

	LOGGER_OPENSSL(X509_EXTENSION_get_critical);
	return X509_EXTENSION_get_critical(this->internal());
}

void Extension::setCritical(bool critical) {
	LOGGER_FN();

	LOGGER_OPENSSL(X509_EXTENSION_set_critical);
	if (!X509_EXTENSION_set_critical(this->internal(), critical)) {
		THROW_OPENSSL_EXCEPTION(0, Extension, NULL, "Error set critical");
	}
}
