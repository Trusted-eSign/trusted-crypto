#include "../stdafx.h"

#include "wrapper/pki/exts.h"

void ExtensionCollection::push(Handle<Extension> ext) {
	LOGGER_FN();

	if (this->isEmpty()){
		LOGGER_OPENSSL("sk_X509_EXTENSION_new_null");
		this->setData(sk_X509_EXTENSION_new_null());
	}

	LOGGER_OPENSSL(X509_EXTENSION_dup);
	X509_EXTENSION *_ext = X509_EXTENSION_dup(ext->internal());
	if (!_ext) {
		THROW_EXCEPTION(0, ExtensionCollection, NULL, "X509_EXTENSION_dup");
	}
	
	LOGGER_OPENSSL(sk_X509_EXTENSION_push);
	sk_X509_EXTENSION_push(this->internal(), _ext);
}

void ExtensionCollection::pop() {
	LOGGER_FN();

	LOGGER_OPENSSL(sk_X509_EXTENSION_pop);
	sk_X509_EXTENSION_pop(this->internal());
}

Handle<Extension> ExtensionCollection::items(int index) {
	LOGGER_FN();

	LOGGER_OPENSSL(sk_X509_EXTENSION_value);
	X509_EXTENSION *res = sk_X509_EXTENSION_value(this->internal(), index);

	if (!res){
		THROW_OPENSSL_EXCEPTION(0, CertificateCollection, NULL, "Has no item by index %d", index);
	}

	return new Extension(res, this->handle());
}

int ExtensionCollection::length() {
	LOGGER_FN();

	if (this->isEmpty()) {
		return 0;
	}

	LOGGER_OPENSSL(sk_X509_EXTENSION_num);
	int res = sk_X509_EXTENSION_num(this->internal());

	return res;
}

Handle<ExtensionCollection> ExtensionCollection::duplicate() {
	LOGGER_FN();

	LOGGER_OPENSSL(sk_X509_EXTENSION_dup);
	STACK_OF(X509_EXTENSION) *_copy = sk_X509_EXTENSION_dup(this->internal());
	if (!_copy) {
		THROW_EXCEPTION(0, ExtensionCollection, NULL, "sk_X509_EXTENSION_dup");
	}
	
	Handle<ExtensionCollection> res = new ExtensionCollection(_copy);

	return res;
}

void ExtensionCollection::removeAt(int index){
	LOGGER_FN();

	LOGGER_OPENSSL("sk_X509_EXTENSION_delete");
	sk_X509_EXTENSION_delete(this->internal(), index);
}
