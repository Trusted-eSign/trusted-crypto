#include "../stdafx.h"

#include "wpkcs12.h"
#include "wcert.h"
#include "wcerts.h"
#include "wkey.h"

void WPkcs12::Init(v8::Handle<v8::Object> exports) {
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("Pkcs12").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "getCertificate", GetCertificate);
	Nan::SetPrototypeMethod(tpl, "getKey", GetKey);
	Nan::SetPrototypeMethod(tpl, "getCACertificates", GetCACertificates);

	Nan::SetPrototypeMethod(tpl, "load", Load);
	Nan::SetPrototypeMethod(tpl, "save", Save);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WPkcs12::New) {
	METHOD_BEGIN();

	try {
		WPkcs12 *obj = new WPkcs12();
		obj->data_ = new Pkcs12();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

/*
 * filename: String
 */
NAN_METHOD(WPkcs12::Load) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("filename");
		v8::String::Utf8Value v8Filename(info[0]->ToString());
		char *filename = *v8Filename;

		UNWRAP_DATA(Pkcs12);

		Handle<Bio> in = NULL;

		in = new Bio(BIO_TYPE_FILE, filename, "rb");

		_this->read(in);

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

/*
* filename: String
*/
NAN_METHOD(WPkcs12::Save) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("filename");
		v8::String::Utf8Value v8Filename(info[0]->ToString());
		char *filename = *v8Filename;

		UNWRAP_DATA(Pkcs12);

		Handle<Bio> out = new Bio(BIO_TYPE_FILE, filename, "wb");
		_this->write(out);
		out->flush();

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkcs12::GetCertificate)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Pkcs12);

		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[0]->ToString());
		char *password = *v8Pass;

		Handle<Certificate> cert = _this->getCertificate(password);
		v8::Local<v8::Object> v8Cert = WCertificate::NewInstance(cert);
		info.GetReturnValue().Set(v8Cert);
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkcs12::GetKey)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Pkcs12);

		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[0]->ToString());
		char *password = *v8Pass;

		Handle<Key> key = _this->getKey(password);
		v8::Local<v8::Object> v8Key = WKey::NewInstance(key);
		info.GetReturnValue().Set(v8Key);
		return;
	}
	TRY_END();
}

NAN_METHOD(WPkcs12::GetCACertificates)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Pkcs12);

		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[0]->ToString());
		char *password = *v8Pass;

		Handle<CertificateCollection> certs = _this->getCACertificates(password);
		v8::Local<v8::Object> v8Certificates = WCertificateCollection::NewInstance(certs);
		info.GetReturnValue().Set(v8Certificates);
		return;
	}
	TRY_END();
}