#include "../stdafx.h"

#include <node_buffer.h>

#include "wcert_request.h"
#include "wcert_request_info.h"
#include "wkey.h"
#include "wcert.h"
#include "wexts.h"

void WCertificationRequest::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("CertificationRequest").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "load", Load);
	Nan::SetPrototypeMethod(tpl, "save", Save);

	Nan::SetPrototypeMethod(tpl, "setSubject", SetSubject);
	Nan::SetPrototypeMethod(tpl, "setPublicKey", SetPublicKey);
	Nan::SetPrototypeMethod(tpl, "setVersion", SetVersion);
	Nan::SetPrototypeMethod(tpl, "setExtensions", SetExtensions);

	Nan::SetPrototypeMethod(tpl, "getSubject", GetSubject);
	Nan::SetPrototypeMethod(tpl, "getPublicKey", GetPublicKey);
	Nan::SetPrototypeMethod(tpl, "getVersion", GetVersion);
	Nan::SetPrototypeMethod(tpl, "getExtensions", GetExtensions);

	Nan::SetPrototypeMethod(tpl, "sign", Sign);
	Nan::SetPrototypeMethod(tpl, "verify", Verify);
	Nan::SetPrototypeMethod(tpl, "getPEMString", GetPEMString);

	Nan::SetPrototypeMethod(tpl, "toCertificate", ToCertificate);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WCertificationRequest::New){
	METHOD_BEGIN();
	try{
		WCertificationRequest *obj = new WCertificationRequest();
		obj->data_ = new CertificationRequest();

		if (!info[0]->IsUndefined()){
			LOGGER_INFO("csrinfo");
			WCertificationRequestInfo * wCertRegInfo = WCertificationRequestInfo::Unwrap<WCertificationRequestInfo>(info[0]->ToObject());

			obj->data_ = new CertificationRequest(wCertRegInfo->data_);

		}
		
		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();	
}

/*
* filename: String
* format: DataFormat
*/
NAN_METHOD(WCertificationRequest::Load) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("filename");
		v8::String::Utf8Value v8Filename(info[0]->ToString());
		char *filename = *v8Filename;

		Handle<Bio> in = NULL;
		in = new Bio(BIO_TYPE_FILE, filename, "rb");

		LOGGER_ARG("format");
		DataFormat::DATA_FORMAT format = (info[1]->IsUndefined() || !info[1]->IsNumber()) ?
			getCmsFileType(in) :
			DataFormat::get(info[1]->ToNumber()->Int32Value());

		UNWRAP_DATA(CertificationRequest);

		_this->read(in, format);

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequest::Save) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("filename");
		v8::String::Utf8Value v8Filename(info[0]->ToString());
		char *filename = *v8Filename;

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		UNWRAP_DATA(CertificationRequest);

		Handle<Bio> out = new Bio(BIO_TYPE_FILE, filename, "wb");
		_this->write(out, DataFormat::get(format));
		out->flush();

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequest::SetSubject){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificationRequest);

		LOGGER_ARG("x509Name");
		v8::String::Utf8Value v8Name(info[0]->ToString());
		char *x509Name = *v8Name;
		if (x509Name == NULL) {
			Nan::ThrowError("Wrong x509name");
			info.GetReturnValue().SetUndefined();
		}

		Handle<std::string> hname = new std::string(x509Name);

		_this->setSubject(hname);

		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequest::SetPublicKey){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificationRequest);

		LOGGER_ARG("certificate")
			WKey * wKey = WKey::Unwrap<WKey>(info[0]->ToObject());

		_this->setPublicKey(wKey->data_);

		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequest::SetVersion){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificationRequest);

		LOGGER_ARG("version")
		long version = info[0]->ToNumber()->Int32Value();

		_this->setVersion(version);

		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequest::SetExtensions){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificationRequest);

		LOGGER_ARG("extensions")
			WExtensionCollection * wExts = WExtensionCollection::Unwrap<WExtensionCollection>(info[0]->ToObject());

		_this->setExtensions(wExts->data_);

		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequest::GetSubject) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CertificationRequest);

		Handle<std::string> name = _this->getSubject();

		v8::Local<v8::String> v8Name = Nan::New<v8::String>(name->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Name);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequest::GetVersion)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CertificationRequest);

		long version = _this->getVersion();

		info.GetReturnValue().Set(
			Nan::New<v8::Number>(version)
			);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequest::GetPublicKey)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CertificationRequest);

		Handle<Key> key = _this->getPublicKey();
		v8::Local<v8::Object> v8Key = WKey::NewInstance(key);
		info.GetReturnValue().Set(v8Key);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequest::GetExtensions)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CertificationRequest);

		Handle<ExtensionCollection> exts = _this->getExtensions();
		v8::Local<v8::Object> v8Exts = WExtensionCollection::NewInstance(exts);
		info.GetReturnValue().Set(v8Exts);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequest::Sign){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificationRequest);

		LOGGER_ARG("key");
		WKey * wKey = WKey::Unwrap<WKey>(info[0]->ToObject());

		LOGGER_ARG("digest");
		v8::String::Utf8Value v8Digest(info[1]->ToString());
		char *digest = *v8Digest;
		std::string strDigest(digest);

		_this->sign(wKey->data_, strDigest.c_str());

		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequest::Verify) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CertificationRequest);

		bool res = _this->verify();

		info.GetReturnValue().Set(Nan::New<v8::Boolean>(res));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequest::GetPEMString) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CertificationRequest);

		Handle<std::string> encCSR = _this->getPEMString();

		info.GetReturnValue().Set(stringToBuffer(encCSR));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequest::ToCertificate){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificationRequest);

		LOGGER_ARG("days");
		int days = info[0]->ToNumber()->Int32Value();

		LOGGER_ARG("key");
		WKey * wKey = WKey::Unwrap<WKey>(info[1]->ToObject());

		Handle<Certificate> cert = _this->toCertificate(days, wKey->data_);
		v8::Local<v8::Object> v8Cert = WCertificate::NewInstance(cert);
		info.GetReturnValue().Set(v8Cert);

		return;
	}
	TRY_END();
}
