#include "../stdafx.h"

#include <node_buffer.h>

#include "wcert_request_info.h"
#include "wkey.h"

void WCertificationRequestInfo::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("CertificationRequestInfo").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "setSubject", SetSubject);
	Nan::SetPrototypeMethod(tpl, "setPublicKey", SetPublicKey);
	Nan::SetPrototypeMethod(tpl, "setVersion", SetVersion);

	Nan::SetPrototypeMethod(tpl, "getSubject", GetSubject);
	Nan::SetPrototypeMethod(tpl, "getPublicKey", GetPublicKey);
	Nan::SetPrototypeMethod(tpl, "getVersion", GetVersion);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WCertificationRequestInfo::New){
	METHOD_BEGIN();
	try{
		WCertificationRequestInfo *obj = new WCertificationRequestInfo();
		obj->data_ = new CertificationRequestInfo();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();	
}

NAN_METHOD(WCertificationRequestInfo::SetSubject){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificationRequestInfo);

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

NAN_METHOD(WCertificationRequestInfo::SetPublicKey){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificationRequestInfo);

		LOGGER_ARG("certificate")
		WKey * wKey = WKey::Unwrap<WKey>(info[0]->ToObject());

		_this->setSubjectPublicKey(wKey->data_);

		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequestInfo::SetVersion){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificationRequestInfo);

		LOGGER_ARG("version")
		long version = info[0]->ToNumber()->Int32Value();

		_this->setVersion(version);

		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequestInfo::GetSubject) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CertificationRequestInfo);

		Handle<std::string> name = _this->getSubject();

		v8::Local<v8::String> v8Name = Nan::New<v8::String>(name->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Name);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequestInfo::GetVersion)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CertificationRequestInfo);

		long version = _this->getVersion();

		info.GetReturnValue().Set(
			Nan::New<v8::Number>(version)
			);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificationRequestInfo::GetPublicKey)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CertificationRequestInfo);

		Handle<Key> key = _this->getPublicKey();
		v8::Local<v8::Object> v8Key = WKey::NewInstance(key);
		info.GetReturnValue().Set(v8Key);
		return;
	}
	TRY_END();
}
