#include "../stdafx.h"

#include "wmicrosoft.h"

void WProviderMicrosoft::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("ProviderMicrosoft").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "getKey", GetKey);
	Nan::SetPrototypeMethod(tpl, "hasPrivateKey", HasPrivateKey);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
	
	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WProviderMicrosoft::New){
	METHOD_BEGIN();

	try{
		WProviderMicrosoft *obj = new WProviderMicrosoft();
		obj->data_ = new ProviderMicrosoft();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WProviderMicrosoft::GetKey){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("cert");
		WCertificate * wCert = WCertificate::Unwrap<WCertificate>(info[0]->ToObject());

		UNWRAP_DATA(ProviderMicrosoft);

		Handle<Key> key = _this->getKey(wCert->data_);

		v8::Local<v8::Object> v8Key = WKey::NewInstance(key);

		info.GetReturnValue().Set(v8Key);
		return;
	}

	TRY_END();
}

NAN_METHOD(WProviderMicrosoft::HasPrivateKey){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("cert");
		WCertificate * wCert = WCertificate::Unwrap<WCertificate>(info[0]->ToObject());

		UNWRAP_DATA(ProviderMicrosoft);

		bool res = _this->hasPrivateKey(wCert->data_);

		info.GetReturnValue().Set(Nan::New<v8::Boolean>(res));
		return;
	}

	TRY_END();
}
