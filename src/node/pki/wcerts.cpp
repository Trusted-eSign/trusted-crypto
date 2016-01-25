#include "../stdafx.h"

#include "wcerts.h"
#include "wcert.h"

const char* WCertificateCollection::className = "CertificateCollection";

void WCertificateCollection::Init(v8::Handle<v8::Object> exports){
	v8::Local<v8::String> v8ClassName = Nan::New(WCertificateCollection::className).ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(v8ClassName);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "items", Items);
	Nan::SetPrototypeMethod(tpl, "push", Push);
	Nan::SetPrototypeMethod(tpl, "pop", Pop);
	Nan::SetPrototypeMethod(tpl, "removeAt", RemoveAt);
	Nan::SetPrototypeMethod(tpl, "length", Length);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
	
	exports->Set(v8ClassName, tpl->GetFunction());
}

NAN_METHOD(WCertificateCollection::New){
	WCertificateCollection *obj = new WCertificateCollection();
	obj->data_ = new CertificateCollection();

	obj->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

/*
 * index: number
 */
NAN_METHOD(WCertificateCollection::Items){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificateCollection);

		LOGGER_ARG("index");
		int index = info[0]->ToNumber()->Uint32Value();

		Handle<Certificate> cert = _this->items(index);

		v8::Local<v8::Object> v8Cert = WCertificate::NewInstance(cert);
		
		info.GetReturnValue().Set(v8Cert);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificateCollection::Length){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificateCollection);

		int len = _this->length();

		info.GetReturnValue().Set(Nan::New<v8::Number>(len));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificateCollection::Pop){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificateCollection);

		_this->pop();
		return;
	}
	TRY_END();
}

/*
 * index: number
 */
NAN_METHOD(WCertificateCollection::RemoveAt){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificateCollection);

		LOGGER_ARG("index")
		int index = info[0]->ToNumber()->Uint32Value();

		_this->removeAt(index);
		return;
	}
	TRY_END();
}

/*
* cert: Certificate
*/
NAN_METHOD(WCertificateCollection::Push){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CertificateCollection);

		LOGGER_ARG("cert")
		WCertificate * wCert = WCertificate::Unwrap<WCertificate>(info[0]->ToObject());

		_this->push(wCert->data_);
		return;
	}
	TRY_END();
}