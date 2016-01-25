#include "../stdafx.h"

#include <node_buffer.h>
//#include <string_bytes.h>

#include "wcertstore.h"

void WCertStore::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("CertStore").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "CERT_STORE_NEW", CERT_STORE_NEW);
	Nan::SetPrototypeMethod(tpl, "newJson", newJson);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
	
	exports->Set(Nan::New("CertStore").ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WCertStore::New){
	METHOD_BEGIN();

	try{
		WCertStore *obj = new WCertStore();
		obj->data_ = new CertStore();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertStore::CERT_STORE_NEW){
	METHOD_BEGIN();

	try{
		if (info[0]->IsUndefined()){
			Nan::ThrowError("Parameter 1 is required");
			return;
		}

		v8::String::Utf8Value v8Str(info[0]->ToString());
		char *pvdType = *v8Str;

		if (pvdType == NULL) {
			Nan::ThrowError("Wrong provider type");
			return;
		}

		UNWRAP_DATA(CertStore);

		LOGGER_ARG("pvdURI");
		if (info[1]->IsUndefined()){
			try{
				_this->CERT_STORE_NEW(pvdType);
			}
			catch (Handle<Exception> e){
				Nan::ThrowError("Error create new cert store");
				return;
			}
		}
		else{
			v8::String::Utf8Value v8URI(info[1]->ToString());
			char *pvdURI = *v8URI;
			std::string strPvdURI(pvdURI);

			try{
				_this->CERT_STORE_NEW(pvdType, strPvdURI);
			}
			catch (Handle<Exception> e){
				Nan::ThrowError("Error create new cert store");
				return;
			}
		}
	
		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertStore::newJson){
	METHOD_BEGIN();

	try{
		if (info[0]->IsUndefined()){
			Nan::ThrowError("Parameter 1 is required");
			return;
		}

		v8::String::Utf8Value v8Str(info[0]->ToString());
		char *filename = *v8Str;

		if (filename == NULL) {
			Nan::ThrowError("Wrong filename");
			return;
		}

		std::string fname(filename);
		//free(filename);

		UNWRAP_DATA(CertStore);

		try{
			_this->newJSON(fname.c_str());
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("Error create new json");
			return;
		}
		

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}