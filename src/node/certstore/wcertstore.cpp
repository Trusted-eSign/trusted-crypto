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

	Nan::SetPrototypeMethod(tpl, "addCertStore", addCertStore);
	Nan::SetPrototypeMethod(tpl, "removeCertStore", removeCertStore);
	Nan::SetPrototypeMethod(tpl, "createCache", createCache);
	Nan::SetPrototypeMethod(tpl, "addCacheSection", addCacheSection);

	Nan::SetPrototypeMethod(tpl, "getCertStore", getCertStore);
	Nan::SetPrototypeMethod(tpl, "getPrvTypePresent", getPrvTypePresent);

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

NAN_METHOD(WCertStore::addCertStore){
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
				_this->addCertStore(pvdType);
			}
			catch (Handle<Exception> e){
				Nan::ThrowError("Error create new cert store");
				return;
			}
		}
		else{
			v8::String::Utf8Value v8URI(info[1]->ToString());
			char *pvdURI = *v8URI;

			try{
				_this->addCertStore(pvdType, pvdURI);
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

NAN_METHOD(WCertStore::removeCertStore){
	METHOD_BEGIN();

	try{
		if (info[0]->IsUndefined()){
			Nan::ThrowError("Parameter 1 is required");
			return;
		}

		LOGGER_ARG("pvdType");
		v8::String::Utf8Value v8pvdType(info[0]->ToString());
		char *pvdType = *v8pvdType;

		UNWRAP_DATA(CertStore);

		try{
			_this->removeCertStore(pvdType);
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("Error remove provider");
			return;
		}

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertStore::createCache){
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

		UNWRAP_DATA(CertStore);

		try{
			_this->createCache(fname.c_str());
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

NAN_METHOD(WCertStore::addCacheSection){
	METHOD_BEGIN();

	try{
		if (info[0]->IsUndefined()){
			Nan::ThrowError("Parameter 1 is required");
			return;
		}
		if (info[1]->IsUndefined()){
			Nan::ThrowError("Parameter 2 is required");
			return;
		}

		LOGGER_ARG("cacheURI");
		v8::String::Utf8Value v8Str(info[0]->ToString());
		char *cacheURI = *v8Str;

		LOGGER_ARG("pvdType");
		v8::String::Utf8Value v8pvdType(info[1]->ToString());
		char *pvdType = *v8pvdType;

		UNWRAP_DATA(CertStore);

		try{
			_this->addCacheSection(cacheURI, pvdType);
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("Error add cache section");
			return;
		}

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertStore::getCertStore) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CertStore);

		try{
			Handle<std::string> strCertStore = _this->getCertStore();
			
			v8::Local<v8::String> v8CertStore = Nan::New<v8::String>(strCertStore->c_str()).ToLocalChecked();
			
			info.GetReturnValue().Set(v8CertStore);
			return;
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("Can not get list cert store");
			return;
		}		
	}
	TRY_END();
}

NAN_METHOD(WCertStore::getPrvTypePresent) {
	METHOD_BEGIN();

	try {		
		if (info[0]->IsUndefined()){
			Nan::ThrowError("Parameter 1 is required");
			return;
		}

		LOGGER_ARG("pvdType");
		v8::String::Utf8Value v8pvdType(info[0]->ToString());
		char *pvdType = *v8pvdType;

		UNWRAP_DATA(CertStore);

		bool res = _this->getPrvTypePresent(pvdType);

		info.GetReturnValue().Set(
			Nan::New<v8::Boolean>(res)
			);
		return;
	}
	TRY_END();
}
