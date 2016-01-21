#include "../stdafx.h"

#include <node_buffer.h>
//#include <string_bytes.h>

#include "wprovider_system.h"

void WProviderSystem::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("ProviderSystem").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "fillingJsonFromSystemStore", fillingJsonFromSystemStore);
	Nan::SetPrototypeMethod(tpl, "readJson", readJson);
	Nan::SetPrototypeMethod(tpl, "testRead", testRead);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
	
	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WProviderSystem::New){
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

		WProviderSystem *obj = new WProviderSystem();
		obj->data_ = new ProviderSystem(fname);

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WProviderSystem::fillingJsonFromSystemStore){
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

		UNWRAP_DATA(ProviderSystem);

		try{
			_this->fillingJsonFromSystemStore(fname.c_str());
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("Error filling json");
			return;
		}

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WProviderSystem::readJson){
	METHOD_BEGIN();

	try{	
		v8::String::Utf8Value v8Str(info[0]->ToString());
		char *filename = *v8Str;

		if (filename == NULL) {
			Nan::ThrowError("Wrong filename");
			return;
		}

		std::string fname(filename);

		UNWRAP_DATA(ProviderSystem);

		std::string strJson = "";
		strJson = _this->readInputJsonFile(fname.c_str());

		v8::Local<v8::String> v8Name = Nan::New<v8::String>(strJson).ToLocalChecked();

		info.GetReturnValue().Set(v8Name);
		return;
	}
	TRY_END();
}

NAN_METHOD(WProviderSystem::testRead){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(ProviderSystem);

		printf("CRLs num in stack: %d \n", sk_X509_CRL_num(_this->cert_store_system.crls));
		printf("Certs num in stack: %d \n", sk_X509_URI_num(_this->cert_store_system.cert_pkey));
		printf("CSR num in stack: %d \n", sk_X509_REQ_num(_this->cert_store_system.request));
		return;
	}
	TRY_END();
}