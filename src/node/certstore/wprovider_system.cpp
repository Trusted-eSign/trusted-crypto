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

	Nan::SetPrototypeMethod(tpl, "fillingCache", fillingCache);
	Nan::SetPrototypeMethod(tpl, "readJson", readJson);

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

		WProviderSystem *obj = new WProviderSystem();
		obj->data_ = new ProviderSystem(fname);

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WProviderSystem::fillingCache){
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
		v8::String::Utf8Value v8cacheURI(info[0]->ToString());
		char *cacheURI = *v8cacheURI;

		LOGGER_ARG("pvdURI");
		v8::String::Utf8Value v8pvdURI(info[1]->ToString());
		char *pvdURI = *v8pvdURI;

		UNWRAP_DATA(ProviderSystem);

		try{
			_this->fillingCache(cacheURI, pvdURI);
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