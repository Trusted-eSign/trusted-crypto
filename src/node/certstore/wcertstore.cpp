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
			_this->newJSON(&fname);
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