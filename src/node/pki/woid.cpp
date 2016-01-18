#include "../stdafx.h"

#include "woid.h"

void WOID::Init(v8::Handle<v8::Object> exports){
	v8::Local<v8::String> className = Nan::New(CLASS_NAME_OID).ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "getLongName", GetLongName);
	Nan::SetPrototypeMethod(tpl, "getShortName", GetShortName);
	Nan::SetPrototypeMethod(tpl, "getValue", GetValue);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(Nan::New(CLASS_NAME_OID).ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WOID::New){
	METHOD_BEGIN();
	try{
		WOID *obj = new WOID();

		obj->data_ = new OID();

		LOGGER_INFO("Get Oid value");
		if (!info[0]->IsUndefined()){
			LOGGER_INFO("Create new Oid from String");
			v8::String::Utf8Value v8OidString(info[0]->ToString());
			obj->data_ = new OID(*v8OidString);
		}

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WOID::GetLongName){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(OID);

		Handle<std::string> name = _this->getLongName();

		v8::Local<v8::String> v8Name = Nan::New(name->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Name);
		return;
	}
	TRY_END();
}

NAN_METHOD(WOID::GetShortName){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(OID);

		Handle<std::string> name = _this->getShortName();

		v8::Local<v8::String> v8Name = Nan::New(name->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Name);
		return;
	}
	TRY_END();
}

NAN_METHOD(WOID::GetValue){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(OID);

		Handle<std::string> name = _this->getValue();

		v8::Local<v8::String> v8Name = Nan::New(name->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Name);
		return;
	}
	TRY_END();
}