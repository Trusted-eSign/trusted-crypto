#include "../stdafx.h"
#include "../helper.h"

#include "walg.h"
#include "woid.h"

void WAlgorithm::Init(v8::Handle<v8::Object> exports){
	v8::Local<v8::String> className = Nan::New(CLASS_NAME_ALGORITHM).ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	// Properties
	Nan::SetPrototypeMethod(tpl, "getTypeId", GetTypeId);
	Nan::SetPrototypeMethod(tpl, "getName", GetName);

	// Methods
	Nan::SetPrototypeMethod(tpl, "duplicate", Duplicate);
	Nan::SetPrototypeMethod(tpl, "compare", Compare);
	Nan::SetPrototypeMethod(tpl, "isDigest", IsDigest);
	
	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(Nan::New(CLASS_NAME_ALGORITHM).ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WAlgorithm::New){
	WAlgorithm *obj = new WAlgorithm();
	obj->data_ = new Algorithm();

	obj->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(WAlgorithm::GetTypeId){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Algorithm);

		Handle<OID> oid = _this->getTypeId();

		LOGGER_INFO("Create new instance of JS Pki");
		v8::Local<v8::Object> v8Pki = Nan::New<v8::Object>();
		WOID::Init(v8Pki);
		v8::Local<v8::Object> v8Oid= Nan::Get(v8Pki, Nan::New(CLASS_NAME_OID).ToLocalChecked()).ToLocalChecked()->ToObject()->CallAsConstructor(0, NULL)->ToObject();
		
		LOGGER_INFO("Set internal data for JS Oid");
		WOID* woid= (WOID*)Nan::GetInternalFieldPointer(v8Oid, 0);
		woid->data_ = oid;

		info.GetReturnValue().Set(v8Oid);
		return;
	}
	TRY_END();
}

NAN_METHOD(WAlgorithm::GetName){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Algorithm);

		Handle<std::string> name = _this->getName();

		v8::Local<v8::String> v8Name = Nan::New(name->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(
			v8Name
			);
		return;
	}
	TRY_END();
}

NAN_METHOD(WAlgorithm::Duplicate){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Algorithm);

		Handle<Algorithm> alg = _this->duplicate();

		LOGGER_INFO("Create new instance of JS Pki");
		v8::Local<v8::Object> v8Pki = Nan::New<v8::Object>();
		WAlgorithm::Init(v8Pki);
		v8::Local<v8::Object> v8Algorithm= Nan::Get(v8Pki, Nan::New(CLASS_NAME_ALGORITHM).ToLocalChecked()).ToLocalChecked()->ToObject()->CallAsConstructor(0, NULL)->ToObject();

		LOGGER_INFO("Set internal data for JS Algorithm");
		WAlgorithm* walg = (WAlgorithm*)Nan::GetInternalFieldPointer(v8Algorithm, 0);
		walg->data_ = alg;

		info.GetReturnValue().Set(
			v8Algorithm
			);
		return;
	}
	TRY_END();
}

/*
 * alg: Algorithm
 */
NAN_METHOD(WAlgorithm::Compare){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Algorithm);

		LOGGER_INFO("v8Algorithm -> Algorithm");
		v8::Local<v8::Object> v8Algorithm = info[0]->ToObject();
		WAlgorithm* walg = (WAlgorithm*)Nan::GetInternalFieldPointer(v8Algorithm, 0);

		int cmp = _this->compare(walg->data_);

		info.GetReturnValue().Set(
			Nan::New<v8::Number>(cmp)
			);
		return;
	}
	TRY_END();
}

NAN_METHOD(WAlgorithm::IsDigest){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Algorithm);

		bool isDigest = _this->isDigest();

		info.GetReturnValue().Set(
			Nan::New<v8::Boolean>(isDigest)
			);
		return;
	}
	TRY_END();
}