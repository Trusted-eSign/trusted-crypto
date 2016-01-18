#include "../stdafx.h"
#include "../helper.h"

#include "woid.h"
#include "walg.h"

const char* WAlgorithm::className = "Algorithm";

void WAlgorithm::Init(v8::Handle<v8::Object> exports){
	v8::Local<v8::String> className = Nan::New(WAlgorithm::className).ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	// Properties
	Nan::SetPrototypeMethod(tpl, "getTypeId", GetTypeId);
	Nan::SetPrototypeMethod(tpl, "getName", GetName);

	// Methods
	Nan::SetPrototypeMethod(tpl, "duplicate", Duplicate);
	Nan::SetPrototypeMethod(tpl, "isDigest", IsDigest);
	
	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(Nan::New(WAlgorithm::className).ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WAlgorithm::New){
	METHOD_BEGIN();

	try{
		WAlgorithm *obj = new WAlgorithm();
		obj->data_ = new Algorithm();

		if (!info[0]->IsUndefined()){
			LOGGER_INFO("Create Algorithm from String");
			v8::String::Utf8Value v8AlgName(info[0]->ToString());

			obj->data_ = new Algorithm(*v8AlgName);
		}

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END()
}

NAN_METHOD(WAlgorithm::GetTypeId){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Algorithm);

		Handle<OID> oid = _this->getTypeId();

		v8::Local<v8::Object> v8Oid = WOID::NewInstance(oid);

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
		v8::Local<v8::Object> v8Algorithm = WAlgorithm::NewInstance(alg);

		info.GetReturnValue().Set(
			v8Algorithm
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