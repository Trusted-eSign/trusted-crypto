#include "../stdafx.h"

#include "woid.h"
#include "wattr_vals.h"
#include "wattr.h"

const char* WAttribute::className = "Attribute";

void WAttribute::Init(v8::Handle<v8::Object> exports){
	LOGGER_FN();

	v8::Local<v8::String> className = Nan::New(WAttribute::className).ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "duplicate", Duplicate);
	Nan::SetPrototypeMethod(tpl, "export", Export);
	Nan::SetPrototypeMethod(tpl, "values", Values);

	Nan::SetPrototypeMethod(tpl, "getAsnType", GetAsnType);
	Nan::SetPrototypeMethod(tpl, "setAsnType", SetAsnType);
	Nan::SetPrototypeMethod(tpl, "getTypeId", GetTypeId);
	Nan::SetPrototypeMethod(tpl, "setTypeId", SetTypeId);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(Nan::New(WAttribute::className).ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WAttribute::New){
	LOGGER_FN();

	WAttribute *obj = new WAttribute();
	obj->data_ = new Attribute();

	obj->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(WAttribute::Duplicate){
	LOGGER_FN();

	try{
		UNWRAP_DATA(Attribute);

		v8::Local<v8::Object> v8Object = WAttribute::NewInstance();

		info.GetReturnValue().Set(v8Object);
		return;
	}
	TRY_END();
}

NAN_METHOD(WAttribute::Export){
	LOGGER_FN();
	try{
		UNWRAP_DATA(Attribute);

		Handle<std::string> buf = _this->write();

		info.GetReturnValue().Set(stringToBuffer(buf));
		return;
	}
	TRY_END();
}

NAN_METHOD(WAttribute::GetAsnType){
	LOGGER_FN();
	try{
		UNWRAP_DATA(Attribute);

		int type = _this->getAsnType();

		info.GetReturnValue().Set(
			Nan::New<v8::Number>(type)
			);
		return;
	}
	TRY_END();
}


/*
 * type: number
 */
NAN_METHOD(WAttribute::SetAsnType){
	LOGGER_FN();
	try{
		UNWRAP_DATA(Attribute);

		LOGGER_ARG("type");
		int type = info[0]->ToNumber()->Int32Value();

		_this->setAsnType(type);

		return;
	}
	TRY_END();
}

NAN_METHOD(WAttribute::GetTypeId){
	LOGGER_FN();
	try{
		UNWRAP_DATA(Attribute);

		Handle<OID> oid = _this->getTypeId();

		WOID::NewInstance(oid);

		info.GetReturnValue().SetNull();
		return;
	}
	TRY_END();
}

/*
 * oid: string
 */
NAN_METHOD(WAttribute::SetTypeId){
	LOGGER_FN();
	try{
		UNWRAP_DATA(Attribute);

		LOGGER_ARG("oid");
		v8::String::Utf8Value v8OidValue(info[0]->ToString());
		std::string oidValue(*v8OidValue);

		Handle<OID> oid = new OID(oidValue);
		_this->setTypeId(oid);

		return;
	}
	TRY_END();
}

NAN_METHOD(WAttribute::Values){
	LOGGER_FN();
	try{
		UNWRAP_DATA(Attribute);

		v8::Local<v8::Object> v8Obj = WAttributeValueCollection::NewInstance(info.This());

		info.GetReturnValue().Set(v8Obj);
		return;
	}
	TRY_END();
}