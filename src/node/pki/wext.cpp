#include "../stdafx.h"

#include "woid.h"
#include "wext.h"

const char* WExtension::className = "Extension";

void WExtension::Init(v8::Handle<v8::Object> exports){
	LOGGER_FN();

	v8::Local<v8::String> className = Nan::New(WExtension::className).ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "getTypeId", GetTypeId);
	Nan::SetPrototypeMethod(tpl, "setTypeId", SetTypeId);
	Nan::SetPrototypeMethod(tpl, "getCritical", GetCritical);
	Nan::SetPrototypeMethod(tpl, "setCritical", SetCritical);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(Nan::New(WExtension::className).ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WExtension::New){
	METHOD_BEGIN();

	try {
		WExtension *obj = new WExtension();
		obj->data_ = new Extension();

		if (!info[0]->IsUndefined() && !info[1]->IsUndefined()){
			LOGGER_INFO("Create Extension from input params");

			LOGGER_ARG("oid");
			WOID *woid = ObjectWrap::Unwrap<WOID>(info[0]->ToObject());

			LOGGER_ARG("value");
			v8::String::Utf8Value v8ValueString(info[1]->ToString());
			Handle<std::string> hvalue = new std::string(*v8ValueString);

			obj->data_ = new Extension(woid->data_, hvalue);
		}

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
	}
	TRY_END();
}


NAN_METHOD(WExtension::GetTypeId){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Extension);

		Handle<OID> oid = _this->getTypeId();

		v8::Local<v8::Object> v8Oid = WOID::NewInstance(oid);

		info.GetReturnValue().Set(v8Oid);
		return;
	}
	TRY_END();
}

/*
 * oid: Oid
 */
NAN_METHOD(WExtension::SetTypeId){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Extension);

		LOGGER_ARG("oid");
		WOID *woid = Wrapper::Unwrap<WOID>(info[0]->ToObject());

		_this->setTypeId(woid->data_);

		return;
	}
	TRY_END();
}

NAN_METHOD(WExtension::GetCritical){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Extension);

		bool res = _this->getCritical();

		info.GetReturnValue().Set(Nan::New<v8::Boolean>(res));
		return;
	}
	TRY_END();
}

NAN_METHOD(WExtension::SetCritical){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Extension);

		LOGGER_ARG("critical");
		v8::Local<v8::Boolean> v8Crit = info[0]->ToBoolean();

		_this->setCritical(v8Crit->BooleanValue());

		return;
	}
	TRY_END();
}
