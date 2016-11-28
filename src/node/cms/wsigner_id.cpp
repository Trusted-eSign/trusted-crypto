#include "../stdafx.h"

#include "wsigner_id.h"

void WSignerId::Init(v8::Handle<v8::Object> exports) {
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("SignerId").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "getIssuerName", GetIssuerName);
	Nan::SetPrototypeMethod(tpl, "getSerialNumber", GetSerialNumber);
	Nan::SetPrototypeMethod(tpl, "getKeyId", GetKeyId);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WSignerId::New) {
	METHOD_BEGIN();

	try {
		WSignerId *obj = new WSignerId();
		obj->data_ = NULL;

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WSignerId::GetIssuerName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignerId);

		Handle<std::string> name = _this->getIssuerName();

		v8::Local<v8::String> v8Name = Nan::New<v8::String>(name->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Name);
		return;
	}
	TRY_END();
}

NAN_METHOD(WSignerId::GetSerialNumber)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignerId);

		Handle<std::string> buf = _this->getSerialNumber();

		info.GetReturnValue().Set(
			stringToBuffer(buf)
			);
		return;
	}
	TRY_END();
}

NAN_METHOD(WSignerId::GetKeyId) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignerId);

		Handle<std::string> keyId = _this->getKeyId();

		v8::Local<v8::String> v8KeyId = Nan::New<v8::String>(keyId->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8KeyId);
		return;
	}
	TRY_END();
}
