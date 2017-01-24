#include "../stdafx.h"

#include "wrevoked.h"

void WRevoked::Init(v8::Handle<v8::Object> exports){
	v8::Local<v8::String> className = Nan::New("Revoked").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "duplicate", Duplicate);

	Nan::SetPrototypeMethod(tpl, "getSerialNumber", GetSerialNumber);
	Nan::SetPrototypeMethod(tpl, "getRevocationDate", GetRevocationDate);
	Nan::SetPrototypeMethod(tpl, "getReason", GetReason);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
	
	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WRevoked::New){
	WRevoked *obj = new WRevoked();
	obj->data_ = new Revoked();

	obj->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(WRevoked::Duplicate)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Revoked);

		Handle<Revoked> rv = _this->duplicate();
		v8::Local<v8::Object> v8Rv = WRevoked::NewInstance(rv);
		info.GetReturnValue().Set(v8Rv);

		info.GetReturnValue().Set(v8Rv);
		return;
	}
	TRY_END();
}

NAN_METHOD(WRevoked::GetSerialNumber)
{
	try{

		UNWRAP_DATA(Revoked);

		Handle<std::string> buf = _this->getSerialNumber();

		info.GetReturnValue().Set(
			stringToBuffer(buf)
		);
		return;
	}
	TRY_END();
}

NAN_METHOD(WRevoked::GetRevocationDate)
{
	try{

		UNWRAP_DATA(Revoked);

		Handle<std::string> time = _this->getRevocationDate();
		v8::Local<v8::String> v8Time = Nan::New<v8::String>(time->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Time);
		return;
	}
	TRY_END();
}

NAN_METHOD(WRevoked::GetReason)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Revoked);

		Handle<std::string> reason = _this->getReason();
		v8::Local<v8::String> v8Reason = Nan::New<v8::String>(reason->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Reason);
		return;
	}
	TRY_END();
}
