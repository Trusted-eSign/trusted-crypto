#include "../stdafx.h"

#include "wjwt.h"

void WJwt::Init(v8::Handle<v8::Object> exports) {
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("Jwt").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "checkLicense", CheckLicense);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WJwt::New) {
	METHOD_BEGIN();

	try {
		WJwt *obj = new WJwt();
		obj->data_ = new Jwt();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WJwt::CheckLicense) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Jwt);

		info.GetReturnValue().Set(_this->checkLicense());
		return;
	}
	TRY_END();
}
