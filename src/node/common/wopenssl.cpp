#include "../stdafx.h"

#include "wopenssl.h"

void WOpenSSL::Init(v8::Handle<v8::Object> exports) {
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("OpenSSL").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "run", Run);
	Nan::SetPrototypeMethod(tpl, "stop", Stop);
	Nan::SetPrototypeMethod(tpl, "printErrors", PrintErrors);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WOpenSSL::New) {
	METHOD_BEGIN();

	try {
		WOpenSSL *obj = new WOpenSSL();
		obj->data_ = new OpenSSL();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WOpenSSL::Run) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(OpenSSL);

		_this->run();

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WOpenSSL::Stop) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(OpenSSL);

		_this->stop();

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WOpenSSL::PrintErrors) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(OpenSSL);

		Handle<std::string> err = _this->printErrors();

		v8::Local<v8::String> v8Err = Nan::New<v8::String>(err->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Err);
		return;
	}
	TRY_END();
}
