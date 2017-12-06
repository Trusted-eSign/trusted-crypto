#include "../stdafx.h"

#include "wcsp.h"

void WCsp::Init(v8::Handle<v8::Object> exports) {
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("Csp").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "isGost2001CSPAvailable", IsGost2001CSPAvailable);
	Nan::SetPrototypeMethod(tpl, "isGost2012_256CSPAvailable", IsGost2012_256CSPAvailable);
	Nan::SetPrototypeMethod(tpl, "isGost2012_512CSPAvailable", IsGost2012_512CSPAvailable);

	Nan::SetPrototypeMethod(tpl, "checkCPCSPLicense", CheckCPCSPLicense);
	Nan::SetPrototypeMethod(tpl, "getCPCSPLicense", GetCPCSPLicense);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WCsp::New) {
	METHOD_BEGIN();

	try {
		WCsp *obj = new WCsp();
		obj->data_ = new Csp();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCsp::IsGost2001CSPAvailable) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Csp);

		bool res = _this->isGost2001CSPAvailable();
		
		info.GetReturnValue().Set(Nan::New<v8::Boolean>(res));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCsp::IsGost2012_256CSPAvailable) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Csp);

		bool res = _this->isGost2012_256CSPAvailable();

		info.GetReturnValue().Set(Nan::New<v8::Boolean>(res));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCsp::IsGost2012_512CSPAvailable) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Csp);

		bool res = _this->isGost2012_512CSPAvailable();

		info.GetReturnValue().Set(Nan::New<v8::Boolean>(res));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCsp::CheckCPCSPLicense) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Csp);

		bool res = _this->checkCPCSPLicense();

		info.GetReturnValue().Set(Nan::New<v8::Boolean>(res));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCsp::GetCPCSPLicense) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Csp);

		Handle<std::string> lic = _this->getCPCSPLicense();

		v8::Local<v8::String> v8Lic = Nan::New<v8::String>(lic->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Lic);
		return;
	}
	TRY_END();
}
