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
	Nan::SetPrototypeMethod(tpl, "checkTrialLicense", CheckTrialLicense);
	Nan::SetPrototypeMethod(tpl, "getExpirationTime", GetExpirationTime);
	Nan::SetPrototypeMethod(tpl, "getTrialExpirationTime", GetTrialExpirationTime);
	Nan::SetPrototypeMethod(tpl, "createTrialLicense", CreateTrialLicense);

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

		if (info[0]->IsUndefined()){
			info.GetReturnValue().Set(_this->checkLicense());
		}
		else {
			LOGGER_ARG("lic");
			v8::String::Utf8Value v8Lic(info[0]->ToString());
			char *lic = *v8Lic;

			info.GetReturnValue().Set(_this->checkLicense(new std::string(lic)));
		}
		
		return;
	}
	TRY_END();
}

NAN_METHOD(WJwt::GetExpirationTime) {
	METHOD_BEGIN();
	try {
		UNWRAP_DATA(Jwt);
		LOGGER_ARG("lic");
		v8::String::Utf8Value v8Lic(info[0]->ToString());
		char *lic = *v8Lic;
		info.GetReturnValue().Set(_this->getExpirationTime(new std::string(lic)));
		return;
	}
	TRY_END();
}

NAN_METHOD(WJwt::GetTrialExpirationTime) {
	METHOD_BEGIN();
	try {
		UNWRAP_DATA(Jwt);
		LOGGER_ARG("lic");
		info.GetReturnValue().Set(_this->getTrialExpirationTime());
		return;
	}
	TRY_END();
}

NAN_METHOD(WJwt::CheckTrialLicense) {
	METHOD_BEGIN();
	try {
		UNWRAP_DATA(Jwt);
		LOGGER_ARG("lic");
		info.GetReturnValue().Set(_this->checkTrialLicense());
		return;
	}
	TRY_END();
}

NAN_METHOD(WJwt::CreateTrialLicense) {
	METHOD_BEGIN();
	try {
		UNWRAP_DATA(Jwt);
		LOGGER_ARG("lic");
		info.GetReturnValue().Set(_this->createTrialLicense());
		return;
	}
	TRY_END();
}


