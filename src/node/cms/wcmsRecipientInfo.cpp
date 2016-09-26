#include "../stdafx.h"

#include "wcmsRecipientInfo.h"
#include "../pki/wcert.h"

void WCmsRecipientInfo::Init(v8::Handle<v8::Object> exports) {
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("CmsRecipientInfo").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "getIssuerName", GetIssuerName);
	Nan::SetPrototypeMethod(tpl, "getSerialNumber", GetSerialNumber);

	Nan::SetPrototypeMethod(tpl, "ktriCertCmp", KtriCertCmp);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WCmsRecipientInfo::New) {
	METHOD_BEGIN();

	try {
		WCmsRecipientInfo *obj = new WCmsRecipientInfo();
		obj->data_ = NULL;

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCmsRecipientInfo::GetIssuerName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CmsRecipientInfo);

		Handle<std::string> name = _this->getIssuerName();

		v8::Local<v8::String> v8Name = Nan::New<v8::String>(name->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Name);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCmsRecipientInfo::GetSerialNumber)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CmsRecipientInfo);

		Handle<std::string> buf = _this->getSerialNumber();

		info.GetReturnValue().Set(
			stringToBuffer(buf)
			);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCmsRecipientInfo::KtriCertCmp) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CmsRecipientInfo);

		LOGGER_ARG("certificate")
		WCertificate* obj = (WCertificate*)Nan::GetInternalFieldPointer(info[0]->ToObject(), 0);
		Handle<Certificate> cert = obj->data_;

		int res = _this->ktriCertCmp(cert);

		v8::Local<v8::Number> v8Number = Nan::New<v8::Number>(res);

		info.GetReturnValue().Set(v8Number);
		return;
	}
	TRY_END();
}
