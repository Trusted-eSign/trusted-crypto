#include "../stdafx.h"

#include "wcsp.h"
#include "../pki/wcert.h"
#include "../helper.h"

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
	Nan::SetPrototypeMethod(tpl, "getCPCSPVersion", GetCPCSPVersion);
	Nan::SetPrototypeMethod(tpl, "getCPCSPSecurityLvl", GetCPCSPSecurityLvl);

	Nan::SetPrototypeMethod(tpl, "enumProviders", EnumProviders);
	Nan::SetPrototypeMethod(tpl, "enumContainers", EnumContainers);
	Nan::SetPrototypeMethod(tpl, "getCertifiacteFromContainer", GetCertifiacteFromContainer);
	Nan::SetPrototypeMethod(tpl, "installCertifiacteFromContainer", InstallCertifiacteFromContainer);
	Nan::SetPrototypeMethod(tpl, "getContainerNameByCertificate", GetContainerNameByCertificate);
	Nan::SetPrototypeMethod(tpl, "deleteContainer", DeleteContainer);
	
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

NAN_METHOD(WCsp::GetCPCSPVersion) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Csp);

		Handle<std::string> lic = _this->getCPCSPVersion();

		v8::Local<v8::String> v8Lic = Nan::New<v8::String>(lic->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Lic);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCsp::GetCPCSPSecurityLvl) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Csp);

		Handle<std::string> lic = _this->getCPCSPSecurityLvl();

		v8::Local<v8::String> v8Lic = Nan::New<v8::String>(lic->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Lic);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCsp::EnumProviders)
{
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Csp);

		std::vector<ProviderProps> res = _this->enumProviders();

		v8::Isolate* isolate = v8::Isolate::GetCurrent();

		v8::Local<v8::Array> array8 = v8::Array::New(isolate, res.size());

		for (int i = 0; i < res.size(); i++){
			v8::Local<v8::Object> obj = Nan::New<v8::Object>();
			obj->Set(Nan::New("type").ToLocalChecked(), Nan::New<v8::Number>(res[i].type));
			obj->Set(Nan::New("name").ToLocalChecked(), Nan::New<v8::String>(res[i].name->c_str()).ToLocalChecked());

			array8->Set(i, obj);
		}

		info.GetReturnValue().Set(array8);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCsp::EnumContainers)
{
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Csp);

		int type = NULL;

		LOGGER_ARG("type");
		if (!info[0]->IsUndefined() && info[0]->IsNumber()) {
			type = info[0]->ToNumber()->Int32Value();
		}

		LOGGER_ARG("name");
		v8::String::Utf8Value v8Prov(info[1]->ToString());
		char *provName = *v8Prov;

		std::vector<Handle<std::string>> res = _this->enumContainers(type, new std::string(provName));

		v8::Isolate* isolate = v8::Isolate::GetCurrent();

		v8::Local<v8::Array> array8 = v8::Array::New(isolate, res.size());

		for (int i = 0; i < res.size(); i++){
			v8::Local<v8::String> v8FName = Nan::New<v8::String>(res[i]->c_str()).ToLocalChecked();

			info.GetReturnValue().Set(v8FName);
			array8->Set(i, v8FName);
		}

		info.GetReturnValue().Set(array8);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCsp::GetCertifiacteFromContainer)
{
	METHOD_BEGIN();

	try{
#ifdef CSP_ENABLE
		UNWRAP_DATA(Csp);

		LOGGER_ARG("container");
		v8::String::Utf8Value v8Cont(info[0]->ToString());
		char *cont = *v8Cont;

		LOGGER_ARG("type");
		int type = info[1]->ToNumber()->Int32Value();

		LOGGER_ARG("provider");
		v8::String::Utf8Value v8Prov(info[2]->ToString());
		char *provName = *v8Prov;

		Handle<Certificate> cert = _this->getCertifiacteFromContainer(new std::string(cont), type, new std::string(provName));
		v8::Local<v8::Object> v8Cert = WCertificate::NewInstance(cert);
		info.GetReturnValue().Set(v8Cert);
		return;
#else
		Nan::ThrowError("Only if CSP_ENABLE");
#endif // CSP_ENABLE
	}
	TRY_END();
}

NAN_METHOD(WCsp::InstallCertifiacteFromContainer)
{
	METHOD_BEGIN();

	try{
#ifdef CSP_ENABLE
		UNWRAP_DATA(Csp);

		LOGGER_ARG("container");
		v8::String::Utf8Value v8Cont(info[0]->ToString());
		char *cont = *v8Cont;

		LOGGER_ARG("type");
		int type = info[1]->ToNumber()->Int32Value();

		LOGGER_ARG("provider");
		v8::String::Utf8Value v8Prov(info[2]->ToString());
		char *provName = *v8Prov;

		_this->installCertifiacteFromContainer(new std::string(cont), type, new std::string(provName));

		info.GetReturnValue().Set(info.This());
		return;
#else
		Nan::ThrowError("Only if CSP_ENABLE");
#endif // CSP_ENABLE
	}
	TRY_END();
}

NAN_METHOD(WCsp::GetContainerNameByCertificate){
	METHOD_BEGIN();

	try{
#ifdef CSP_ENABLE
		LOGGER_ARG("cert");
		WCertificate * wCert = WCertificate::Unwrap<WCertificate>(info[0]->ToObject());

		LOGGER_ARG("category");
		v8::String::Utf8Value v8Category(info[1]->ToString());
		char *category = *v8Category;

		UNWRAP_DATA(Csp);

		Handle<std::string> cont = _this->getContainerNameByCertificate(wCert->data_, new std::string(category));

		v8::Local<v8::String> v8Cont = Nan::New<v8::String>(cont->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Cont);

		return;
#else
		Nan::ThrowError("Only if CSP_ENABLE");
#endif // CSP_ENABLE
	}

	TRY_END();
}

NAN_METHOD(WCsp::DeleteContainer)
{
	METHOD_BEGIN();

	try{
#ifdef CSP_ENABLE
		UNWRAP_DATA(Csp);

		LOGGER_ARG("container");
		v8::String::Utf8Value v8Cont(info[0]->ToString());
		char *cont = *v8Cont;

		LOGGER_ARG("type");
		int type = info[1]->ToNumber()->Int32Value();

		LOGGER_ARG("provider");
		v8::String::Utf8Value v8Prov(info[2]->ToString());
		char *provName = *v8Prov;

		_this->deleteContainer(new std::string(cont), type, new std::string(provName));

		info.GetReturnValue().Set(info.This());
		return;
#else
		Nan::ThrowError("Only if CSP_ENABLE");
#endif // CSP_ENABLE
	}
	TRY_END();
}
