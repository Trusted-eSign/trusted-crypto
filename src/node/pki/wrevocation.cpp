#include "../stdafx.h"

#include "wrevocation.h"
#include "wcert.h"
#include "wcrl.h"
#include "../store/wpkistore.h"

void WRevocation::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("Revocation").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	Nan::SetPrototypeMethod(tpl, "getCrlLocal", GetCrlLocal);
	Nan::SetPrototypeMethod(tpl, "getCrlDistPoints", GetCrlDistPoints);
	Nan::SetPrototypeMethod(tpl, "checkCrlTime", CheckCrlTime);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WRevocation::New){
	METHOD_BEGIN();
	try{		
		WRevocation *obj = new WRevocation();
			
		obj->data_ = new Revocation();
		
		obj->Wrap(info.This());
		
		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();	
}

NAN_METHOD(WRevocation::GetCrlLocal) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("cert");
		WCertificate * wCert = WCertificate::Unwrap<WCertificate>(info[0]->ToObject());

		LOGGER_ARG("store");
		WPkiStore * wStore = WPkiStore::Unwrap<WPkiStore>(info[1]->ToObject());

		UNWRAP_DATA(Revocation);

		Handle<CRL> outCrl;
		boolean res = _this->getCrlLocal(outCrl, wCert->data_, wStore->data_);
		if (res) {
			v8::Local<v8::Object> v8Crls = WCRL::NewInstance(outCrl);

			info.GetReturnValue().Set(v8Crls);
		}
		else {
			v8::Local<v8::Boolean> v8NoCrl = Nan::New<v8::Boolean>(false);

			info.GetReturnValue().Set(v8NoCrl);
		}
		
		return;
	}
	TRY_END();
}

NAN_METHOD(WRevocation::GetCrlDistPoints){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("cert");
		WCertificate * wCert = WCertificate::Unwrap<WCertificate>(info[0]->ToObject());

		UNWRAP_DATA(Revocation);

		std::vector<std::string> res = _this->getCrlDistPoints(wCert->data_);

		v8::Isolate* isolate = v8::Isolate::GetCurrent();

		v8::Local<v8::Array> array8 = v8::Array::New(isolate, res.size());

		for (int i = 0; i < res.size(); i++){
			v8::Local<v8::String> v8Str = Nan::New<v8::String>(res[i]).ToLocalChecked();
			array8->Set(i, v8Str);
		}

		info.GetReturnValue().Set(array8);
		return;
	}
	TRY_END();
}

NAN_METHOD(WRevocation::CheckCrlTime) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("crl");
		WCRL * wCrl = WCRL::Unwrap<WCRL>(info[0]->ToObject());

		UNWRAP_DATA(Revocation);

		v8::Local<v8::Boolean> v8Res = Nan::New<v8::Boolean>(_this->checkCrlTime(wCrl->data_));

		info.GetReturnValue().Set(v8Res);
		return;
	}
	TRY_END();
}
