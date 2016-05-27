#include "../stdafx.h"

#include <node_buffer.h>

#include "wchain.h"
#include "wcert.h"
#include "wcerts.h"
#include "wcrls.h"
#include "../store/wsystem.h"
#include "../store/wpkistore.h"

void WChain::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("Chain").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "buildChain", BuildChain);
	Nan::SetPrototypeMethod(tpl, "verifyChain", VerifyChain);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WChain::New){
	METHOD_BEGIN();
	try{		
		WChain *obj = new WChain();
			
		obj->data_ = new Chain();
		
		obj->Wrap(info.This());
		
		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();	
}

NAN_METHOD(WChain::BuildChain) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("cert");
		WCertificate * wCert = WCertificate::Unwrap<WCertificate>(info[0]->ToObject());

		LOGGER_ARG("certs");
		WCertificateCollection * wCerts = WCertificateCollection::Unwrap<WCertificateCollection>(info[1]->ToObject());

		UNWRAP_DATA(Chain);

		Handle<CertificateCollection> chain = _this->buildChain(wCert->data_, wCerts->data_);
		v8::Local<v8::Object> v8Certificates = WCertificateCollection::NewInstance(chain);

		info.GetReturnValue().Set(v8Certificates);
		return;
	}
	TRY_END();
}

NAN_METHOD(WChain::VerifyChain) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("chain");
		WCertificateCollection * wChain = WCertificateCollection::Unwrap<WCertificateCollection>(info[0]->ToObject());

		LOGGER_ARG("crls");
		WCrlCollection * wCrls = WCrlCollection::Unwrap<WCrlCollection>(info[1]->ToObject());

		UNWRAP_DATA(Chain);

		bool res = _this->verifyChain(wChain->data_, wCrls->data_);

		info.GetReturnValue().Set(Nan::New<v8::Boolean>(res));
		return;
	}
	TRY_END();
}
