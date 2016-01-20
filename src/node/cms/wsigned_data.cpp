#include "../stdafx.h"

#include "wsigned_data.h"
#include "../pki/wcert.h"

const char* WSignedData::className = "SignedData";

void WSignedData::Init(v8::Handle<v8::Object> exports){
	LOGGER_FN();

	v8::Local<v8::String> className = Nan::New(WSignedData::className).ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "load", Load);
	Nan::SetPrototypeMethod(tpl, "import", Import);
	Nan::SetPrototypeMethod(tpl, "getCertificates", GetCertificates);
	Nan::SetPrototypeMethod(tpl, "getSigners", GetSigners);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(Nan::New(WSignedData::className).ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WSignedData::New){
	METHOD_BEGIN();
	try{
		WSignedData *obj = new WSignedData();

		obj->data_ = new SignedData();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

/*
 * filename: String
 * format: DataFromat
 */
NAN_METHOD(WSignedData::Load){
	METHOD_BEGIN();

	try {
		LOGGER_ARG("filename");
		v8::String::Utf8Value v8Filename(info[0]->ToString());
		char *filename = *v8Filename;

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		UNWRAP_DATA(SignedData);

		Handle<Bio> in = NULL;

		in = new Bio(BIO_TYPE_FILE, filename, "rb");

		_this->read(in, DataFormat::get(format));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

/*
* data: Buffer
* format: DataFormat
*/
NAN_METHOD(WSignedData::Import) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("data");
		char* buf = node::Buffer::Data(info[0]->ToObject());
		size_t buflen = node::Buffer::Length(info[0]);
		std::string buffer(buf, buflen);

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		UNWRAP_DATA(SignedData);

		Handle<Bio> in = new Bio(BIO_TYPE_MEM, buffer);

		_this->read(in, DataFormat::get(format));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WSignedData::GetSigners) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignedData);

		v8::Local<v8::Array> v8Signers = Nan::New<v8::Array>();

		Handle<SignerCollection> signers = _this->signers();

		for (int i = 0; i < signers->length(); i++){
			v8Signers->Set(i, Nan::New<v8::Object>());
		}

		info.GetReturnValue().Set(v8Signers);
		return;
	}
	TRY_END();
}

NAN_METHOD(WSignedData::GetCertificates) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignedData);

		v8::Local<v8::Array> v8Certificates= Nan::New<v8::Array>();

		Handle<CertificateCollection> certs= _this->certificates();

		for (int i = 0; i < certs->length(); i++){
			v8Certificates->Set(i, WCertificate::NewInstance(certs->items(i)));
		}

		info.GetReturnValue().Set(v8Certificates);
		return;
	}
	TRY_END();
}