#include "../stdafx.h"

#include <node_buffer.h>

#include "wcsr.h"
#include "wkey.h"

void WCSR::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("CSR").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "save", Save);
	Nan::SetPrototypeMethod(tpl, "getEncoded", GetEncoded);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WCSR::New){
	METHOD_BEGIN();
	try{
		WCSR *obj = new WCSR();

		LOGGER_ARG("x509Name");
		v8::String::Utf8Value v8Name(info[0]->ToString());
		char *x509Name = *v8Name;
		if (x509Name == NULL) {
			Nan::ThrowError("Wrong x509name");
			info.GetReturnValue().SetUndefined();
		}
		Handle<std::string> hname = new std::string(x509Name);

		LOGGER_ARG("key")
		WKey * wKey = WKey::Unwrap<WKey>(info[1]->ToObject());

		LOGGER_ARG("digest");
		v8::String::Utf8Value v8Digest(info[2]->ToString());
		char *digest = *v8Digest;
		std::string strDigest(digest);

		obj->data_ = new CSR(hname, wKey->data_, strDigest.c_str());

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();	
}

NAN_METHOD(WCSR::Save) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("filename");
		v8::String::Utf8Value v8Filename(info[0]->ToString());
		char *filename = *v8Filename;

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		UNWRAP_DATA(CSR);

		Handle<Bio> out = new Bio(BIO_TYPE_FILE, filename, "wb");
		_this->write(out, DataFormat::get(format));
		out->flush();

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCSR::GetEncoded) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CSR);

		Handle<std::string> encCSR = _this->getEncoded();

		info.GetReturnValue().Set(stringToBuffer(encCSR));
		return;
	}
	TRY_END();
}