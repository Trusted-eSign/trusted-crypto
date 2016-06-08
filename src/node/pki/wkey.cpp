#include "../stdafx.h"

#include <node_buffer.h>
//#include <string_bytes.h>

#include "wkey.h"

void WKey::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("Key").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "generate", Generate);
	Nan::SetPrototypeMethod(tpl, "compare", Compare);
	Nan::SetPrototypeMethod(tpl, "duplicate", Duplicate);

	Nan::SetPrototypeMethod(tpl, "readPrivateKey", ReadPrivateKey);
	Nan::SetPrototypeMethod(tpl, "writePrivateKey", WritePrivateKey);

	Nan::SetPrototypeMethod(tpl, "readPublicKey", ReadPublicKey);
	Nan::SetPrototypeMethod(tpl, "writePublicKey", WritePublicKey);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WKey::New){
	METHOD_BEGIN();

	try{
		WKey *obj = new WKey();
		obj->data_ = new Key();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::Generate){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("format");
		int format = info[0]->ToNumber()->Int32Value();

		LOGGER_ARG("pubExp");
		int pubExp = info[1]->ToNumber()->Int32Value();

		LOGGER_ARG("keySize");
		int keySize = info[2]->ToNumber()->Int32Value();

		UNWRAP_DATA(Key);

		Handle<Key> key = _this->generate(DataFormat::get(format), PublicExponent::get(pubExp), keySize);
		v8::Local<v8::Object> v8Key = WKey::NewInstance(key);
		info.GetReturnValue().Set(v8Key);

		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::Compare) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Key);

		LOGGER_ARG("key");
		WKey * wKey = WKey::Unwrap<WKey>(info[0]->ToObject());
		
		int res = _this->compare(wKey->data_);

		v8::Local<v8::Number> v8Number = Nan::New<v8::Number>(res);

		info.GetReturnValue().Set(v8Number);
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::Duplicate)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Key);

		Handle<Key> key = _this->duplicate();
		v8::Local<v8::Object> v8Key = WKey::NewInstance(key);
		info.GetReturnValue().Set(v8Key);

		info.GetReturnValue().Set(v8Key);
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::ReadPrivateKey){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("filename");
		v8::String::Utf8Value v8Name(info[0]->ToString());
		char *filename = *v8Name;

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[2]->ToString());
		char *password = *v8Pass;

		Handle<Bio> in = NULL;

		in = new Bio(BIO_TYPE_FILE, filename, "rb");

		UNWRAP_DATA(Key);

		_this->readPrivateKey(in, DataFormat::get(format), new std::string(password));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::ReadPublicKey){
	METHOD_BEGIN();

	try{
		v8::String::Utf8Value v8Str(info[0]->ToString());
		char *filename = *v8Str;

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		Handle<Bio> in = NULL;

		in = new Bio(BIO_TYPE_FILE, filename, "rb");

		UNWRAP_DATA(Key);

		_this->readPublicKey(in, DataFormat::get(format));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::WritePrivateKey) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("filename");
		v8::String::Utf8Value v8Filename(info[0]->ToString());
		char *filename = *v8Filename;

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[2]->ToString());
		char *password = *v8Pass;

		Handle<Bio> out = new Bio(BIO_TYPE_FILE, filename, "wb");

		UNWRAP_DATA(Key);

		_this->writePrivateKey(out, DataFormat::get(format), new std::string(password));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::WritePublicKey) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("filename");
		v8::String::Utf8Value v8Filename(info[0]->ToString());
		char *filename = *v8Filename;

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		Handle<Bio> out = new Bio(BIO_TYPE_FILE, filename, "wb");

		UNWRAP_DATA(Key);

		_this->writePublicKey(out, DataFormat::get(format));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}
