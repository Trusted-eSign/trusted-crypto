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

	Nan::SetPrototypeMethod(tpl, "keypairGenerate", keypairGenerate);
	Nan::SetPrototypeMethod(tpl, "keypairGenerateMemory", keypairGenerateMemory);
	Nan::SetPrototypeMethod(tpl, "keypairGenerateBIO", keypairGenerateBIO);

	Nan::SetPrototypeMethod(tpl, "privkeyLoad", privkeyLoad);
	Nan::SetPrototypeMethod(tpl, "privkeyLoadMemory", privkeyLoadMemory);
	//Nan::SetPrototypeMethod(tpl, "privkeyLoadBIO", privkeyLoadBIO);

	Nan::SetPrototypeMethod(tpl, "pubkeyLoad", pubkeyLoad);
	Nan::SetPrototypeMethod(tpl, "pubkeyLoadMemory", pubkeyLoadMemory);
	//Nan::SetPrototypeMethod(tpl, "pubkeyLoadBIO", pubkeyLoadBIO);

	Nan::SetPrototypeMethod(tpl, "privkeySave", privkeySave);
	Nan::SetPrototypeMethod(tpl, "privkeySaveBIO", privkeySaveBIO);
	Nan::SetPrototypeMethod(tpl, "privkeySaveMemory", privkeySaveMemory);

	Nan::SetPrototypeMethod(tpl, "pubkeySave", pubkeySave);
	Nan::SetPrototypeMethod(tpl, "pubkeySaveBIO", pubkeySaveBIO);
	Nan::SetPrototypeMethod(tpl, "pubkeySaveMemory", pubkeySaveMemory);

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

NAN_METHOD(WKey::keypairGenerate){
	METHOD_BEGIN();

	try{
		if (info[0]->IsUndefined()){
			Nan::ThrowError("Parameter 1 is required");
			return;
		}
		if (info[1]->IsUndefined()){
			Nan::ThrowError("Parameter 2 is required");
			return;
		}
		if (info[2]->IsUndefined()){
			Nan::ThrowError("Parameter 3 is required");
			return;
		}
		if (info[3]->IsUndefined()){
			Nan::ThrowError("Parameter 4 is required");
			return;
		}

		v8::String::Utf8Value v8Str(info[0]->ToString());
		char *filename = *v8Str;

		if (filename == NULL) {
			Nan::ThrowError("Wrong filename");
			return;
		}

		std::string fname(filename);

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		LOGGER_ARG("keySize");
		int keySize = info[2]->ToNumber()->Int32Value();

		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[3]->ToString());
		char *password = *v8Pass;

		UNWRAP_DATA(Key);

		try{
			_this->keypairGenerate(fname, DataFormat::get(format), keySize, password);
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("Error create new key");
			return;
		}


		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::keypairGenerateMemory){
	METHOD_BEGIN();

	try{
		std::string data;

		LOGGER_ARG("format");
		int format = info[0]->ToNumber()->Int32Value();

		LOGGER_ARG("keySize");
		int keySize = info[1]->ToNumber()->Int32Value();

		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[2]->ToString());
		char *password = *v8Pass;

		UNWRAP_DATA(Key);

		try{
			_this->keypairGenerateMemory(data, DataFormat::get(format), keySize, password);
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("Error create new key");
			return;
		}


		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::keypairGenerateBIO){
	METHOD_BEGIN();

	try{
		std::string data;
		Handle<Bio> out = NULL;

		out = new Bio(BIO_TYPE_MEM, data, "w+");

		LOGGER_ARG("format");
		int format = info[0]->ToNumber()->Int32Value();

		LOGGER_ARG("keySize");
		int keySize = info[1]->ToNumber()->Int32Value();

		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[2]->ToString());
		char *password = *v8Pass;

		UNWRAP_DATA(Key);

		try{
			_this->keypairGenerateBIO(out, DataFormat::get(format), keySize, password);
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("Error create new key");
			return;
		}


		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

/*
 * filename: string
 */
NAN_METHOD(WKey::privkeyLoad){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("filename");
		if (info[0]->IsUndefined()){
			Nan::ThrowError("Parameter 1 is required");
			return;
		}

		v8::String::Utf8Value v8Str(info[0]->ToString());
		char *filename = *v8Str;

		if (filename == NULL) {
			Nan::ThrowError("Wrong filename");
			return;
		}

		std::string fname(filename);

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[2]->ToString());
		char *password = *v8Pass;

		UNWRAP_DATA(Key);

		_this->privkeyLoad(fname, DataFormat::get(format), password);

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::privkeyLoadMemory){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("data");
		char* buf = node::Buffer::Data(info[0]->ToObject());
		size_t buflen = node::Buffer::Length(info[0]);
		std::string buffer(buf, buflen);

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[2]->ToString());
		char *password = *v8Pass;

		UNWRAP_DATA(Key);

		try{
			_this->privkeyLoadMemory(buffer, DataFormat::get(format), password);
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("Error load key");
			return;
		}


		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::pubkeyLoad){
	METHOD_BEGIN();

	try{
		if (info[0]->IsUndefined()){
			Nan::ThrowError("Parameter 1 is required");
			return;
		}

		v8::String::Utf8Value v8Str(info[0]->ToString());
		char *filename = *v8Str;

		if (filename == NULL) {
			Nan::ThrowError("Wrong filename");
			return;
		}

		std::string fname(filename);

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		UNWRAP_DATA(Key);

		try{
			_this->pubkeyLoad(fname, DataFormat::get(format));
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("Error load key");
			return;
		}


		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::pubkeyLoadMemory){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("data");
		char* buf = node::Buffer::Data(info[0]->ToObject());
		size_t buflen = node::Buffer::Length(info[0]);
		std::string buffer(buf, buflen);

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		UNWRAP_DATA(Key);

		try{
			_this->pubkeyLoadMemory(buffer, DataFormat::get(format));
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("Error load key");
			return;
		}


		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::privkeySave) {
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

		UNWRAP_DATA(Key);

		_this->privkeySave(filename, DataFormat::get(format), password);

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::privkeySaveBIO) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("format");
		int format = info[0]->ToNumber()->Int32Value();

		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[1]->ToString());
		char *password = *v8Pass;

		UNWRAP_DATA(Key);

		Handle<Bio> out = new Bio(BIO_TYPE_MEM, "");
		_this->privkeySaveBIO(out, DataFormat::get(format), password);

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::privkeySaveMemory) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("data");
		char* buf = node::Buffer::Data(info[0]->ToObject());
		size_t buflen = node::Buffer::Length(info[0]);
		std::string buffer(buf, buflen);

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[2]->ToString());
		char *password = *v8Pass;

		UNWRAP_DATA(Key);

		_this->privkeySaveMemory(buffer, DataFormat::get(format), password);

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::pubkeySave) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("filename");
		v8::String::Utf8Value v8Filename(info[0]->ToString());
		char *filename = *v8Filename;

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		UNWRAP_DATA(Key);

		_this->pubkeySave(filename, DataFormat::get(format));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::pubkeySaveBIO) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("format");
		int format = info[0]->ToNumber()->Int32Value();

		UNWRAP_DATA(Key);

		Handle<Bio> out = new Bio(BIO_TYPE_MEM, "");
		_this->pubkeySaveBIO(out, DataFormat::get(format));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WKey::pubkeySaveMemory) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("data");
		char* buf = node::Buffer::Data(info[0]->ToObject());
		size_t buflen = node::Buffer::Length(info[0]);
		std::string buffer(buf, buflen);

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		UNWRAP_DATA(Key);

		_this->pubkeySaveMemory(buffer, DataFormat::get(format));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}