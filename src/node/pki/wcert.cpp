#include "../stdafx.h"

#include <node_buffer.h>
//#include <string_bytes.h>

#include "wcert.h"
#include "wkey.h"

void WCertificate::Init(v8::Handle<v8::Object> exports){
	v8::Local<v8::String> className = Nan::New("Certificate").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "load", Load);
	Nan::SetPrototypeMethod(tpl, "import", Import);

	Nan::SetPrototypeMethod(tpl, "save", Save);
	Nan::SetPrototypeMethod(tpl, "export", Export);

	Nan::SetPrototypeMethod(tpl, "getSubjectFriendlyName", GetSubjectFriendlyName);
	Nan::SetPrototypeMethod(tpl, "getIssuerFriendlyName", GetIssuerFriendlyName);
	Nan::SetPrototypeMethod(tpl, "getSubjectName", GetSubjectName);
	Nan::SetPrototypeMethod(tpl, "getIssuerName", GetIssuerName);
	Nan::SetPrototypeMethod(tpl, "getNotAfter", GetNotAfter);
	Nan::SetPrototypeMethod(tpl, "getNotBefore", GetNotBefore);
	Nan::SetPrototypeMethod(tpl, "getSerialNumber", GetSerialNumber);
	Nan::SetPrototypeMethod(tpl, "getThumbprint", GetThumbprint);
	Nan::SetPrototypeMethod(tpl, "getVersion", GetVersion);
    Nan::SetPrototypeMethod(tpl, "getType", GetType);
    Nan::SetPrototypeMethod(tpl, "getKeyUsage", GetKeyUsage);
	Nan::SetPrototypeMethod(tpl, "compare", Compare);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
	
	exports->Set(Nan::New("Certificate").ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WCertificate::New){
	try{
		WCertificate *obj = new WCertificate();
		obj->data_ = new Certificate();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::Load){
	try{
		if (info[0]->IsUndefined()){
			Nan::ThrowError("Parameter 1 is required");
			return;
		}

		v8::Local<v8::String> str = info[0].As<v8::String>();
		char *filename = copyBufferToUtf8String(str);
		if (filename == NULL) {
			Nan::ThrowError("Wrong filename");
			return;
		}

		std::string fname(filename);
		free(filename);

		WCertificate* obj = (WCertificate*)Nan::GetInternalFieldPointer(info.This(), 0);

		Handle<Bio> in = NULL;

		try{
			in = new Bio(BIO_TYPE_FILE, fname, "rb");
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("File not found");
			return;
		}

		try{
			obj->data_->read(in);
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("File has wrong data");
			return;
		}

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::Import){
	try{
		//get data from buffer
		char* buf = node::Buffer::Data(info[0]);
		size_t buflen = node::Buffer::Length(info[0]);
		std::string buffer(buf, buflen);

		//unwrap
		WCertificate* v8This = (WCertificate*)Nan::GetInternalFieldPointer(info.This(), 0);
		Handle<Certificate> _this = v8This->data_;

		try{
			Handle<Bio> in = new Bio(BIO_TYPE_MEM, buffer);

			_this->read(in);
		}
		catch (Handle<Exception> e){
			Nan::ThrowError(e->what());
			return;
		}

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::Save){
	try{
		if (info[0]->IsUndefined()){
			Nan::ThrowError("Parameter 1 is required (filename)");
			return;
		}

		v8::Local<v8::String> str = info[0].As<v8::String>();
		char *filename = copyBufferToUtf8String(str);
		if (filename == NULL) {
			Nan::ThrowError("Wrong filename");
			return;
		}

		std::string fname(filename);
		free(filename);

		WCertificate* obj = (WCertificate*)Nan::GetInternalFieldPointer(info.This(), 0);
		Handle<Certificate> cert = obj->data_;

		Handle<Bio> out = new Bio(BIO_TYPE_FILE, fname, "wb");
		cert->write(out);
		out->flush();

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::Export){
	try{
		UNWRAP_DATA(Certificate);

		Handle<Bio> out = new Bio(BIO_TYPE_MEM, "");
		_this->write(out);

		Handle<std::string> buf = out->read();

		info.GetReturnValue().Set(
			stringToBuffer(buf)
		);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::GetSubjectFriendlyName){
	try{
		UNWRAP_DATA(Certificate);

		Handle<std::string> fname = _this->subjectFriendlyName();

		v8::Local<v8::String> v8FName = Nan::New<v8::String>(fname->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8FName);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::GetIssuerFriendlyName){
	try{
		WCertificate* obj = (WCertificate*)Nan::GetInternalFieldPointer(info.This(), 0);
		Handle<Certificate> cert = obj->data_;

		Handle<std::string> fname = cert->issuerFriendlyName();

		v8::Local<v8::String> v8FName = Nan::New<v8::String>(fname->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8FName);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::GetSubjectName){
	try{
		WCertificate* obj = (WCertificate*)Nan::GetInternalFieldPointer(info.This(), 0);
		Handle<Certificate> cert = obj->data_;

		Handle<std::string> name = NULL;
		name = cert->subjectName();

		v8::Local<v8::String> v8Name = Nan::New<v8::String>(name->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Name);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::GetIssuerName){
	try{
		WCertificate* obj = (WCertificate*)Nan::GetInternalFieldPointer(info.This(), 0);
		Handle<Certificate> cert = obj->data_;

		Handle<std::string> name = NULL;

		name = cert->issuerName();

		v8::Local<v8::String> v8Name = Nan::New<v8::String>(name->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Name);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::GetNotBefore)
{
	try{
		WCertificate* obj = (WCertificate*)Nan::GetInternalFieldPointer(info.This(), 0);
		Handle<Certificate> cert = obj->data_;

		Handle<std::string> time = NULL;

		time = cert->notBefore();

		v8::Local<v8::String> v8Time = Nan::New<v8::String>(time->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Time);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::GetNotAfter)
{
	try{
		WCertificate* obj = (WCertificate*)Nan::GetInternalFieldPointer(info.This(), 0);
		Handle<Certificate> cert = obj->data_;

		Handle<std::string> time = NULL;

		time = cert->notAfter();

		v8::Local<v8::String> v8Time = Nan::New<v8::String>(time->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Time);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::GetSerialNumber)
{
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Certificate);

		Handle<std::string> buf = _this->serialNumber();                

		info.GetReturnValue().Set(
			stringToBuffer(buf)
		);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::GetThumbprint)
{
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Certificate);

		Handle<std::string> buf = _this->thumbprint();

		info.GetReturnValue().Set(
			stringToBuffer(buf)
		);
        
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::Compare){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Certificate);

		WCertificate* obj = (WCertificate*)Nan::GetInternalFieldPointer(info[0]->ToObject(), 0);
		Handle<Certificate> cert = obj->data_;

		int res = _this->compare(cert);

		v8::Local<v8::Number> v8Number = Nan::New<v8::Number>(res);

		info.GetReturnValue().Set(v8Number);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::GetVersion)
{
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Certificate);

		long version = _this->version();

		info.GetReturnValue().Set(
			Nan::New<v8::Number>(version)
		);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::GetType)
{
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Certificate);

		int type = _this->type();

		info.GetReturnValue().Set(
			Nan::New<v8::Number>(type)
		);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCertificate::GetKeyUsage)
{
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Certificate);

		int type = _this->keyUsage();

		info.GetReturnValue().Set(
			Nan::New<v8::Number>(type)
		);
		return;
	}
	TRY_END();
}