#include "../stdafx.h"

#include "wcrl.h"
#include "wcert.h"

void WCRL::Init(v8::Handle<v8::Object> exports){
	v8::Local<v8::String> className = Nan::New("CRL").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "load", Load);
	Nan::SetPrototypeMethod(tpl, "import", Import);
	Nan::SetPrototypeMethod(tpl, "save", Save);
	Nan::SetPrototypeMethod(tpl, "export", Export);
	Nan::SetPrototypeMethod(tpl, "equals", Equals);
	Nan::SetPrototypeMethod(tpl, "compare", Compare);
	Nan::SetPrototypeMethod(tpl, "duplicate", Duplicate);
	Nan::SetPrototypeMethod(tpl, "hash", Hash);

	Nan::SetPrototypeMethod(tpl, "getEncoded", GetEncoded);
	Nan::SetPrototypeMethod(tpl, "getSignature", GetSignature);
	Nan::SetPrototypeMethod(tpl, "getVersion", GetVersion);
	Nan::SetPrototypeMethod(tpl, "getIssuerName", GetIssuerName);
	Nan::SetPrototypeMethod(tpl, "getIssuerFriendlyName", GetIssuerFriendlyName);
	Nan::SetPrototypeMethod(tpl, "getLastUpdate", GetLastUpdate);
	Nan::SetPrototypeMethod(tpl, "getNextUpdate", GetNextUpdate);
	Nan::SetPrototypeMethod(tpl, "getCertificate", GetCertificate);
	Nan::SetPrototypeMethod(tpl, "getThumbprint", GetThumbprint);
	Nan::SetPrototypeMethod(tpl, "getSigAlgName", GetSigAlgName);
	Nan::SetPrototypeMethod(tpl, "getSigAlgShortName", GetSigAlgShortName);
	Nan::SetPrototypeMethod(tpl, "getSigAlgOID", GetSigAlgOID);

	Nan::SetPrototypeMethod(tpl, "getRevokedCertificateCert", GetRevokedCertificateCert);
	Nan::SetPrototypeMethod(tpl, "getRevokedCertificateSerial", GetRevokedCertificateSerial);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
	
	exports->Set(Nan::New("CRL").ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WCRL::New){
	WCRL *obj = new WCRL();
	obj->data_ = new CRL();

	obj->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(WCRL::GetVersion){
	try{
		UNWRAP_DATA(CRL);

		long version = _this->getVersion();

		info.GetReturnValue().Set(Nan::New<v8::Number>(version));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::GetIssuerName)
{
	try{

		UNWRAP_DATA(CRL);

		Handle<std::string> name = NULL;

		try{
			name = _this->issuerName();
		}
		catch (Handle<Exception> e){
			Nan::ThrowError(e->what());
			return;
		}

		v8::Local<v8::String> v8Name = Nan::New<v8::String>(name->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Name);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::GetIssuerFriendlyName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CRL);

		Handle<std::string> fname = _this->issuerFriendlyName();

		v8::Local<v8::String> v8FName = Nan::New<v8::String>(fname->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8FName);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::GetLastUpdate)
{
	try{

		UNWRAP_DATA(CRL);

		Handle<std::string> time = NULL;

		try{
			time = _this->getThisUpdate();
		}
		catch (Handle<Exception> e){
			Nan::ThrowError(e->what());
			info.GetReturnValue().SetUndefined();
		}

		v8::Local<v8::String> v8Time = Nan::New<v8::String>(time->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Time);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::GetNextUpdate)
{
	try{
		UNWRAP_DATA(CRL);

		Handle<std::string> time = NULL;

		try{
			time = _this->getNextUpdate();
		}
		catch (Handle<Exception> e){
			Nan::ThrowError(e->what());
			info.GetReturnValue().SetUndefined();
		}

		v8::Local<v8::String> v8Time = Nan::New<v8::String>(time->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Time);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::GetCertificate)
{
	info.GetReturnValue().SetUndefined();
}

NAN_METHOD(WCRL::Load)
{
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

		UNWRAP_DATA(CRL);

		Handle<Bio> _in = NULL;

		try{
			_in = new Bio(BIO_TYPE_FILE, fname, "rb");
		}
		catch (Handle<Exception> e){
			Nan::ThrowError("File not found");
			return;
		}

		try{
			_this->read(_in, DataFormat::DER);
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

NAN_METHOD(WCRL::Import)
{
	try{
		if (info[0]->IsUndefined()){
			Nan::ThrowError("Parameter 1 is required");
			info.GetReturnValue().SetUndefined();
		}

		//get data from buffer
		char* buf = node::Buffer::Data(info[0]);
		size_t buflen = node::Buffer::Length(info[0]);
		std::string buffer(buf, buflen);

		UNWRAP_DATA(CRL);

		Handle<Bio> in = NULL;

		try{
			Handle<Bio> in = new Bio(BIO_TYPE_MEM, buffer);

			_this->read(in, DataFormat::DER);
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

NAN_METHOD(WCRL::Save)
{
	try{
		if (info[0]->IsUndefined()){
			Nan::ThrowError("Parameter 1 is required (filename)");
			info.GetReturnValue().SetUndefined();
		}

		v8::Local<v8::String> str = info[0].As<v8::String>();
		char *filename = copyBufferToUtf8String(str);
		if (filename == NULL) {
			Nan::ThrowError("Wrong filename");
			info.GetReturnValue().SetUndefined();
		}

		std::string fname(filename);
		free(filename);

		UNWRAP_DATA(CRL);

		try{
			Handle<Bio> out = new Bio(BIO_TYPE_FILE, fname, "wb");
			_this->write(out, DataFormat::DER);
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

NAN_METHOD(WCRL::Export)
{
	try{
		UNWRAP_DATA(CRL);

		Handle<Bio> out = new Bio(BIO_TYPE_MEM, "");
		_this->write(out, DataFormat::DER);

		Handle<std::string> buf = out->read();

		info.GetReturnValue().Set(
			stringToBuffer(buf)
		);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::Equals) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CRL);

		LOGGER_ARG("CRL")
		WCRL* obj = (WCRL*)Nan::GetInternalFieldPointer(info[0]->ToObject(), 0);
		Handle<CRL> crl = obj->data_;

		int res = _this->equals(crl);

		info.GetReturnValue().Set(
			Nan::New<v8::Integer>(res)
			);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::Compare) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CRL);

		LOGGER_ARG("crl")
		WCRL* obj = (WCRL*)Nan::GetInternalFieldPointer(info[0]->ToObject(), 0);
		Handle<CRL> crl = obj->data_;

		int res = _this->compare(crl);

		v8::Local<v8::Number> v8Number = Nan::New<v8::Number>(res);

		info.GetReturnValue().Set(v8Number);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::Duplicate)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CRL);

		Handle<CRL> crl = _this->duplicate();
		v8::Local<v8::Object> v8CRL = WCRL::NewInstance(crl);
		info.GetReturnValue().Set(v8CRL);

		info.GetReturnValue().Set(v8CRL);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::GetThumbprint)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CRL);

		Handle<std::string> buf = _this->getThumbprint();

		info.GetReturnValue().Set(
			stringToBuffer(buf)
			);

		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::Hash)
{
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CRL);

		LOGGER_ARG("algorithm")
		v8::String::Utf8Value v8Alg(info[0]->ToString());
		char *alg = *v8Alg;

		Handle<std::string> hash = _this->hash(new std::string(alg));

		info.GetReturnValue().Set(stringToBuffer(hash));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::GetEncoded) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CRL);

		Handle<std::string> encCrl = _this->getEncoded();

		info.GetReturnValue().Set(stringToBuffer(encCrl));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::GetSignature) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CRL);

		Handle<std::string> sigCrl = _this->getSignature();

		info.GetReturnValue().Set(stringToBuffer(sigCrl));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::GetSigAlgName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CRL);

		Handle<std::string> algName = _this->getSigAlgName();

		v8::Local<v8::String> v8algName = Nan::New<v8::String>(algName->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8algName);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::GetSigAlgShortName) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CRL);

		Handle<std::string> algSN = _this->getSigAlgShortName();

		v8::Local<v8::String> v8algSN = Nan::New<v8::String>(algSN->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8algSN);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::GetSigAlgOID) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CRL);

		Handle<std::string> algSN = _this->getSigAlgOID();

		v8::Local<v8::String> v8algSN = Nan::New<v8::String>(algSN->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8algSN);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::GetRevokedCertificateCert) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CRL);
		
		LOGGER_ARG("certificate")
		WCertificate * wCert = WCertificate::Unwrap<WCertificate>(info[0]->ToObject());

		_this->getRevokedCertificate(wCert->data_);

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCRL::GetRevokedCertificateSerial) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(CRL);

		LOGGER_ARG("serial")
		v8::String::Utf8Value v8serial(info[0]->ToString());
		char *serial = *v8serial;
		std::string strSerial(serial);

		_this->getRevokedCertificate(&strSerial);

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}