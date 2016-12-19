#include "../stdafx.h"

#include "../pki/wcert.h"
#include "../pki/wcerts.h"
#include "../pki/wkey.h"
#include "wsigner.h"
#include "wsigners.h"
#include "wsigned_data.h"

const char* WSignedData::className = "SignedData";

void WSignedData::Init(v8::Handle<v8::Object> exports){
	LOGGER_FN();

	v8::Local<v8::String> className = Nan::New(WSignedData::className).ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "getContent", GetContent);
	Nan::SetPrototypeMethod(tpl, "setContent", SetContent);
	Nan::SetPrototypeMethod(tpl, "getFlags", GetFlags);
	Nan::SetPrototypeMethod(tpl, "setFlags", SetFlags);

	Nan::SetPrototypeMethod(tpl, "load", Load);
	Nan::SetPrototypeMethod(tpl, "import", Import);
	Nan::SetPrototypeMethod(tpl, "save", Save);
	Nan::SetPrototypeMethod(tpl, "export", Export);
	Nan::SetPrototypeMethod(tpl, "getCertificates", GetCertificates);
	Nan::SetPrototypeMethod(tpl, "getSigners", GetSigners);
	Nan::SetPrototypeMethod(tpl, "isDetached", IsDetached);
	Nan::SetPrototypeMethod(tpl, "createSigner", CreateSigner);
	Nan::SetPrototypeMethod(tpl, "addCertificate", AddCertificate);
	Nan::SetPrototypeMethod(tpl, "verify", Verify);
	Nan::SetPrototypeMethod(tpl, "sign", Sign);

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

/*
* filename: String
* format: DataFormat
*/
NAN_METHOD(WSignedData::Save) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("filename");
		v8::String::Utf8Value v8Filename(info[0]->ToString());
		char *filename = *v8Filename;

		LOGGER_ARG("format");
		int format = info[1]->ToNumber()->Int32Value();

		UNWRAP_DATA(SignedData);

		Handle<Bio> out = new Bio(BIO_TYPE_FILE, filename, "wb");
		_this->write(out, DataFormat::get(format));
		out->flush();

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

/*
* format: DataFormat
*/
NAN_METHOD(WSignedData::Export) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("format");
		int format = info[0]->ToNumber()->Int32Value();

		UNWRAP_DATA(SignedData);

		Handle<Bio> out = new Bio(BIO_TYPE_MEM, "");
		_this->write(out, DataFormat::get(format));

		Handle<std::string> buf = out->read();

		info.GetReturnValue().Set(
			stringToBuffer(buf)
			);
		return;
	}
	TRY_END();
}

NAN_METHOD(WSignedData::GetSigners) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignedData);

		Handle<SignerCollection> signers = _this->signers();

		v8::Local<v8::Object> v8Signers= WSignerCollection::NewInstance(signers);

		info.GetReturnValue().Set(v8Signers);
		return;
	}
	TRY_END();
}

NAN_METHOD(WSignedData::GetCertificates) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignedData);

		Handle<CertificateCollection> certs = _this->certificates();

		v8::Local<v8::Object> v8Certificates = WCertificateCollection::NewInstance(certs);

		info.GetReturnValue().Set(v8Certificates);
		return;
	}
	TRY_END();
}

NAN_METHOD(WSignedData::IsDetached) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignedData);

		v8::Local<v8::Boolean> v8Detached = Nan::New<v8::Boolean>(_this->isDetached());

		info.GetReturnValue().Set(v8Detached);
		return;
	}
	TRY_END();
}

/*
 * certificate: Certificate
 * privateKey: Key
 * digestName: string
 */
NAN_METHOD(WSignedData::CreateSigner) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignedData);

		LOGGER_ARG("certificate");
		WCertificate *wCert = Wrapper::Unwrap<WCertificate>(info[0]->ToObject());

		LOGGER_ARG("privateKey");
		WKey *wKey = Wrapper::Unwrap<WKey>(info[1]->ToObject());

		Handle<Signer> signer = _this->createSigner(wCert->data_, wKey->data_);

		v8::Local<v8::Object> v8Signer = WSigner::NewInstance(signer);

		info.GetReturnValue().Set(v8Signer);
		return;
	}
	TRY_END();
}

/*
 * certificate: Certificate
 */
NAN_METHOD(WSignedData::AddCertificate) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignedData);

		LOGGER_ARG("certificate");
		WCertificate *wCert = Wrapper::Unwrap<WCertificate>(info[0]->ToObject());

		_this->addCertificate(wCert->data_);

		return;
	}
	TRY_END();
}

NAN_METHOD(WSignedData::GetContent) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignedData);

		Handle<std::string> buf = _this->getContent()->read();
		_this->getContent()->reset();

		info.GetReturnValue().Set(stringToBuffer(buf));
		return;
	}
	TRY_END();
}

/*
 * data: string | buffer
 */
NAN_METHOD(WSignedData::SetContent) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignedData);

		Handle<Bio> buffer;

		if (info[0]->IsString()){
			LOGGER_INFO("Set content from file");
			v8::String::Utf8Value v8Filename(info[0]->ToString());

			BIO *pBuffer = BIO_new_file(*v8Filename, "rb");
			if (!pBuffer){
				Nan::ThrowError("File not found");
				return;
			}

			buffer = new Bio(pBuffer);

		}
		else{
			LOGGER_INFO("Set content from buffer");
			v8::Local<v8::Object> v8Buffer = info[0]->ToObject();

			BIO *pBuffer = BIO_new_mem_buf(node::Buffer::Data(v8Buffer), node::Buffer::Length(v8Buffer));
			buffer = new Bio(pBuffer);
		}

		_this->setContent(buffer);

		return;
	}
	TRY_END();
}

/*
 * certs: CertificateCollection
 */
NAN_METHOD(WSignedData::Verify) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignedData);

		WCertificateCollection *wcerts = WCertificateCollection::Unwrap<WCertificateCollection>(info[0]->ToObject());

		bool res = _this->verify(wcerts->data_);
		_this->getContent()->reset();

		info.GetReturnValue().Set(Nan::New<v8::Boolean>(res));
		return;
	}
	TRY_END();
}

NAN_METHOD(WSignedData::Sign) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignedData);
		
		_this->sign();
		return;
	}
	TRY_END();
}

NAN_METHOD(WSignedData::GetFlags) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignedData);

		info.GetReturnValue().Set(Nan::New<v8::Number>(_this->getFlags()));
		return;
	}
	TRY_END();
}

/*
 * value: number
 */
NAN_METHOD(WSignedData::SetFlags) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(SignedData);

		int flags = info[0]->ToNumber()->Uint32Value();
		_this->setFlags(flags);
		return;
	}
	TRY_END();
}