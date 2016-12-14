#include "../stdafx.h"

#include "../pki/wcert.h"
#include "../pki/walg.h"
#include "wsigned_data.h"
#include "wsigner_attrs.h"
#include "wsigner.h"
#include "wsigner_id.h"

const char* WSigner::className = "Signer";

void WSigner::Init(v8::Handle<v8::Object> exports){
	LOGGER_FN();

	v8::Local<v8::String> className = Nan::New(WSigner::className).ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "setCertificate", SetCertificate);
	Nan::SetPrototypeMethod(tpl, "getCertificate", GetCertificate);
	Nan::SetPrototypeMethod(tpl, "getSignature", GetSignature);
	Nan::SetPrototypeMethod(tpl, "getSignatureAlgorithm", GetSignatureAlgorithm);
	Nan::SetPrototypeMethod(tpl, "getDigestAlgorithm", GetDigestAlgorithm);
	Nan::SetPrototypeMethod(tpl, "getSignerId", GetSignerId);

	Nan::SetPrototypeMethod(tpl, "getSignedAttributes", GetSignedAttributes);
	Nan::SetPrototypeMethod(tpl, "getUnsignedAttributes", GetUnsignedAttributes);
	Nan::SetPrototypeMethod(tpl, "verify", Verify);
	Nan::SetPrototypeMethod(tpl, "verifyContent", VerifyContent);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(Nan::New(WSigner::className).ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WSigner::New){
	METHOD_BEGIN();
	try{
		WSigner *obj = new WSigner();
		obj->data_ = NULL;

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WSigner::VerifyContent) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Signer);

		Handle<Bio> buffer;
		bool res;
		WSignedData *wSd = NULL;

		if (info[0]->IsString()){
			LOGGER_INFO("Set content from file");
			v8::String::Utf8Value v8Filename(info[0]->ToString());

			BIO *pBuffer = BIO_new_file(*v8Filename, "rb");
			if (!pBuffer){
				Nan::ThrowError("File not found");
				return;
			}

			Handle<std::string> in = (new Bio(pBuffer))->read();
			BIO *mem = BIO_new(BIO_s_mem());
			BIO_write(mem, in->c_str(), in->length());
			buffer = new Bio(mem);
		}
		else{
			LOGGER_INFO("Set content from buffer");
			v8::Local<v8::Object> v8Buffer = info[0]->ToObject();

			BIO *pBuffer = BIO_new_mem_buf(node::Buffer::Data(v8Buffer), node::Buffer::Length(v8Buffer));
			buffer = new Bio(pBuffer);
		}

		res = _this->verify(buffer);

		info.GetReturnValue().Set(Nan::New<v8::Boolean>(res));
		return;
	}
	TRY_END();
}

NAN_METHOD(WSigner::Verify) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Signer);

		info.GetReturnValue().Set(Nan::New<v8::Boolean>(_this->verify()));
		return;
	}
	TRY_END();
}

/*
 * cert: Cewrtificate
 */
NAN_METHOD(WSigner::SetCertificate){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Signer);

		LOGGER_ARG("cert");
		WCertificate* wcert = Wrapper::Unwrap<WCertificate>(info[0]->ToObject());

		_this->setCertificate(wcert->data_);
		return;
	}
	TRY_END();
}

NAN_METHOD(WSigner::GetCertificate){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Signer);

		Handle<Certificate> cert = _this->getCertificate();
		v8::Local<v8::Object> v8Cert = WCertificate::NewInstance(cert);

		info.GetReturnValue().Set(v8Cert);
		return;
	}
	TRY_END();
}

NAN_METHOD(WSigner::GetSignature){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Signer);

		Handle<std::string> signature = _this->getSignature();

		info.GetReturnValue().Set(stringToBuffer(signature));
		return;
	}
	TRY_END();
}

NAN_METHOD(WSigner::GetSignatureAlgorithm){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Signer);

		Handle<Algorithm> alg = _this->getSignatureAlgorithm();
		v8::Local<v8::Object> v8Alg = WAlgorithm::NewInstance(alg);

		info.GetReturnValue().Set(v8Alg);
		return;
	}
	TRY_END();
}

NAN_METHOD(WSigner::GetDigestAlgorithm){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Signer);

		Handle<Algorithm> alg = _this->getDigestAlgorithm();
		v8::Local<v8::Object> v8Alg = WAlgorithm::NewInstance(alg);

		info.GetReturnValue().Set(v8Alg);
		return;
	}
	TRY_END();
}

NAN_METHOD(WSigner::GetSignerId){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Signer);

		Handle<SignerId> id = _this->getSignerId();
		v8::Local<v8::Object> v8Id = WSignerId::NewInstance(id);

		info.GetReturnValue().Set(v8Id);
		return;
	}
	TRY_END();
}

NAN_METHOD(WSigner::GetSignedAttributes){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Signer);

		Handle<SignerAttributeCollection> attrs = _this->signedAttributes();
		v8::Local<v8::Object> v8Attrs = WSignerAttributeCollection::NewInstance(attrs);

		info.GetReturnValue().Set(v8Attrs);
		return;
	}
	TRY_END();
}

NAN_METHOD(WSigner::GetUnsignedAttributes){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(Signer);

		Handle<SignerAttributeCollection> attrs = _this->unsignedAttributes();
		v8::Local<v8::Object> v8Attrs = WSignerAttributeCollection::NewInstance(attrs);

		info.GetReturnValue().Set(v8Attrs);
		return;
	}
	TRY_END();
}
