#include "../stdafx.h"

#include <node_buffer.h>

#include "wcipher.h"
#include "wcerts.h"
#include "wcert.h"
#include "wkey.h"

void WCipher::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("Cipher").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "setCryptoMethod", SetCryptoMethod);

	Nan::SetPrototypeMethod(tpl, "encrypt", Encrypt);
	Nan::SetPrototypeMethod(tpl, "decrypt", Decrypt);

	Nan::SetPrototypeMethod(tpl, "addRecipientsCerts", AddRecipientsCerts);
	Nan::SetPrototypeMethod(tpl, "setPrivKey", SetPrivKey);
	Nan::SetPrototypeMethod(tpl, "setRecipientCert", SetRecipientCert);

	Nan::SetPrototypeMethod(tpl, "setDigest", SetDigest);
	Nan::SetPrototypeMethod(tpl, "setSalt", SetSalt);
	Nan::SetPrototypeMethod(tpl, "setPass", SetPass);
	Nan::SetPrototypeMethod(tpl, "setIV", SetIV);
	Nan::SetPrototypeMethod(tpl, "setKey", SetKey);

	Nan::SetPrototypeMethod(tpl, "getSalt", GetSalt);
	Nan::SetPrototypeMethod(tpl, "getIV", GetIV);
	Nan::SetPrototypeMethod(tpl, "getKey", GetKey);

	Nan::SetPrototypeMethod(tpl, "getAlgorithm", GetAlgorithm);
	Nan::SetPrototypeMethod(tpl, "getMode", GetMode);
	Nan::SetPrototypeMethod(tpl, "getDigestAlgorithm", GetDigestAlgorithm);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WCipher::New){
	METHOD_BEGIN();
	try{		
		WCipher *obj = new WCipher();
			
		LOGGER_ARG("cipher");
		v8::String::Utf8Value v8Ciph(info[0]->ToString());
		char *ciph = *v8Ciph;
		std::string strCiph(ciph);
		Handle<std::string> res = new std::string(strCiph);
		obj->data_ = new Cipher(res);
		
		obj->Wrap(info.This());
		
		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();	
}

NAN_METHOD(WCipher::SetCryptoMethod) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("method");
		int method = info[0]->ToNumber()->Int32Value();

		UNWRAP_DATA(Cipher);

		_this->setCryptoMethod(CryptoMethod::get(method));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::Encrypt) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("filenameSource");
		v8::String::Utf8Value v8FilenameSource(info[0]->ToString());
		char *filenameSource = *v8FilenameSource;

		LOGGER_ARG("filenameEnc");
		v8::String::Utf8Value v8FilenameEnc(info[1]->ToString());
		char *filenameEnc = *v8FilenameEnc;

		LOGGER_ARG("format");
		int format = info[2]->ToNumber()->Int32Value();

		Handle<Bio> inSource = NULL;
		Handle<Bio> outEnc = NULL;

		inSource = new Bio(BIO_TYPE_FILE, filenameSource, "rb");
		outEnc = new Bio(BIO_TYPE_FILE, filenameEnc, "wb");

		UNWRAP_DATA(Cipher);

		_this->encrypt(inSource, outEnc, DataFormat::get(format));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::Decrypt) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("filenameEnc");
		v8::String::Utf8Value v8FilenameEnc(info[0]->ToString());
		char *filenameEnc = *v8FilenameEnc;

		LOGGER_ARG("filenameDec");
		v8::String::Utf8Value v8FilenameDec(info[1]->ToString());
		char *filenameDec = *v8FilenameDec;

		LOGGER_ARG("format");
		int format = info[2]->ToNumber()->Int32Value();

		Handle<Bio> inEnc = NULL;
		Handle<Bio> outDec = NULL;

		inEnc = new Bio(BIO_TYPE_FILE, filenameEnc, "rb");
		outDec = new Bio(BIO_TYPE_FILE, filenameDec, "wb");

		UNWRAP_DATA(Cipher);

		_this->decrypt(inEnc, outDec, DataFormat::get(format));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::AddRecipientsCerts) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("certs");
		WCertificateCollection * wCerts = WCertificateCollection::Unwrap<WCertificateCollection>(info[0]->ToObject());

		UNWRAP_DATA(Cipher);

		_this->addRecipientsCerts(wCerts->data_);

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::SetRecipientCert) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("rcert");
		WCertificate * wCert = WCertificate::Unwrap<WCertificate>(info[0]->ToObject());

		UNWRAP_DATA(Cipher);

		_this->setRecipientCert(wCert->data_);

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::SetPrivKey) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("rkey");
		WKey * wKey = WKey::Unwrap<WKey>(info[0]->ToObject());

		UNWRAP_DATA(Cipher);

		_this->setPrivKey(wKey->data_);

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::SetPass) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("password");
		v8::String::Utf8Value v8Pass(info[0]->ToString());
		char *pass = *v8Pass;

		UNWRAP_DATA(Cipher);

		_this->setPass(new std::string(pass));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::SetDigest) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("md");
		v8::String::Utf8Value v8MD(info[0]->ToString());
		char *md = *v8MD;

		UNWRAP_DATA(Cipher);

		_this->setDigest(new std::string(md));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::SetIV) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("iv");
		v8::String::Utf8Value v8IV(info[0]->ToString());
		char *iv = *v8IV;

		UNWRAP_DATA(Cipher);

		_this->setIV(new std::string(iv));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::SetKey) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("key");
		v8::String::Utf8Value v8Key(info[0]->ToString());
		char *key = *v8Key;

		UNWRAP_DATA(Cipher);

		_this->setKey(new std::string(key));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::SetSalt) {
	METHOD_BEGIN();

	try {
		LOGGER_ARG("salt");
		v8::String::Utf8Value v8Salt(info[0]->ToString());
		char *salt = *v8Salt;

		UNWRAP_DATA(Cipher);

		_this->setSalt(new std::string(salt));

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::GetSalt) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Cipher);

		Handle<std::string> salt = _this->getSalt();

		info.GetReturnValue().Set(stringToBuffer(salt));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::GetIV) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Cipher);

		Handle<std::string> iv = _this->getIV();

		info.GetReturnValue().Set(stringToBuffer(iv));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::GetKey) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Cipher);

		Handle<std::string> key = _this->getKey();

		info.GetReturnValue().Set(stringToBuffer(key));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::GetAlgorithm) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Cipher);

		Handle<std::string> calg = _this->getAlgorithm();
		v8::Local<v8::String> v8Alg = Nan::New<v8::String>(calg->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Alg);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::GetMode) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Cipher);

		Handle<std::string> mode = _this->getMode();
		v8::Local<v8::String> v8Mode = Nan::New<v8::String>(mode->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Mode);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCipher::GetDigestAlgorithm) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Cipher);

		Handle<std::string> dgst = _this->getDigestAlgorithm();
		v8::Local<v8::String> v8Dgst = Nan::New<v8::String>(dgst->c_str()).ToLocalChecked();

		info.GetReturnValue().Set(v8Dgst);
		return;
	}
	TRY_END();
}