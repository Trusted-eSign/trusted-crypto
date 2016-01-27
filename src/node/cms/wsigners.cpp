#include "../stdafx.h"

#include "wsigned_data.h"
#include "wsigner.h"
#include "wsigners.h"

const char* WSignerCollection::className = "SignerCollection";

void WSignerCollection::Init(v8::Handle<v8::Object> exports){
	v8::Local<v8::String> v8ClassName = Nan::New(WSignerCollection::className).ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(v8ClassName);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "items", Items);
	Nan::SetPrototypeMethod(tpl, "length", Length);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(v8ClassName, tpl->GetFunction());
}

NAN_METHOD(WSignerCollection::New){

	WSignerCollection *obj = new WSignerCollection();
	obj->data_ = NULL;

	// WSignedData *wSd = WSignedData::Unwrap<WSignedData>(info[0]->ToObject());

	// obj->data_ = wSd->data_->signers();

	obj->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

/*
 * index: number
 */
NAN_METHOD(WSignerCollection::Items){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(SignerCollection);

		LOGGER_ARG("index");
		int index = info[0]->ToNumber()->Uint32Value();

		Handle<Signer> signer = _this->items(index);

		v8::Local<v8::Object> v8Signer = WSigner::NewInstance(signer);

		info.GetReturnValue().Set(v8Signer);
		return;
	}
	TRY_END();
}

NAN_METHOD(WSignerCollection::Length){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(SignerCollection);

		int len = _this->length();

		info.GetReturnValue().Set(Nan::New<v8::Number>(len));
		return;
	}
	TRY_END();
}