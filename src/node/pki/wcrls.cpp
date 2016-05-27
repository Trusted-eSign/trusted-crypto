#include "../stdafx.h"

#include "wcrls.h"
#include "wcrl.h"

const char* WCrlCollection::className = "CrlCollection";

void WCrlCollection::Init(v8::Handle<v8::Object> exports){
	v8::Local<v8::String> v8ClassName = Nan::New(WCrlCollection::className).ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(v8ClassName);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "items", Items);
	Nan::SetPrototypeMethod(tpl, "push", Push);
	Nan::SetPrototypeMethod(tpl, "pop", Pop);
	Nan::SetPrototypeMethod(tpl, "removeAt", RemoveAt);
	Nan::SetPrototypeMethod(tpl, "length", Length);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
	
	exports->Set(v8ClassName, tpl->GetFunction());
}

NAN_METHOD(WCrlCollection::New){
	WCrlCollection *obj = new WCrlCollection();
	obj->data_ = new CrlCollection();

	obj->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

/*
 * index: number
 */
NAN_METHOD(WCrlCollection::Items){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CrlCollection);

		LOGGER_ARG("index");
		int index = info[0]->ToNumber()->Uint32Value();

		Handle<CRL> crl = _this->items(index);

		v8::Local<v8::Object> v8Crl = WCRL::NewInstance(crl);
		
		info.GetReturnValue().Set(v8Crl);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCrlCollection::Length){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CrlCollection);

		int len = _this->length();

		info.GetReturnValue().Set(Nan::New<v8::Number>(len));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCrlCollection::Pop){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CrlCollection);

		_this->pop();
		return;
	}
	TRY_END();
}

/*
 * index: number
 */
NAN_METHOD(WCrlCollection::RemoveAt){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CrlCollection);

		LOGGER_ARG("index")
		int index = info[0]->ToNumber()->Uint32Value();

		_this->removeAt(index);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCrlCollection::Push){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CrlCollection);

		LOGGER_ARG("crl")
		WCRL * wCrl = WCRL::Unwrap<WCRL>(info[0]->ToObject());

		_this->push(wCrl->data_);
		return;
	}
	TRY_END();
}
