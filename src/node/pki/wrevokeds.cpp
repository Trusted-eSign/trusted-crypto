#include "../stdafx.h"

#include "wrevokeds.h"
#include "wrevoked.h"

const char* WRevokedCollection::className = "RevokedCollection";

void WRevokedCollection::Init(v8::Handle<v8::Object> exports){
	v8::Local<v8::String> v8ClassName = Nan::New(WRevokedCollection::className).ToLocalChecked();

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

NAN_METHOD(WRevokedCollection::New){
	WRevokedCollection *obj = new WRevokedCollection();
	obj->data_ = new RevokedCollection();

	obj->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

/*
 * index: number
 */
NAN_METHOD(WRevokedCollection::Items){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(RevokedCollection);

		LOGGER_ARG("index");
		int index = info[0]->ToNumber()->Uint32Value();

		Handle<Revoked> rv = _this->items(index);

		v8::Local<v8::Object> v8Rv = WRevoked::NewInstance(rv);
		
		info.GetReturnValue().Set(v8Rv);
		return;
	}
	TRY_END();
}

NAN_METHOD(WRevokedCollection::Length){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(RevokedCollection);

		int len = _this->length();

		info.GetReturnValue().Set(Nan::New<v8::Number>(len));
		return;
	}
	TRY_END();
}

NAN_METHOD(WRevokedCollection::Pop){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(RevokedCollection);

		_this->pop();
		return;
	}
	TRY_END();
}

/*
 * index: number
 */
NAN_METHOD(WRevokedCollection::RemoveAt){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(RevokedCollection);

		LOGGER_ARG("index")
		int index = info[0]->ToNumber()->Uint32Value();

		_this->removeAt(index);
		return;
	}
	TRY_END();
}

/*
* rv: Revoked
*/
NAN_METHOD(WRevokedCollection::Push){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(RevokedCollection);

		LOGGER_ARG("rv")
		WRevoked * wRv = WRevoked::Unwrap<WRevoked>(info[0]->ToObject());

		_this->push(wRv->data_);
		return;
	}
	TRY_END();
}
