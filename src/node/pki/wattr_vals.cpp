#include "../stdafx.h"

#include "wattr.h"
#include "wattr_vals.h"

const char* WAttributeValueCollection::className = "AttributeValues";

void WAttributeValueCollection::Init(v8::Handle<v8::Object> exports){
	LOGGER_FN();

	v8::Local<v8::String> className = Nan::New(WAttributeValueCollection::className).ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "push", Push);
	Nan::SetPrototypeMethod(tpl, "pop", Pop);
	Nan::SetPrototypeMethod(tpl, "removeAt", RemoveAt);

	Nan::SetPrototypeMethod(tpl, "items", Items);
	Nan::SetPrototypeMethod(tpl, "length", Length);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(Nan::New(WAttributeValueCollection::className).ToLocalChecked(), tpl->GetFunction());
}

/*
 * algorithm: Algorithm
 */
NAN_METHOD(WAttributeValueCollection::New){
	LOGGER_FN();

	LOGGER_ARG("algorithm");
	WAttribute *watr = ObjectWrap::Unwrap<WAttribute>(info[0]->ToObject());

	WAttributeValueCollection *obj = new WAttributeValueCollection();
	obj->data_ = new AttributeValueCollection(watr->data_);

	obj->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

/*
 * value: string
 */
NAN_METHOD(WAttributeValueCollection::Push){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(AttributeValueCollection);

		LOGGER_ARG("value");
		v8::String::Utf8Value v8Value(info[0]->ToString());
		std::string value(*v8Value);
		_this->push(value);

		return;
	}
	TRY_END();
}

NAN_METHOD(WAttributeValueCollection::Pop){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(AttributeValueCollection);

		_this->pop();

		return;
	}
	TRY_END();
}

/*
 * index: number
 */
NAN_METHOD(WAttributeValueCollection::RemoveAt){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(AttributeValueCollection);

		LOGGER_ARG("index");
		int index = info[0]->ToNumber()->Uint32Value();

		_this->removeAt(index);

		return;
	}
	TRY_END();
}

/*
* index: number
*/
NAN_METHOD(WAttributeValueCollection::Items){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(AttributeValueCollection);

		LOGGER_ARG("index");
		int index = info[0]->ToNumber()->Uint32Value();

		Handle<std::string> value = _this->items(index);

		info.GetReturnValue().Set(stringToBuffer(value));
		return;
	}
	TRY_END();
}

NAN_METHOD(WAttributeValueCollection::Length){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(AttributeValueCollection);

		info.GetReturnValue().Set(
			Nan::New<v8::Number>(_this->length())
			);
		return;
	}
	TRY_END();
}

v8::Local<v8::Object> WAttributeValueCollection::NewInstance(v8::Local<v8::Object> attribute){
	LOGGER_FN();

	LOGGER_INFO("Create new instance of JS Pki");
	v8::Local<v8::Object> v8Module = Nan::New<v8::Object>();
	WAttributeValueCollection::Init(v8Module);

	v8::Local<v8::Value> v8Values[] = { attribute };

	v8::Local<v8::Object> v8Object = Nan::Get(v8Module, Nan::New(WAttributeValueCollection::className)
		.ToLocalChecked()).ToLocalChecked()->ToObject()->CallAsConstructor(1, v8Values)->ToObject();

	return v8Object;
}