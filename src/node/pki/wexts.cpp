#include "../stdafx.h"

#include "wexts.h"
#include "wext.h"

const char* WExtensionCollection::className = "ExtensionCollection";

void WExtensionCollection::Init(v8::Handle<v8::Object> exports){
	v8::Local<v8::String> v8ClassName = Nan::New(WExtensionCollection::className).ToLocalChecked();

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

NAN_METHOD(WExtensionCollection::New){
	WExtensionCollection *obj = new WExtensionCollection();
	obj->data_ = new ExtensionCollection();

	obj->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

/*
 * index: number
 */
NAN_METHOD(WExtensionCollection::Items){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(ExtensionCollection);

		LOGGER_ARG("index");
		int index = info[0]->ToNumber()->Uint32Value();

		Handle<Extension> ext = _this->items(index);

		v8::Local<v8::Object> v8Ext = WExtension::NewInstance(ext);
		
		info.GetReturnValue().Set(v8Ext);
		return;
	}
	TRY_END();
}

NAN_METHOD(WExtensionCollection::Length){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(ExtensionCollection);

		int len = _this->length();

		info.GetReturnValue().Set(Nan::New<v8::Number>(len));
		return;
	}
	TRY_END();
}

NAN_METHOD(WExtensionCollection::Pop){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(ExtensionCollection);

		_this->pop();
		return;
	}
	TRY_END();
}

/*
 * index: number
 */
NAN_METHOD(WExtensionCollection::RemoveAt){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(ExtensionCollection);

		LOGGER_ARG("index")
		int index = info[0]->ToNumber()->Uint32Value();

		_this->removeAt(index);
		return;
	}
	TRY_END();
}

NAN_METHOD(WExtensionCollection::Push){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(ExtensionCollection);

		LOGGER_ARG("ext")
		WExtension * wExt = WExtension::Unwrap<WExtension>(info[0]->ToObject());

		_this->push(wExt->data_);
		return;
	}
	TRY_END();
}
