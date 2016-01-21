#include "../stdafx.h"

#include "../pki/wattr.h"
#include "wsigned_data.h"
#include "wsigner_attrs.h"

const char* WSignerAttributeCollection::className = "SignerAttributeCollection";

void WSignerAttributeCollection::Init(v8::Handle<v8::Object> exports){
	LOGGER_FN();

	v8::Local<v8::String> className = Nan::New(WSignerAttributeCollection::className).ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "length", Length);
	Nan::SetPrototypeMethod(tpl, "push", Push);
	Nan::SetPrototypeMethod(tpl, "removeAt", RemoveAt);
	Nan::SetPrototypeMethod(tpl, "items", Items);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(Nan::New(WSignerAttributeCollection::className).ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WSignerAttributeCollection::New){
	METHOD_BEGIN();
	try{
		WSignerAttributeCollection *obj = new WSignerAttributeCollection();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WSignerAttributeCollection::Length){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(SignerAttributeCollection);

		info.GetReturnValue().Set(Nan::New<v8::Number>(_this->length()));
		return;
	}
	TRY_END();
}

/*
 * attr: Attribute
 */
NAN_METHOD(WSignerAttributeCollection::Push){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(SignerAttributeCollection);

		LOGGER_ARG("attr");
		WAttribute *v8Attr = Wrapper::Unwrap<WAttribute>(info[0]->ToObject());

		_this->push(v8Attr->data_);

		return;
	}
	TRY_END();
}

/*
* index: Number
*/
NAN_METHOD(WSignerAttributeCollection::RemoveAt){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(SignerAttributeCollection);

		LOGGER_ARG("index");
		int index = info[0]->ToNumber()->Uint32Value();

		_this->removeAt(index);

		return;
	}
	TRY_END();
}

/*
* index: Number
*/
NAN_METHOD(WSignerAttributeCollection::Items){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(SignerAttributeCollection);

		LOGGER_ARG("index");
		int index = info[0]->ToNumber()->Uint32Value();

		Handle<Attribute> attr = _this->items(index);

		v8::Local<v8::Object> v8Attr = WAttribute::NewInstance(attr);

		info.GetReturnValue().Set(v8Attr);
		return;
	}
	TRY_END();
}