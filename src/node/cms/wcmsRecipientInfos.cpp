#include "../stdafx.h"

#include "wcmsRecipientInfos.h"
#include "wcmsRecipientInfo.h"

void WCmsRecipientInfoCollection::Init(v8::Handle<v8::Object> exports){
	v8::Local<v8::String> className = Nan::New("CmsRecipientInfoCollection").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "items", Items);
	Nan::SetPrototypeMethod(tpl, "push", Push);
	Nan::SetPrototypeMethod(tpl, "pop", Pop);
	Nan::SetPrototypeMethod(tpl, "removeAt", RemoveAt);
	Nan::SetPrototypeMethod(tpl, "length", Length);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
	
	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WCmsRecipientInfoCollection::New){
	WCmsRecipientInfoCollection *obj = new WCmsRecipientInfoCollection();
	obj->data_ = new CmsRecipientInfoCollection();

	obj->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

/*
 * index: number
 */
NAN_METHOD(WCmsRecipientInfoCollection::Items){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CmsRecipientInfoCollection);

		LOGGER_ARG("index");
		int index = info[0]->ToNumber()->Uint32Value();

		Handle<CmsRecipientInfo> ri = _this->items(index);

		v8::Local<v8::Object> v8Ri = WCmsRecipientInfo::NewInstance(ri);
		
		info.GetReturnValue().Set(v8Ri);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCmsRecipientInfoCollection::Length){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CmsRecipientInfoCollection);

		int len = _this->length();

		info.GetReturnValue().Set(Nan::New<v8::Number>(len));
		return;
	}
	TRY_END();
}

NAN_METHOD(WCmsRecipientInfoCollection::Pop){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CmsRecipientInfoCollection);

		_this->pop();
		return;
	}
	TRY_END();
}

/*
 * index: number
 */
NAN_METHOD(WCmsRecipientInfoCollection::RemoveAt){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CmsRecipientInfoCollection);

		LOGGER_ARG("index")
		int index = info[0]->ToNumber()->Uint32Value();

		_this->removeAt(index);
		return;
	}
	TRY_END();
}

NAN_METHOD(WCmsRecipientInfoCollection::Push){
	METHOD_BEGIN();

	try{
		UNWRAP_DATA(CmsRecipientInfoCollection);

		LOGGER_ARG("ri")
		WCmsRecipientInfo * wRi = WCmsRecipientInfo::Unwrap<WCmsRecipientInfo>(info[0]->ToObject());

		_this->push(wRi->data_);
		return;
	}
	TRY_END();
}
