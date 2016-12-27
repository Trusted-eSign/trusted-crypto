#include "../stdafx.h"

#include "wslot.h"

void WSlot::Init(v8::Handle<v8::Object> exports) {
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("Slot").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	Nan::SetPrototypeMethod(tpl, "findToken", FindToken);

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WSlot::New) {
	METHOD_BEGIN();

	try {
		WSlot *obj = new WSlot();
		obj->data_ = new Slot();

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}

NAN_METHOD(WSlot::FindToken) {
	METHOD_BEGIN();

	try {
		UNWRAP_DATA(Slot);

		Handle<std::string> token = _this->findToken();

		v8::Local<v8::String> v8Token = Nan::New<v8::String>(token->c_str()).ToLocalChecked();
		info.GetReturnValue().Set(v8Token);
		return;
	}
	TRY_END();
}
