#include "../stdafx.h"

#include "wsystem.h"

void WProvider_System::Init(v8::Handle<v8::Object> exports){
	METHOD_BEGIN();

	v8::Local<v8::String> className = Nan::New("Provider_System").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
	
	exports->Set(className, tpl->GetFunction());
}

NAN_METHOD(WProvider_System::New){
	METHOD_BEGIN();

	try{
		LOGGER_ARG("folder");
		v8::String::Utf8Value v8Folder(info[0]->ToString());
		char *folder = *v8Folder;

		WProvider_System *obj = new WProvider_System();
		Handle<std::string> str = new std::string(folder);
		obj->data_ = new Provider_System(str);

		obj->Wrap(info.This());

		info.GetReturnValue().Set(info.This());
		return;
	}
	TRY_END();
}