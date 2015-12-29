#include "stdafx.h"

#include "wkey.h"

void WKey::Init(v8::Handle<v8::Object> exports) {
	v8::Local<v8::String> className = NanNew<v8::String>("Key");

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = NanNew<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	// Prototype method bindings
	v8::Local<v8::ObjectTemplate> proto = tpl->PrototypeTemplate();

	NODE_SET_METHOD(proto, "load", Load);
	NODE_SET_METHOD(proto, "import", Import);

	// Store the constructor in the target bindings.
	exports->Set(NanNew("Key"), tpl->GetFunction());
	v8::Persistent<v8::Function> handle;
	NanAssignPersistent<v8::Function>(handle, tpl->GetFunction());
}

NAN_METHOD(WKey::New){
	NanScope();

	try{
		WKey *obj = new WKey();
		obj->data_ = new Key();

		obj->Wrap(args.This());

		NanReturnValue(args.This());
	}
	TRY_END();
}

NAN_METHOD(WKey::Load){
	NanScope();

	try{
		if (args[0]->IsUndefined()){
			NanThrowError("Parameter 1 is required");
			NanReturnUndefined();
		}

		v8::Local<v8::String> str = args[0].As<v8::String>();
		char *filename = copyBufferToUtf8String(str);
		if (filename == NULL) {
			NanThrowError("Wrong filename");
			NanReturnUndefined();
		}

		std::string fname(filename);
		free(filename);

		WKey* obj = (WKey*)NanGetInternalFieldPointer(args.This(), 0);

		Handle<Bio> in = NULL;

		try{
			in = new Bio(BIO_TYPE_FILE, fname, "rb");
		}
		catch (Handle<Exception> e){
			NanThrowError("File not found");
			NanReturnUndefined();
		}
		catch (...){
			NanThrowError("File not found");
			NanReturnUndefined();
		}
		try{
			obj->data_->read(in);
		}
		catch (Handle<Exception> e){
			NanThrowError("File has wrong data");
			NanReturnUndefined();
		}

		NanReturnValue(args.This());
	}
	TRY_END();
}

NAN_METHOD(WKey::Import){
	NanScope();

	NanReturnValue(args.This());
}
