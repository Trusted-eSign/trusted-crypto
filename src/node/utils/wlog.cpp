#include "../stdafx.h"

#ifndef UTIL_WLOG_INCLUDED
#define  UTIL_WLOG_INCLUDED

#include "wlog.h"

void WLogger::Init(v8::Handle<v8::Object> exports){
	v8::Local<v8::String> className = Nan::New("Logger").ToLocalChecked();

	// Basic instance setup
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);

	tpl->SetClassName(className);
	tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

	// Prototype method bindings
	

	Nan::SetPrototypeMethod(tpl, "start", Start);
	Nan::SetPrototypeMethod(tpl, "stop", Stop);
	Nan::SetPrototypeMethod(tpl, "clear", Clear);

	Nan::SetPrototypeMethod(tpl, "write", Write);
	Nan::SetPrototypeMethod(tpl, "info", Info);
	Nan::SetPrototypeMethod(tpl, "warn", Warn);
	Nan::SetPrototypeMethod(tpl, "error", Error);
	Nan::SetPrototypeMethod(tpl, "debug", Debug);

	/*NODE_SET_METHOD(proto, "certificate", Certificate);*/

	// Store the constructor in the target bindings.
	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
}

NAN_METHOD(WLogger::New){
	WLogger*obj = new WLogger();
	try{
		if (info[0]->IsBoolean() && info[0]->ToBoolean()->Value()){
			obj->data_.attach(&logger);
			obj->data_.getRCObject().addReference();
		}
		else{
			obj->data_ = new Logger();
		}
	}
	catch (Handle<Exception> e){
		Nan::ThrowError(e->what());
	}

	obj->Wrap(info.This());

	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(WLogger::Start)
{
	if (info.Length() < 1){
		Nan::ThrowError("Wrong number of arguments. Must be more then 1");
	}

	//get filename
	v8::Local<v8::String> str = info[0].As<v8::String>();
	char *filename = copyBufferToUtf8String(str);
	if (filename == NULL) {
		Nan::ThrowError("Wrong filename");
	}
	std::string sfilename(filename);
	free(filename);

	//get LoggerLevel
	v8::Local<v8::Number> v8Levels = info[1].As<v8::Number>();
	int levels = v8Levels->Value();

	UNWRAP_DATA(Logger);

	_this->start(sfilename.c_str(), levels);

	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(WLogger::Stop)
{
	UNWRAP_DATA(Logger);

	logger.info(__FUNCTION__, "Hello from Wrapper");
	//_this->stop();

	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(WLogger::Write)
{
	UNWRAP_DATA(Logger);

	Nan::ThrowError("method is not complited");

	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(WLogger::Info)
{
	UNWRAP_DATA(Logger);

	Handle<std::string> fn = getString(info[0].As<v8::String>());
	Handle<std::string> msg = getString(info[1].As<v8::String>());

	_this->info(fn->c_str(), msg->c_str(), NULL);

	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(WLogger::Debug)
{
	UNWRAP_DATA(Logger);

	Handle<std::string> fn = getString(info[0].As<v8::String>());
	Handle<std::string> msg = getString(info[1].As<v8::String>());

	_this->debug(fn->c_str(), msg->c_str(), NULL);

	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(WLogger::Error)
{
	UNWRAP_DATA(Logger);

	Handle<std::string> fn = getString(info[0].As<v8::String>());
	Handle<std::string> msg = getString(info[1].As<v8::String>());

	_this->error(fn->c_str(), msg->c_str(), NULL);

	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(WLogger::Warn)
{
	UNWRAP_DATA(Logger);

	Handle<std::string> fn = getString(info[0].As<v8::String>());
	Handle<std::string> msg = getString(info[1].As<v8::String>());

	_this->warn(fn->c_str(), msg->c_str(), NULL);

	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(WLogger::Clear)
{
	UNWRAP_DATA(Logger);

	_this->clear();

	info.GetReturnValue().Set(info.This());
}

#endif //!UTIL_WLOG_INCLUDED
