#include "stdafx.h"

#include "helper.h"

/**
* Schedule an "allocation failed" exception. This (tries) to allocate
* as well, which very well could (probably will) fail too, but it's the
* best we can do in a bad situation.
*/
void scheduleAllocException() {
	Nan::ThrowError("Allocation failed.");
}

/**
* Get a string out of args[] at the given index, converted to a
* freshly-allocated (char *). Returns a non-null pointer on
* success. On failure, schedules an exception and returns NULL.
*/
char *copyBufferToUtf8String(const v8::Local<v8::String> str) {
	int length = str->Utf8Length();
	char *result = (char *)malloc(length + 1);

	if (result == NULL) {
		scheduleAllocException();
		return NULL;
	}

	result[length] = 'x'; // Set up a small sanity check (see below).
	str->WriteUtf8(result, length + 1);

	if (result[length] != '\0') {
		const char *message = "String conversion failed.";
		Nan::ThrowError(message);
		free(result);
		return NULL;
	}

	return result;
}

v8::Local<v8::Object> stringToBuffer(Handle<std::string> v){
    v8::Local<v8::Object> v8Buf = Nan::NewBuffer(v->length()).ToLocalChecked();
    char* pbuf = node::Buffer::Data(v8Buf);
    memcpy(pbuf, v->c_str(), v->length());                

	return v8Buf;
}

Handle<std::string> getString(v8::Local<v8::String> v8String){
	LOGGER_FN();

	char *cString = copyBufferToUtf8String(v8String);
	if (cString == NULL){
		THROW_EXCEPTION(0, "Helper", NULL, "Parameter has wrong value");
	}
	Handle<std::string> str = new std::string(cString);
	free(cString);
	return str;
}

Handle<std::string> getBuffer(v8::Local<v8::Value> v8Value)
{
	LOGGER_FN();

	//get data from buffer
	char* buf = node::Buffer::Data(v8Value);
	size_t buflen = node::Buffer::Length(v8Value);
	std::string *buffer = new std::string(buf, buflen);
	//free(buf);
	return buffer;
}

Handle<std::string> getErrorText(Handle<Exception> e)
{
	LOGGER_FN();

	Handle<std::string> t = new std::string("");
	switch (e->code()){
	case 1:
	{
		t = new std::string("OpenSSL Error\n");
		t->append(*OpenSSL::printErrors());
	}
	break;
	case 2:
	{
		t = new std::string("You cann't call internal methods if object was destroyed.");
	}
		break;
	default:
		t = new std::string(e->what());
	}

	return t;
}

DataFormat::DATA_FORMAT getCmsFileType(Handle<Bio> in) {
	LOGGER_FN();

	char buf[1] = { 0 };

	LOGGER_OPENSSL(BIO_read);
	if (in.isEmpty() || (BIO_read(in->internal(), buf, sizeof(buf)) <= 0)) {
		THROW_EXCEPTION(0, NULL, NULL, "Error get CMS file type");
	}

	in->seek(0);

	return (0x30 == buf[0]) ? DataFormat::DER : DataFormat::BASE64;
}
