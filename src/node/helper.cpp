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

std::string encBase64(const char* buf){
	std::string res = "";
	int i = 0;
	while (buf[i] != NULL)
	{
		if ( (48 <= buf[i] && buf[i] <= 57) ||//0-9
			(65 <= buf[i] && buf[i] <= 90) ||//abc...xyz
			(97 <= buf[i] && buf[i] <= 122) || //ABC...XYZ
			(buf[i]=='~' || buf[i]=='!' || buf[i]=='*' || buf[i]=='(' || buf[i]==')' || buf[i]=='\'')
			)
		{
			res.append( &buf[i], 1);
		} else {
			res.append("%");
			char dig1 = (buf[i]&0xF0)>>4;
			char dig2 = (buf[i]&0x0F);
			if ( 0<= dig1 && dig1<= 9) dig1+=48;    //0, 48 in ascii
			if (10<= dig1 && dig1<=15) dig1+=97-10; //a, 97 in ascii
			if ( 0<= dig2 && dig2<= 9) dig2+=48;
			if (10<= dig2 && dig2<=15) dig2+=97-10;
			
			std::string r;
			r.append( &dig1, 1);
			r.append( &dig2, 1);
			res.append(r);//converts char 255 to string "ff"
		}
		i++;
	}
	return res;
}

std::string decBase64(const char* buf){
	std::string str = "";
	int i = 0;
	while (buf[i] != NULL){
		str = str + (char)buf[i];
		i++;
	}
	std::string res = "";
	int len = str.length();
		
	for (int i = 0; i < len; i++) {
		int j = i ;
		char ch = str.at(j);
		if (ch == '%'){
			char tmpstr[] = "0x0__";
			int chnum;
			tmpstr[3] = str.at(j+1);
			tmpstr[4] = str.at(j+2);
			chnum = strtol(tmpstr, NULL, 16);
			res += chnum;
			i += 2;
		} else {
			res += ch;
		}
	}
	return res;
}