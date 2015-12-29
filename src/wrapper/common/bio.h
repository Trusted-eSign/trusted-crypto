#include "common.h"

#ifndef COMMON_BIO_H_INCLUDED
#define  COMMON_BIO_H_INCLUDED

#include <openssl/bio.h>

class CTWRAPPER_API Bio;

#define BIO_BUFFER_SIZE 1024 * 64

class CTWRAPPER_API Bio
{
public:
	Bio(BIO* data, bool del = true);
	Bio(int type, const std::string &data, const std::string &param = "rb");
	~Bio();

	void seek(int index);
	void reset();

	void write(const std::string&buf);
	void write(Handle<std::string> buf);
	void flush();
	Handle<std::string> read(int size = -1);

	int type();

	BIO* internal();

protected:
	void init();

protected: 
	BIO *data_;
	bool delData_;
};

#endif  //!COMMON_BIO_H_INCLUDED
