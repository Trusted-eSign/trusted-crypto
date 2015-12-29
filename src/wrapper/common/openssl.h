#include "common.h"

#ifndef COMMON_OPENSSL_T_H_INCLUDED
#define  COMMON_OPENSSL_T_H_INCLUDED

class CTWRAPPER_API OpenSSL;

#include "bio.h"

class CTWRAPPER_API OpenSSL{
	public:
		static void run();
		static void stop();
		static Handle<std::string> printErrors();
};

#endif //!COMMON_OPENSSL_T_H_INCLUDED
