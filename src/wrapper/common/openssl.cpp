#include "../stdafx.h"

#include "openssl.h"
#include "common.h"

void OpenSSL::run()
{
	LOGGER_FN();

	CRYPTO_malloc_debug_init();
	CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
	
	LOGGER_OPENSSL(ERR_load_crypto_strings);
	ERR_load_crypto_strings();
	LOGGER_OPENSSL(OpenSSL_add_all_algorithms);
	OpenSSL_add_all_algorithms();
    
	LOGGER_OPENSSL(ENGINE_load_builtin_engines);
	ENGINE_load_builtin_engines();

#ifndef OPENSSL_NO_CTGOSTCP
	ENGINE_CTGOST_init();
#endif
}

void OpenSSL::stop(){
	LOGGER_FN();

	LOGGER_OPENSSL(ERR_free_strings);
	ERR_free_strings();
	LOGGER_OPENSSL(EVP_cleanup);
	EVP_cleanup();
}

Handle<std::string> OpenSSL::printErrors()
{
	LOGGER_FN();

	Handle<Bio> out = new Bio(BIO_TYPE_MEM, "");
	ERR_print_errors(out->internal());

	return out->read();
}
