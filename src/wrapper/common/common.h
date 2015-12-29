#ifndef CMS_COMMON_H_INCLUDED
#define  CMS_COMMON_H_INCLUDED

#include <string>
#include <openssl/engine.h>

//#if defined(CTWRAPPER_STATIC) // �������� �������� ����
#if !defined(_WIN32) || defined(CTWRAPPER_STATIC)
#define CTWRAPPER_API
#elif defined(CTWRAPPER_EXPORTS)
#define CTWRAPPER_API __declspec(dllexport)
#else // !CTWRAPPER_EXPORTS
#define CTWRAPPER_API __declspec(dllimport)
#endif // !CTWRAPPER_EXPORTS

#include "refcount.h"
#include "excep.h"
#include "log.h"

//GLOBAL LOG
extern CTWRAPPER_API Logger logger;

#include "bio.h"
#include "object.h"
#include "prov.h"
#include "openssl.h"

#ifdef _WIN32
#define LIBRARY_EXTENSION "dll"
#else
#define LIBRARY_EXTENSION "so"
#endif

#ifdef WRAPPER_NODEJS
#define LIBRARY_DIRECTORY "node_modules\\"
#else
#define LIBRARY_DIRECTORY ""
#endif

CTWRAPPER_API ENGINE *ENGINE_CTGOST_init();
CTWRAPPER_API ENGINE *ENGINE_CTGOST_get_ptr();
CTWRAPPER_API ENGINE *ENGINE_CAPI_init();
CTWRAPPER_API ENGINE *ENGINE_CAPI_get_ptr();
CTWRAPPER_API Handle<std::string> GetLibraryPath(std::string &name);
//CTWRAPPER_API LPCWSTR CA2W(const char* cs, int len = -1);
//Handle<std::string> CW2A(LPCWSTR text, int len = -1);
Handle<std::string> ASN1_TIME_toString(ASN1_TIME* time);
char *X509_NAME_onelineEx(X509_NAME *a, char *buf, int len);
std::string X509_NAME_oneline_ex(X509_NAME *a);

#endif  //!CMS_COMMON_H_INCLUDED
