#pragma once

#include "../common/common.h"
#include "../../jsoncpp/json/json.h"
#include <stdio.h>
#include <string>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/e_os2.h>

#if defined(OPENSSL_SYS_WINDOWS) 
	#include <windows.h>
	#include <tchar.h> 
	#include <strsafe.h>
#endif
#if defined(OPENSSL_SYS_UNIX) 
	#include <dirent.h>
	#include <sys/stat.h>
	#include <uuid/uuid.h>
#endif

#include "certstore.h"
using namespace std;

#define sk_EVP_PKEY_new(cmp) SKM_sk_new(EVP_PKEY, (cmp))
#define sk_EVP_PKEY_new_null() SKM_sk_new_null(EVP_PKEY)
#define sk_EVP_PKEY_free(st) SKM_sk_free(EVP_PKEY, (st))
#define sk_EVP_PKEY_num(st) SKM_sk_num(EVP_PKEY, (st))
#define sk_EVP_PKEY_value(st, i) SKM_sk_value(EVP_PKEY, (st), (i))
#define sk_EVP_PKEY_set(st, i, val) SKM_sk_set(EVP_PKEY, (st), (i), (val))
#define sk_EVP_PKEY_zero(st) SKM_sk_zero(EVP_PKEY, (st))
#define sk_EVP_PKEY_push(st, val) SKM_sk_push(EVP_PKEY, (st), (val))
#define sk_EVP_PKEY_unshift(st, val) SKM_sk_unshift(EVP_PKEY, (st), (val))
#define sk_EVP_PKEY_find(st, val) SKM_sk_find(EVP_PKEY, (st), (val))
#define sk_EVP_PKEY_find_ex(st, val) SKM_sk_find_ex(EVP_PKEY, (st), (val))
#define sk_EVP_PKEY_delete(st, i) SKM_sk_delete(EVP_PKEY, (st), (i))
#define sk_EVP_PKEY_delete_ptr(st, ptr) SKM_sk_delete_ptr(EVP_PKEY, (st), (ptr))
#define sk_EVP_PKEY_insert(st, val, i) SKM_sk_insert(EVP_PKEY, (st), (val), (i))
#define sk_EVP_PKEY_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(EVP_PKEY, (st), (cmp))
#define sk_EVP_PKEY_dup(st) SKM_sk_dup(EVP_PKEY, st)
#define sk_EVP_PKEY_pop_free(st, free_func) SKM_sk_pop_free(EVP_PKEY, (st), (free_func))
#define sk_EVP_PKEY_shift(st) SKM_sk_shift(EVP_PKEY, (st))
#define sk_EVP_PKEY_pop(st) SKM_sk_pop(EVP_PKEY, (st))
#define sk_EVP_PKEY_sort(st) SKM_sk_sort(EVP_PKEY, (st))
#define sk_EVP_PKEY_is_sorted(st) SKM_sk_is_sorted(EVP_PKEY, (st))

#define sk_X509_REQ_new(cmp) SKM_sk_new(X509_REQ, (cmp))
#define sk_X509_REQ_new_null() SKM_sk_new_null(X509_REQ)
#define sk_X509_REQ_free(st) SKM_sk_free(X509_REQ, (st))
#define sk_X509_REQ_num(st) SKM_sk_num(X509_REQ, (st))
#define sk_X509_REQ_value(st, i) SKM_sk_value(X509_REQ, (st), (i))
#define sk_X509_REQ_set(st, i, val) SKM_sk_set(X509_REQ, (st), (i), (val))
#define sk_X509_REQ_zero(st) SKM_sk_zero(X509_REQ, (st))
#define sk_X509_REQ_push(st, val) SKM_sk_push(X509_REQ, (st), (val))
#define sk_X509_REQ_unshift(st, val) SKM_sk_unshift(X509_REQ, (st), (val))
#define sk_X509_REQ_find(st, val) SKM_sk_find(X509_REQ, (st), (val))
#define sk_X509_REQ_find_ex(st, val) SKM_sk_find_ex(X509_REQ, (st), (val))
#define sk_X509_REQ_delete(st, i) SKM_sk_delete(X509_REQ, (st), (i))
#define sk_X509_REQ_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_REQ, (st), (ptr))
#define sk_X509_REQ_insert(st, val, i) SKM_sk_insert(X509_REQ, (st), (val), (i))
#define sk_X509_REQ_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_REQ, (st), (cmp))
#define sk_X509_REQ_dup(st) SKM_sk_dup(X509_REQ, st)
#define sk_X509_REQ_pop_free(st, free_func) SKM_sk_pop_free(X509_REQ, (st), (free_func))
#define sk_X509_REQ_shift(st) SKM_sk_shift(X509_REQ, (st))
#define sk_X509_REQ_pop(st) SKM_sk_pop(X509_REQ, (st))
#define sk_X509_REQ_sort(st) SKM_sk_sort(X509_REQ, (st))
#define sk_X509_REQ_is_sorted(st) SKM_sk_is_sorted(X509_REQ, (st))

#define sk_X509_URI_new(cmp) SKM_sk_new(X509_URI, (cmp))
#define sk_X509_URI_new_null() SKM_sk_new_null(X509_URI)
#define sk_X509_URI_free(st) SKM_sk_free(X509_URI, (st))
#define sk_X509_URI_num(st) SKM_sk_num(X509_URI, (st))
#define sk_X509_URI_value(st, i) SKM_sk_value(X509_URI, (st), (i))
#define sk_X509_URI_set(st, i, val) SKM_sk_set(X509_URI, (st), (i), (val))
#define sk_X509_URI_zero(st) SKM_sk_zero(X509_URI, (st))
#define sk_X509_URI_push(st, val) SKM_sk_push(X509_URI, (st), (val))
#define sk_X509_URI_unshift(st, val) SKM_sk_unshift(X509_URI, (st), (val))
#define sk_X509_URI_find(st, val) SKM_sk_find(X509_URI, (st), (val))
#define sk_X509_URI_find_ex(st, val) SKM_sk_find_ex(X509_URI, (st), (val))
#define sk_X509_URI_delete(st, i) SKM_sk_delete(X509_URI, (st), (i))
#define sk_X509_URI_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_URI, (st), (ptr))
#define sk_X509_URI_insert(st, val, i) SKM_sk_insert(X509_URI, (st), (val), (i))
#define sk_X509_URI_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_URI, (st), (cmp))
#define sk_X509_URI_dup(st) SKM_sk_dup(X509_URI, st)
#define sk_X509_URI_pop_free(st, free_func) SKM_sk_pop_free(X509_URI, (st), (free_func))
#define sk_X509_URI_shift(st) SKM_sk_shift(X509_URI, (st))
#define sk_X509_URI_pop(st) SKM_sk_pop(X509_URI, (st))
#define sk_X509_URI_sort(st) SKM_sk_sort(X509_URI, (st))
#define sk_X509_URI_is_sorted(st) SKM_sk_is_sorted(X509_URI, (st))

DECLARE_STACK_OF(EVP_PKEY)
DECLARE_STACK_OF(X509_REQ)
DECLARE_STACK_OF(X509_URI)

#define FORMAT_SIG string
#define PASSWORD_SIG string

typedef struct X509_URI_st X509_URI;

struct X509_URI_st {
	X509 *cert;
	const char *URI;
};


class ProviderSystem : public CertStoreProvider{
public:
	string providerURI; //Параметры инициализации хранилища

	struct CERT_STORE { //Структура для описания хранилища
		int(*verify)(CERT_STORE *cert_store, X509 *x); /* проверка сертификата относительно хранилища */
		int(*verify_cb)(int ok, CERT_STORE *cert_store, X509 *x); /* проверка сертификата относительно хранилища и возвращение номера ошибки верификации */
		int(*get_issuer)(X509 **issuer, CERT_STORE *cert_store, X509 *x);    /* выполняет поиск сертификата в хранилище и возвращает имя издателя */
		int(*check_revocation)(CERT_STORE *cert_store, X509 *x); /* проверяет статус сертификата относительно цепочки (проверка осуществляется в пределах одного хранилища)*/
		int(*get_crl)(CERT_STORE *cert_store, X509_CRL **crl, X509 *x); /* скачивание/получение CRL для данного сертификата и сохранение его в хранилище */
		int(*check_crl)(CERT_STORE *cert_store, X509_CRL *crl); /* проверка подписи CRL */
		int(*cert_crl)(CERT_STORE *cert_store, X509_CRL *crl, X509 *x); /* проверка сертификата относительно CRL */

		STACK_OF(X509_CRL) * (crls);
		STACK_OF(X509_REQ) * (request);
		STACK_OF(X509_URI) * (cert_pkey);
	};

	CERT_STORE cert_store_system;

public:
	ProviderSystem();
	ProviderSystem(string pvdURI);
	~ProviderSystem(){};
public:
	int cert_store_get_issuer(X509 **issuer, CERT_STORE *cert_store, X509 *x);
	int cert_store_verify(CERT_STORE *cert_store, X509 *x);
	int cert_store_get_crl(CERT_STORE *cert_store, X509_CRL **crl, X509 *x);
	int cert_store_get_crl_LOCAL(CERT_STORE *cert_store, X509_CRL **crl, X509 *x);
	int cert_store_check_crl(CERT_STORE *cert_store, X509_CRL *crl);
	int cert_store_cert_crl(CERT_STORE *cert_store, X509_CRL *crl, X509 *x);
	int cert_store_check_revocation(CERT_STORE *cert_store, X509 *x);

	void fillingJsonFromSystemStore(const char *pvdURI);
	void addValueToJSON(const char *pvdURI, BIO *bioFile, const char *full_file_name);
	string readInputJsonFile(const char *path);
	int parseJsonAndFillingCacheStore(string *input);

	X509 * getCertFromURI(string *strFormatPKIObject, string *strUriPKIObject);
	X509_REQ * getCSRFromURI(string *strFormatPKIObject, string *strUriPKIObject);
	X509_CRL * getCRLFromURI(string *strFormatPKIObject, string *strUriPKIObject);

private:
	int cert_store_add_csr(CERT_STORE *cert_store, X509_REQ *x);
	int cert_store_add_crl(CERT_STORE *cert_store, X509_CRL *xcrl);
	int cert_store_add_x509_URI(CERT_STORE *cert_store, X509_URI *cpk);

	int cert_store_key_new(CERT_STORE *cert_store, FORMAT_SIG *type);
	int cert_store_key_new(CERT_STORE *cert_store, FORMAT_SIG *type, EVP_CIPHER *cipher, PASSWORD_SIG *password);

	int createSelfSignedCert(X509 **cert, EVP_PKEY *pkey, X509_NAME *xname, STACK_OF(X509_EXTENSION) *exts, int days);
	int createCertRequest(X509_REQ **xreq, EVP_PKEY *pkey, X509_NAME *xname, STACK_OF(X509_EXTENSION) *exts, int days);
	int generateEVPkey(EVP_PKEY **pkey, int bits);

	int check_cert_time(CERT_STORE *cert_store, X509 *x);
	int check_crl_time(CERT_STORE *cert_store, X509_CRL *crl);

	string generateGuidStr();

	int writeX509CRLToFile(CERT_STORE *cert_store, X509_CRL * xcrl);
	int writeEVPkeyToFile(CERT_STORE *cert_store, EVP_PKEY * pkey);
	int writeX509ToFile(CERT_STORE *cert_store, X509 * x509);
	int writeX509ReqToFile(CERT_STORE *cert_store, X509_REQ * xreq);

	const char* getCRLDistPoint(X509 *cert);
};