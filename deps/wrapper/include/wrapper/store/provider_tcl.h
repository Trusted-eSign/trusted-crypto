#pragma once
#include <openssl/x509.h>
#include "../common/common.h"
#include <string.h>
#include "certstore.h"
using namespace std;


class ProviderTCL : public CertStoreProvider{
	public:
		string providerType; //ѕараметры инициализации хранилища
		string providerURI; //ѕараметры инициализации хранилища
		
		struct CERT_STORE { //—труктура дл€ описани€ хранилища
			int(*verify)(CERT_STORE *cert_store, X509 *x); /* проверка сертификата относительно хранилища */
			int(*verify_cb)(int ok, CERT_STORE *cert_store, X509 *x); /* проверка сертификата относительно хранилища и возвращение номера ошибки верификации */
			int(*get_issuer)(X509 **issuer, CERT_STORE *cert_store, X509 *x);    /* выполн€ет поиск сертификата в хранилище и возвращает им€ издател€ */
			int(*check_revocation)(CERT_STORE *cert_store, X509 *x); /* провер€ет статус сертификата относительно цепочки (проверка осуществл€етс€ в пределах одного хранилища)*/
			int(*get_crl)(CERT_STORE *cert_store, X509_CRL **crl, X509 *x); /* скачивание/получение CRL дл€ данного сертификата и сохранение его в хранилище */
			int(*check_crl)(CERT_STORE *cert_store, X509_CRL *crl); /* проверка подписи CRL */
			int(*cert_crl)(CERT_STORE *cert_store, X509_CRL *crl, X509 *x); /* проверка сертификата относительно CRL */

			STACK_OF(X509) X509STACK;
			STACK_OF(X509_CRL) CRLSTACK;
		};

		typedef struct TCL_INFO{
			int version_tcl;
			string data_tcl;
			vector<string> x509_certificates;
			string signature_xmldsig;
			bool signatureStatus;
		} TCL_CURRENT_INFO;

		CERT_STORE cert_store_tcl;
		TCL_CURRENT_INFO tcl_infos;
	public:
		ProviderTCL();
		ProviderTCL(string pvdURI);
		~ProviderTCL(){};
	private:
		string getValueFromXML(string base_line, string token_start, string token_end);
		string getSignatureFromXML(string base_line, string token_start, string token_end);
		string delimeterCertString(char* cert_string);
		void readTCLfile(const char file_path, CERT_STORE* cert_store, TCL_CURRENT_INFO* tcl_infos);
		void putCertificateToStack(STACK_OF(X509)* X509STACK, char* cert_data);
};

