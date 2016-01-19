#include "../stdafx.h"
#include "provider_tcl.h"

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h> 
#include <openssl/x509.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>



ProviderTCL::ProviderTCL(){
	providerType = "pvdTCL";
};

ProviderTCL::ProviderTCL(string pvdURI){
	providerType = "pvdTCL";
	providerURI = pvdURI;
	if (providerURI.empty()){
		THROW_EXCEPTION(0, ProviderTCL, NULL, "Dont not send parameters");
	}else{
		readTCLfile(providerURI, &cert_store_tcl, &tcl_infos);
	}
}


string ProviderTCL::getValueFromXML(string base_line, string token_start, string token_end){
	string value = "";
	size_t found_st = base_line.find(token_start);
	if (found_st != std::string::npos){
		size_t found_en = base_line.find(token_end);
		if (found_en != std::string::npos){
			value = base_line.substr(found_st + strlen(token_start.c_str()), found_en - (found_st + strlen(token_start.c_str())));
		}
	}
	return value;
}

string ProviderTCL::getSignatureFromXML(string base_line, string token_start, string token_end){
	string value = "";
	size_t found_st = base_line.find(token_start);
	if (found_st != std::string::npos){
		size_t found_en = base_line.find(token_end);
		if (found_en != std::string::npos){
			value = base_line.substr(found_st, found_en + strlen(token_end.c_str()));
		}
	}
	return value;
}


string ProviderTCL::delimeterCertString(char* cert_string){
	if (cert_string == NULL) return "";
	string result = "-----BEGIN CERTIFICATE-----\n";
	size_t str_length = strlen(cert_string);
	for (int i = 0; i < str_length; i += 68){
		string trimmed(cert_string + i, cert_string + (i + 68));
		result.append(trimmed.c_str());
		result.append("\n");
	}
	result.append("-----END CERTIFICATE-----");
	return result;
}

void ProviderTCL::readTCLfile(string file_path, CERT_STORE* cert_store, TCL_CURRENT_INFO* tcl_infos){
	//TCL_CURRENT_INFO tcl_infos;
	tcl_infos->x509_certificates.clear();
	tcl_infos->version_tcl = 0;
	tcl_infos->data_tcl = "";
	tcl_infos->signatureStatus = 0;
	tcl_infos->signature_xmldsig = "";
	//Процедура чтения TCL файла
	//-----------------------------------------------------------------------------------------------------------------
	char _version_token_start[15] = { 60, -48, -110, -48, -75, -47, -128, -47, -127, -48, -72, -47, -113, 62, '\0' }; //<Версия>
	char _version_token_end[16] = { 60, 47, -48, -110, -48, -75, -47, -128, -47, -127, -48, -72, -47, -113, 62, '\0' }; //</Версия>
	string version_token_start(_version_token_start);
	string version_token_end(_version_token_end);
	char _data_token_start[11] = { 60, -48, -108, -48, -80, -47, -126, -48, -80, 62, '\0' }; //<Дата>
	char _data_token_end[12] = { 60, 47, -48, -108, -48, -80, -47, -126, -48, -80, 62, '\0' }; //</Дата>
	string data_token_start(_data_token_start);
	string data_token_end(_data_token_end);
	char _x509_token_start[15] = { 60, -48, -108, -48, -80, -48, -67, -48, -67, -47, -117, -48, -75, 62, '\0' }; //<Данные>
	char _x509_token_end[16] = { 60, 47, -48, -108, -48, -80, -48, -67, -48, -67, -47, -117, -48, -75, 62, '\0' }; //</Данные>
	string x509_token_start(_x509_token_start);
	string x509_token_end(_x509_token_end);
	string signature_token_start("<Signature");
	string signature_token_end("</Signature>");

	int range_start = 10;
	ifstream if_fFile(file_path, ios_base::in);
	if (if_fFile.is_open()){
		try{
			while (!if_fFile.eof()){
				string line;
				getline(if_fFile, line);
				if (range_start > 0){
					string value1 = getValueFromXML(line, version_token_start, version_token_end);
					if (!value1.empty()) tcl_infos->version_tcl = atoi(value1.c_str());
					string value2 = getValueFromXML(line, data_token_start, data_token_end);
					if (!value2.empty()) tcl_infos->data_tcl = value2;
					range_start--;
				}
				else{
					string value3 = getValueFromXML(line, x509_token_start, x509_token_end);
					if (!value3.empty()){
						string cert_blob = delimeterCertString((char*)value3.c_str());
						tcl_infos->x509_certificates.push_back(cert_blob);
						for (int i = 0; i < 6; i++) getline(if_fFile, line);
					}
					string value4 = getSignatureFromXML(line, signature_token_start, signature_token_end);
					if (!value4.empty()){
						tcl_infos->signature_xmldsig = value4;
					}
				}
			}
		}
		catch (...){
			THROW_EXCEPTION(0, ProviderTCL, NULL, "Error parsing TCL file");
		}
	}
	else{
		THROW_EXCEPTION(0, ProviderTCL, NULL, "Can not open TCL file for read");
	}
	if_fFile.close();
	if (tcl_infos->x509_certificates.empty()) THROW_EXCEPTION(0, ProviderTCL, NULL, "TCL file is not processed");
	//-----------------------------------------------------------------------------------------------------------------
}

void ProviderTCL::putCertificateToStack(STACK_OF(X509)* X509STACK, char* cert_data){
	if (X509STACK == NULL) {
		THROW_EXCEPTION(0, ProviderTCL, NULL, "Can not initial STACK_OF(X509)");
	}
	//string cert_blob = delimeterCertString((char*)cert_data);
	BIO *cbio = BIO_new(BIO_s_mem());
	BIO_puts(cbio, (char*)cert_data);
	X509 *cert = PEM_read_bio_X509(cbio, NULL, NULL, NULL);
	if (cert == NULL) {
		THROW_EXCEPTION(0, ProviderTCL, NULL, "Can not load certificate");
	}
	sk_X509_push(X509STACK, cert);
	BIO_free(cbio);
	X509_free(cert);
}