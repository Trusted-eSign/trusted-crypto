#include "../stdafx.h"
#include "provider_system.h"

#if defined(OPENSSL_SYS_WINDOWS) 
	#include <atlconv.h>
#endif

ProviderSystem::ProviderSystem(string pvdURI){
	LOGGER_FN();

	try{
		pvdType = "pvdSystem";
		providerURI = pvdURI;
		if (providerURI.empty()){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "Dont send parameters");
		}
		else{
			LOGGER_OPENSSL(sk_X509_REQ_new_null);
			cert_store_system.request = sk_X509_REQ_new_null();

			LOGGER_OPENSSL(sk_X509_CRL_new_null);
			cert_store_system.crls = sk_X509_CRL_new_null();

			LOGGER_OPENSSL(sk_X509_URI_new_null);
			cert_store_system.cert_pkey = sk_X509_URI_new_null();

			string patchJSON = (providerURI + CROSSPLATFORM_SLASH + "cash_cert_store.json").c_str();
			string strJSON = readInputJsonFile(patchJSON.c_str());
			if ( strJSON.empty() ){
				THROW_EXCEPTION(0, ProviderSystem, NULL, "Json str empty");
			}
			if ( !parseJsonAndFillingCacheStore(&strJSON) ){
				THROW_EXCEPTION(0, ProviderSystem, NULL, "parseJsonAndFillingCacheStore");
			}
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, ProviderSystem, NULL, "Cannot be constructed ProviderSystem(string pvdURI)");
	}
	
}

ProviderSystem::ProviderSystem(){
	pvdType = "pvdSystem";
};

void CertStoreProvider::fillingCache(const char* cacheURI, const char* pvdURI){
#if defined(OPENSSL_SYS_UNIX) 
	DIR *dir;
	class dirent *ent;
	class stat st;
	BIO *bioFile;

	string listCertStore[] = {
		"MY",
		"OTHERS",
		"TRUST",
		"CRL"
	};

	for (int i = 0, c = sizeof(listCertStore) / sizeof(*listCertStore); i < c; i++){
		string dirInCertStore = (string)pvdURI + CROSSPLATFORM_SLASH + listCertStore[i].c_str();
		dir = opendir(dirInCertStore.c_str());
		while ((ent = readdir(dir)) != NULL) {
			const string file_name = ent->d_name;
			const string full_file_name = dirInCertStore + CROSSPLATFORM_SLASH +   file_name;

			if (file_name[0] == '.')
				continue;

			const bool is_directory = (st.st_mode & S_IFDIR) != 0;

			if (is_directory)
				continue;

			LOGGER_OPENSSL(BIO_new);
			bioFile = BIO_new(BIO_s_file());
			LOGGER_OPENSSL(BIO_read_filename);
			if (BIO_read_filename(bioFile, full_file_name.c_str()) > 0){
				LOGGER_TRACE("addValueToJSON");
				ProviderSystem::addValueToJSON(pvdURI, cacheURI,  bioFile, full_file_name.c_str());
			}
			LOGGER_OPENSSL(BIO_free);
			BIO_free(bioFile);
		}
		closedir(dir);
	}
#endif
#if defined(OPENSSL_SYS_WINDOWS) 
	LOGGER_FN();

	try{
		HANDLE dir;
		WIN32_FIND_DATA file_data;
		TCHAR szDir[MAX_PATH];
		BIO *bioFile;

		std::vector<string> listFiles;

		string listCertStore[] = {
			"MY",
			"OTHERS",
			"TRUST",
			"CRL"
		};

		for (int i = 0, c = sizeof(listCertStore) / sizeof(*listCertStore); i < c; i++){
			string dirInCertStore = (string)pvdURI + CROSSPLATFORM_SLASH + listCertStore[i].c_str();
			string tempdirInCertStore = "";
			tempdirInCertStore = dirInCertStore + "\\*";
			LOGGER_TRACE("FindFirstFile");
			if ((dir = FindFirstFile(tempdirInCertStore.c_str(), &file_data)) == INVALID_HANDLE_VALUE){
				continue;
			}

			do {
				string str = file_data.cFileName;
				wstring file_name(str.begin(), str.end());
				string full_file_name = dirInCertStore + CROSSPLATFORM_SLASH + string(file_name.begin(), file_name.end());
				const bool is_directory = (file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

				if (file_name[0] == '.')
					continue;

				if (is_directory)
					continue;

				LOGGER_OPENSSL(BIO_new);
				bioFile = BIO_new(BIO_s_file());
				LOGGER_OPENSSL(BIO_read_filename);
				if (BIO_read_filename(bioFile, full_file_name.c_str()) > 0){
					LOGGER_TRACE("addValueToJSON");
					ProviderSystem::addValueToJSON(pvdURI, cacheURI,  bioFile, full_file_name.c_str());
				}
				LOGGER_OPENSSL(BIO_free);
				BIO_free(bioFile);
				listFiles.push_back(full_file_name);
			} while (FindNextFile(dir, &file_data));

			FindClose(dir);
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, ProviderSystem, NULL, "getListFilesInSystemStore");
	}

#endif
}

void ProviderSystem::addValueToJSON(const char *pvdURI, const char* cacheURI, BIO *bioFile, const char *full_file_name){
	LOGGER_FN();

	try{
		X509_REQ *xReq = NULL;
		X509 *cert = NULL;
		X509_CRL *crl = NULL;
		X509_URI *c_k = NULL;
		BIO *bioKeyFile = NULL;
		string key_file_name, strTrust;
		size_t lastindex;

		Json::Value jsnRoot;
		Json::Value jsnBuf, jsnPKIobj, jsnPkey;
		Json::Reader jsnReader;

		string strJsonPath = (string)cacheURI;

		LOGGER_OPENSSL(BIO_seek);
		BIO_seek(bioFile, 0);
		LOGGER_OPENSSL(PEM_read_bio_X509);
		cert = PEM_read_bio_X509(bioFile, NULL, NULL, NULL);
		if ( cert ){
			jsnBuf["FormatPKIObject"] = "PEM";
		}
		else{
			LOGGER_OPENSSL(BIO_seek);
			BIO_seek(bioFile, 0);
			LOGGER_OPENSSL(d2i_X509_bio);
			cert = d2i_X509_bio(bioFile, NULL);
			if ( cert ){
				jsnBuf["FormatPKIObject"] = "DER";
			}
		}

		if ( cert ){
			LOGGER_TRACE("ifstream");			
			std::ifstream fileJSON(strJsonPath.c_str(), std::ifstream::binary);
			LOGGER_TRACE("Json::Reader::parse");
			bool parsingSuccessful = jsnReader.parse(fileJSON, jsnRoot, false);
			if (!parsingSuccessful){
				THROW_EXCEPTION(0, ProviderSystem, NULL, "Error parse JSON");
			}

			jsnBuf["PKIObjectType"] = "X509";
			jsnBuf["UriPKIObject"] = full_file_name;

			strTrust = (((string)full_file_name).substr(0, ((string)full_file_name).find_last_of(CROSSPLATFORM_SLASH)));
			strTrust = strTrust.substr(strTrust.find_last_of(CROSSPLATFORM_SLASH) + 1, strTrust.length());
			jsnBuf["TRUST"] = strTrust;

			lastindex = ((string)full_file_name).find_last_of(".");
			key_file_name = ((string)full_file_name).substr(0, lastindex) + ".key";
			LOGGER_OPENSSL("BIO_new");
			bioKeyFile = BIO_new(BIO_s_file());
			LOGGER_OPENSSL("BIO_read_filename");
			if ( BIO_read_filename(bioKeyFile, key_file_name.c_str() ) > 0){
				jsnBuf["PKey"] = "T";
				jsnPKIobj["X509"] = jsnBuf;

				jsnPkey["PKIObjectType"] = "PrivKey";
				jsnPkey["TRUST"] = strTrust;
				jsnPkey["UriPKIObject"] = key_file_name;
				jsnRoot["pvdSystem"]["PKIobject"].append(jsnPkey);
			}
			else{
				jsnBuf["PKey"] = "F";
				jsnPKIobj["X509"] = jsnBuf;
			}
			LOGGER_TRACE("Json::Value:append");
			jsnRoot["pvdSystem"]["PKIobject"].append(jsnBuf);
			jsnRoot["pvdSystem"]["StoreURI"] = pvdURI;

			std::ofstream cashStore;
			cashStore.open(strJsonPath.c_str());

			Json::StyledWriter styledWriter;
			cashStore << styledWriter.write(jsnRoot);

			cashStore.close();

			LOGGER_OPENSSL(BIO_free);
			BIO_free(bioKeyFile);
			return;
		}


		LOGGER_OPENSSL(BIO_seek);
		BIO_seek(bioFile, 0);
		LOGGER_OPENSSL(PEM_read_bio_X509_REQ);
		xReq = PEM_read_bio_X509_REQ(bioFile, NULL, NULL, NULL);
		if ( xReq ){
			jsnBuf["FormatPKIObject"] = "PEM";
		}
		else{
			LOGGER_OPENSSL(BIO_seek);
			BIO_seek(bioFile, 0);
			LOGGER_OPENSSL(d2i_X509_REQ_bio);
			xReq = d2i_X509_REQ_bio(bioFile, NULL);
			if ( xReq ){
				jsnBuf["FormatPKIObject"] = "DER";
			}
		}

		if ( xReq ){
			LOGGER_TRACE("ifstream");
			std::ifstream fileJSON(strJsonPath.c_str(), std::ifstream::binary);
			LOGGER_TRACE("Json::Reader::parse");
			bool parsingSuccessful = jsnReader.parse(fileJSON, jsnRoot, false);
			if (!parsingSuccessful){
				THROW_EXCEPTION(0, ProviderSystem, NULL, "Error parse JSON");
			}

			jsnBuf["PKIObjectType"] = "X509_REQ";
			jsnBuf["UriPKIObject"] = full_file_name;

			strTrust = (((string)full_file_name).substr(0, ((string)full_file_name).find_last_of(CROSSPLATFORM_SLASH)));
			strTrust = strTrust.substr(strTrust.find_last_of(CROSSPLATFORM_SLASH) + 1, strTrust.length());
			jsnBuf["TRUST"] = strTrust;

			jsnPKIobj["X509_REQ"] = jsnBuf;

			LOGGER_TRACE("Json::Value:append");
			jsnRoot["pvdSystem"]["PKIobject"].append(jsnBuf);

			std::ofstream cashStore;
			cashStore.open(strJsonPath.c_str());

			Json::StyledWriter styledWriter;
			cashStore << styledWriter.write(jsnRoot);

			cashStore.close();

			LOGGER_OPENSSL(BIO_free);
			BIO_free(bioKeyFile);
			return;
		}

		LOGGER_OPENSSL(BIO_seek);
		BIO_seek(bioFile, 0);
		LOGGER_OPENSSL(PEM_read_bio_X509_CRL);
		crl = PEM_read_bio_X509_CRL(bioFile, NULL, NULL, NULL);
		if ( crl ){
			jsnBuf["FormatPKIObject"] = "PEM";
		}
		else{
			LOGGER_OPENSSL(BIO_seek);
			BIO_seek(bioFile, 0);
			LOGGER_OPENSSL(d2i_X509_CRL_bio);
			crl = d2i_X509_CRL_bio(bioFile, NULL);
			if ( crl ){
				jsnBuf["FormatPKIObject"] = "DER";
			}
		}

		if ( crl ){
			LOGGER_TRACE("ifstream");
			std::ifstream fileJSON(strJsonPath.c_str(), std::ifstream::binary);
			LOGGER_TRACE("Json::Reader::parse");
			bool parsingSuccessful = jsnReader.parse(fileJSON, jsnRoot, false);
			if (!parsingSuccessful){
				THROW_EXCEPTION(0, ProviderSystem, NULL, "Error parse JSON");
			}

			jsnBuf["PKIObjectType"] = "CRL";
			jsnBuf["UriPKIObject"] = full_file_name;

			strTrust = (((string)full_file_name).substr(0, ((string)full_file_name).find_last_of(CROSSPLATFORM_SLASH)));
			strTrust = strTrust.substr(strTrust.find_last_of(CROSSPLATFORM_SLASH) + 1, strTrust.length());
			jsnBuf["TRUST"] = strTrust;

			jsnPKIobj["CRL"] = jsnBuf;

			LOGGER_TRACE("Json::Value:append");
			jsnRoot["pvdSystem"]["PKIobject"].append(jsnBuf);

			std::ofstream cashStore;
			cashStore.open(strJsonPath.c_str());

			Json::StyledWriter styledWriter;
			cashStore << styledWriter.write(jsnRoot);

			cashStore.close();

			LOGGER_OPENSSL(BIO_free);
			BIO_free(bioKeyFile);
			return;
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, ProviderSystem, NULL, "Error work with json");
	}

	try{
		THROW_EXCEPTION(0, ProviderSystem, NULL, "File type not supported");
	}
	catch (Handle<Exception> e){
		return;
	}
}

string ProviderSystem::readInputJsonFile(const char *path){
	LOGGER_FN();

	string strTextJson;

	try{
		FILE *file = fopen(path, "rb");
		if ( !file ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "Cannot open json file");
		}

		fseek(file, 0, SEEK_END);
		long size = ftell(file);
		fseek(file, 0, SEEK_SET);

		char *buffer = new char[size + 1];
		buffer[size] = 0;
		if (fread(buffer, 1, size, file) == (unsigned long)size){
			strTextJson = buffer;
		}

		fclose(file);
		delete[] buffer;
	}
	catch (Handle<Exception> e){
		return string("");
	}

	ASN1_UTF8STRING  *asnStr = ASN1_STRING_new();
	ASN1_STRING_set(asnStr, strTextJson.c_str(), strTextJson.length());

	unsigned char *b;
	std::string res("");
	int b_len = ASN1_STRING_to_UTF8(&b, asnStr);
	if (b_len != -1){
		res += std::string((char *)b, b_len);
		OPENSSL_free(b);
	}
	else{
		res += std::string((char *)asnStr->data, asnStr->length);
	}

	return res;
}

int ProviderSystem::parseJsonAndFillingCacheStore(string *strInputJson){
	LOGGER_FN();

	try{
		Json::Value jsnRoot;
		Json::Reader jsnReader;
		string strPKIObjectType, strFormatPKIObject, strPKey, strUriPKIObject;
		X509_URI *c_k = NULL;
		X509 *xcert = NULL;
		X509_CRL *xcrl = NULL;
		X509_REQ *xreq = NULL;
		string key_file_name;
		size_t lastindex;

		bool parsingSuccessful = jsnReader.parse(*strInputJson, jsnRoot);
		if ( !parsingSuccessful ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "Parsing JSON unsuccessful");
		}

		Json::Value listPkiObj = jsnRoot["StoreSystem"]["PKIobject"];

		for (int i = 0; i < listPkiObj.size(); i++){
			strPKIObjectType = listPkiObj[i]["PKIObjectType"].asString();

			if ( !strcmp(strPKIObjectType.c_str(), "X509") ){
				strFormatPKIObject = listPkiObj[i]["FormatPKIObject"].asString();
				strPKey = listPkiObj[i]["PKey"].asString();
				strUriPKIObject = listPkiObj[i]["UriPKIObject"].asString();

				xcert = getCertFromURI(&strFormatPKIObject, &strUriPKIObject);
				if ( !xcert ){
					THROW_EXCEPTION(0, ProviderSystem, NULL, "Error get cert from URI");
				}

				c_k = new X509_URI;
				c_k->cert = xcert;
				if ( !strcmp((strPKey).c_str(), "T") ){
					lastindex = (strUriPKIObject).find_last_of(".");
					key_file_name = (strUriPKIObject).substr(0, lastindex) + ".key";
					c_k->URI = key_file_name.c_str();
				}
				else{
					c_k->URI = NULL;
				}

				LOGGER_TRACE("cert_store_add_x509_URI");
				if ( !cert_store_add_x509_URI(&cert_store_system, c_k) ){
					THROW_EXCEPTION(0, ProviderSystem, NULL, "cert_store_add_x509_URI");
				}
			}

			if ( !strcmp(strPKIObjectType.c_str(), "X509_REQ") ){
				strFormatPKIObject = listPkiObj[i]["FormatPKIObject"].asString();
				strUriPKIObject = listPkiObj[i]["UriPKIObject"].asString();

				xreq = getCSRFromURI(&strFormatPKIObject, &strUriPKIObject);
				if ( !xreq ){
					THROW_EXCEPTION(0, ProviderSystem, NULL, "Error get csr from URI");
				}

				LOGGER_TRACE("cert_store_add_csr");
				if ( !cert_store_add_csr(&cert_store_system, xreq) ){
					THROW_EXCEPTION(0, ProviderSystem, NULL, "cert_store_add_csr");
				}
			}

			if ( !strcmp(strPKIObjectType.c_str(), "CRL") ){
				strFormatPKIObject = listPkiObj[i]["FormatPKIObject"].asString();
				strUriPKIObject = listPkiObj[i]["UriPKIObject"].asString();

				xcrl = getCRLFromURI(&strFormatPKIObject, &strUriPKIObject);
				if ( !xcrl ){
					THROW_EXCEPTION(0, ProviderSystem, NULL, "Error get crl from URI");
				}

				LOGGER_TRACE("cert_store_add_crl");
				if ( !cert_store_add_crl(&cert_store_system, xcrl) ){
					THROW_EXCEPTION(0, ProviderSystem, NULL, "cert_store_add_crl");
				}
			}
		}
	}
	catch (Handle<Exception> e){
		return 0;
	}
	
	return 1;
}

X509 * ProviderSystem::getCertFromURI(string *strFormatPKIObject, string *strUriPKIObject){
	LOGGER_FN();

	try{
		BIO *bioFile = NULL;
		X509_URI *c_k = NULL;
		X509 *jsnCert = NULL;
		size_t lastindex;

		LOGGER_OPENSSL(BIO_new);
		bioFile = BIO_new(BIO_s_file());
		LOGGER_OPENSSL(BIO_read_filename);
		if ( BIO_read_filename(bioFile, (*strUriPKIObject).c_str()) > 0 ){
			LOGGER_OPENSSL(BIO_seek);
			BIO_seek(bioFile, 0);

			if ( !strcmp((*strFormatPKIObject).c_str(), "PEM") ){
				LOGGER_OPENSSL(PEM_read_bio_X509);
				jsnCert = PEM_read_bio_X509(bioFile, NULL, NULL, NULL);
			}
			if ( !strcmp((*strFormatPKIObject).c_str(), "DER") ){
				LOGGER_OPENSSL(d2i_X509_bio);
				jsnCert = d2i_X509_bio(bioFile, NULL);
			}
		}

		LOGGER_OPENSSL(BIO_free);
		BIO_free(bioFile);

		if (!jsnCert){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "Unable decode cert from PEM/DER to X509");
		}
		else{
			return jsnCert;
		}		
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, ProviderSystem, NULL, "getCertFromURI");
	}	
}

X509_REQ * ProviderSystem::getCSRFromURI(string *strFormatPKIObject, string *strUriPKIObject){
	LOGGER_FN();

	try{
		BIO *bioFile = NULL;
		X509_REQ *jsnCertReq = NULL;

		LOGGER_OPENSSL(BIO_new);
		bioFile = BIO_new(BIO_s_file());
		LOGGER_OPENSSL(BIO_read_filename);
		if ( BIO_read_filename(bioFile, (*strUriPKIObject).c_str()) > 0 ){
			LOGGER_OPENSSL(BIO_seek);
			BIO_seek(bioFile, 0);

			if ( !strcmp((*strFormatPKIObject).c_str(), "PEM") ){
				LOGGER_OPENSSL(PEM_read_bio_X509_REQ);
				jsnCertReq = PEM_read_bio_X509_REQ(bioFile, NULL, NULL, NULL);
			}
			if ( !strcmp((*strFormatPKIObject).c_str(), "DER") ){
				LOGGER_OPENSSL(d2i_X509_REQ_bio);
				jsnCertReq = d2i_X509_REQ_bio(bioFile, NULL);
			}
		}

		LOGGER_OPENSSL(BIO_free);
		BIO_free(bioFile);

		if ( !jsnCertReq ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "Unable decode csr from PEM/DER to X509_REQ");
		}
		else{
			return jsnCertReq;
		}		
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, ProviderSystem, NULL, "getCSRFromURI");
	}	
}

X509_CRL * ProviderSystem::getCRLFromURI(string *strFormatPKIObject, string *strUriPKIObject){
	LOGGER_FN();

	try{
		BIO *bioFile = NULL;
		X509_CRL *jsnCrl = NULL;

		LOGGER_OPENSSL(BIO_new);
		bioFile = BIO_new(BIO_s_file());
		LOGGER_OPENSSL(BIO_read_filename);
		if ( BIO_read_filename(bioFile, (*strUriPKIObject).c_str()) > 0 ){
			LOGGER_OPENSSL(BIO_seek);
			BIO_seek(bioFile, 0);

			if ( !strcmp((*strFormatPKIObject).c_str(), "PEM") ){
				LOGGER_OPENSSL(PEM_read_bio_X509_CRL);
				jsnCrl = PEM_read_bio_X509_CRL(bioFile, NULL, NULL, NULL);
			}
			if ( !strcmp((*strFormatPKIObject).c_str(), "DER") ){
				LOGGER_OPENSSL(d2i_X509_CRL_bio);
				jsnCrl = d2i_X509_CRL_bio(bioFile, NULL);
			}
		}
		LOGGER_OPENSSL(BIO_free);
		BIO_free(bioFile);

		if ( !jsnCrl ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "Unable decode CRL from PEM/DER to X509_CRL");
		}
		else{
			return jsnCrl;
		}		
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, ProviderSystem, NULL, "getCRLFromURI");
	}
}

string ProviderSystem::generateGuidStr(){
	LOGGER_FN();

	try{
		#if defined(OPENSSL_SYS_WINDOWS)
			USES_CONVERSION;

			string strGuid = "";

			OLECHAR* bstrGuid;
			GUID guid = {};

			if ( S_OK != CoCreateGuid(&guid) ){
				THROW_EXCEPTION(0, ProviderSystem, NULL, "CoCreateGuid");
			}
			if ( S_OK != StringFromCLSID(guid, &bstrGuid) ){
				THROW_EXCEPTION(0, ProviderSystem, NULL, "StringFromCLSID");
			}
			string strGuidTemp(OLE2A(bstrGuid));
			strGuid = strGuidTemp;
			CoTaskMemFree(bstrGuid);

			return strGuid;
		#endif

		#if defined(OPENSSL_SYS_UNIX) 
			uuid_t uuid;
			uuid_generate_random(uuid);
			char s[37];
			uuid_unparse(uuid, s);

			return s;
		#endif		
	}
	catch (Handle<Exception> e){
		return "";
	}
}

int ProviderSystem::cert_store_key_new(CERT_STORE *cert_store, FORMAT_SIG *type){
	LOGGER_FN();

	int ok = 1;
	
	RSA *rsa = NULL;
	BIGNUM *bn = NULL;
	EVP_PKEY *evpkey = NULL;
	BIO *bp_private = NULL;

	try{
		ENGINE *en = NULL;
		int num = 1024;
		string dirInCertStore = (string)(providerURI.c_str()) + CROSSPLATFORM_SLASH + "MY";
		string full_file_name = dirInCertStore + CROSSPLATFORM_SLASH + generateGuidStr() + ".pem";

		LOGGER_OPENSSL(RSA_new_method);
		rsa = RSA_new_method(en);
		if ( !rsa ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "RSA_new_method");
		}

		LOGGER_OPENSSL(BN_new);
		bn = BN_new();
		if ( !bn ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "BN_new");
		}

		LOGGER_OPENSSL(EVP_PKEY_new);
		evpkey = EVP_PKEY_new();
		if ( !evpkey ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "EVP_PKEY_new");
		}

		LOGGER_OPENSSL(BN_set_word);
		if ( !BN_set_word(bn, RSA_F4) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "BN_set_word 'Unable set RSA_F4 to BIGNUM'");
		}

		LOGGER_OPENSSL(RSA_generate_key_ex);
		if (!RSA_generate_key_ex(rsa, num, bn, NULL)){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "RSA_generate_key_ex 'Unable  generates a key pair'");
		}

		LOGGER_OPENSSL(EVP_PKEY_set1_RSA);
		EVP_PKEY_set1_RSA(evpkey, rsa);

		LOGGER_OPENSSL(BIO_new_file);
		bp_private = BIO_new_file(full_file_name.c_str(), "w+");
		if (!bp_private){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "BIO_new_file 'Unable creates a new file BIO'");
		}

		if (strcmp((*type).c_str(), "pkcs5") == 0){
			LOGGER_OPENSSL(PEM_write_bio_RSAPrivateKey);
			if ( !PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL) ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "PEM_write_bio_RSAPrivateKey 'Unable writes RSAPrivateKey to BIO'");
			}
		}

		if (strcmp((*type).c_str(), "pkcs8") == 0){
			LOGGER_OPENSSL(PEM_write_bio_PKCS8PrivateKey);
			if ( !PEM_write_bio_PKCS8PrivateKey(bp_private, evpkey, NULL, NULL, 0, NULL, NULL) ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "PEM_write_bio_PKCS8PrivateKey 'Unable writes PKCS8PrivateKey to BIO'");
			}
		}
	}
	catch (Handle<Exception> e){
		ok = 0;
	}

	if (bp_private){
		LOGGER_OPENSSL(BIO_free_all);
		BIO_free_all(bp_private);
	}

	if (rsa){
		LOGGER_OPENSSL(RSA_free);
		RSA_free(rsa);
	}

	if (bn){
		LOGGER_OPENSSL(BN_free)
			BN_free(bn);
	}

	if (evpkey){
		LOGGER_OPENSSL(EVP_PKEY_free);
		EVP_PKEY_free(evpkey);
	}

	return ok;
}

int ProviderSystem::cert_store_key_new(CERT_STORE *cert_store, FORMAT_SIG *type, EVP_CIPHER *cipher, PASSWORD_SIG *password){
	LOGGER_FN();

	int ok = 1;

	RSA *rsa = NULL;
	BIGNUM *bn = NULL;
	EVP_PKEY *evpkey = NULL;
	BIO *bp_private = NULL;

	try{
		ENGINE *en = NULL;
		int num = 2048;
		string dirInCertStore = (string)(providerURI.c_str()) + CROSSPLATFORM_SLASH + "MY";
		string full_file_name = dirInCertStore + CROSSPLATFORM_SLASH + generateGuidStr() + ".pem";

		LOGGER_OPENSSL(RSA_new_method);
		rsa = RSA_new_method(en);
		if ( !rsa ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "RSA_new_method");
		}

		LOGGER_OPENSSL(BN_new);
		bn = BN_new();
		if ( !bn ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "BN_new");
		}

		LOGGER_OPENSSL(EVP_PKEY_new);
		evpkey = EVP_PKEY_new();
		if ( !evpkey ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "EVP_PKEY_new");
		}

		LOGGER_OPENSSL(BN_set_word);
		if ( !BN_set_word(bn, RSA_F4) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "BN_set_word 'Unable set RSA_F4 to BIGNUM'");
		}

		LOGGER_OPENSSL(RSA_generate_key_ex);
		if ( !RSA_generate_key_ex(rsa, num, bn, NULL) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "RSA_generate_key_ex 'Unable  generates a key pair'");
		}

		LOGGER_OPENSSL(EVP_PKEY_set1_RSA);
		EVP_PKEY_set1_RSA(evpkey, rsa);

		LOGGER_OPENSSL(BIO_new_file);
		bp_private = BIO_new_file(full_file_name.c_str(), "w+");
		if ( !bp_private ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "BIO_new_file 'Unable creates a new file BIO'");
		}

		if (strcmp((*type).c_str(), "pkcs5") == 0){
			if ((*cipher).nid > 0 && (*password).length() > 0){
				LOGGER_OPENSSL(PEM_write_bio_RSAPrivateKey);
				if ( !PEM_write_bio_RSAPrivateKey(bp_private, rsa, cipher, (unsigned char *)((*password).c_str()), (*password).length(), NULL, NULL) ){
					THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "PEM_write_bio_RSAPrivateKey 'Unable writes RSAPrivateKey to BIO'");
				}
			}
			else{
				THROW_EXCEPTION(0, ProviderSystem, NULL, "Cipher or password value NULL");
			}
		}

		if (strcmp((*type).c_str(), "pkcs8") == 0){
			if ((*cipher).nid > 0 && (*password).length() > 0){
				LOGGER_OPENSSL(PEM_write_bio_PKCS8PrivateKey);
				if ( !PEM_write_bio_PKCS8PrivateKey(bp_private, evpkey, cipher, (char *)((*password).c_str()), (*password).length(), NULL, NULL) ){
					THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "PEM_write_bio_PKCS8PrivateKey 'Unable writes PKCS8PrivateKey to BIO'");
				}
			}
			else{
				THROW_EXCEPTION(0, ProviderSystem, NULL, "Cipher or password value NULL");
			}
		}
	}
	catch (Handle<Exception> e){
		ok = 0;
	}

	if (bp_private){
		LOGGER_OPENSSL(BIO_free_all);
		BIO_free_all(bp_private);
	}

	if (rsa){
		LOGGER_OPENSSL(RSA_free);
		RSA_free(rsa);
	}

	if (bn){
		LOGGER_OPENSSL(BN_free)
		BN_free(bn);
	}

	if (evpkey){
		LOGGER_OPENSSL(EVP_PKEY_free);
		EVP_PKEY_free(evpkey);
	}

	return ok;
}

int ProviderSystem::generateEVPkey(EVP_PKEY **pkey, int bits)
{
	LOGGER_FN();

	try{
		RSA *rsa = NULL;

		if ( bits < 1024 ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "Key sizes with num < 1024 insecure");
		}

		LOGGER_OPENSSL(EVP_PKEY_new);
		*pkey = EVP_PKEY_new();
		if ( !pkey ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "EVP_PKEY_new 'Unable allocates an empty EVP_PKEY structure'");
		}

		LOGGER_OPENSSL(RSA_generate_key);
		rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);

		LOGGER_OPENSSL(EVP_PKEY_assign_RSA);
		if ( !EVP_PKEY_assign_RSA(*pkey, rsa) ){
			if ( *pkey ){
				LOGGER_OPENSSL(EVP_PKEY_free);
				EVP_PKEY_free(*pkey);
			}

			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "EVP_PKEY_new 'Unable set the referenced RSA key to EVP_PKEY key'");
		}
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return 1;
}

int ProviderSystem::writeEVPkeyToFile(CERT_STORE *cert_store, EVP_PKEY * pkey)
{
	LOGGER_FN();

	try{
		BIO *outFile;
		string dirInCertStore = (string)(providerURI.c_str()) + CROSSPLATFORM_SLASH + "MY";
		string full_file_name = dirInCertStore + CROSSPLATFORM_SLASH + generateGuidStr() + ".pem";

		LOGGER_OPENSSL(BIO_new_file);
		outFile = BIO_new_file(full_file_name.c_str(), "wb");
		if (!outFile){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "BIO_new_file 'Unable creates a new file BIO'");
		}

		LOGGER_OPENSSL(PEM_write_bio_PrivateKey);
		if ( !PEM_write_bio_PrivateKey(outFile, pkey, NULL, NULL, 0, NULL, NULL) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "Unable writes EVP_PKEY to BIO'");
		}

		LOGGER_OPENSSL(BIO_free_all);
		BIO_free_all(outFile);
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return 1;
}

int ProviderSystem::createSelfSignedCert(X509 **xcert, EVP_PKEY * pkey, X509_NAME * xname, STACK_OF(X509_EXTENSION) *exts, int days)
{
	LOGGER_FN();

	try{
		X509_EXTENSION *ex = NULL;

		LOGGER_OPENSSL(X509_new);
		*xcert = X509_new();

		LOGGER_OPENSSL(BN_new);
		BIGNUM *serial = BN_new();

		if ( !xcert || !serial ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "X509 or BIGNUM value NULL");
		}

		LOGGER_OPENSSL(X509_set_version);
		if ( !X509_set_version(*xcert, 2) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_set_version 'Unable sets the numerical value of the version field'");
		}

		LOGGER_OPENSSL(BN_pseudo_rand);
		if ( !BN_pseudo_rand(serial, 64, 0, 0) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "BN_pseudo_rand 'Unable pseudo-random numbers generated'");
		}

		LOGGER_OPENSSL(BN_to_ASN1_INTEGER);
		if ( !BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(*xcert)) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "BN_to_ASN1_INTEGER 'Unable converts BIGNUM bn to an ASN1_INTEGER'");
		}

		LOGGER_OPENSSL(X509_gmtime_adj);
		X509_gmtime_adj(X509_get_notBefore(*xcert), 0);
		X509_gmtime_adj(X509_get_notAfter(*xcert), days);

		LOGGER_OPENSSL(X509_set_pubkey);
		if ( !X509_set_pubkey(*xcert, pkey) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_set_pubkey 'Unable set the public key for certificate'");
		}

		LOGGER_OPENSSL(X509_set_subject_name);
		if ( !X509_set_subject_name(*xcert, xname) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_set_subject_name 'Unable set subject name for certificate'");
		}

		LOGGER_OPENSSL(X509_set_issuer_name);
		if ( !X509_set_issuer_name(*xcert, xname) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_set_issuer_name 'Unable set issuer name for certificate'");
		}

		LOGGER_OPENSSL(sk_X509_EXTENSION_num);
		for (int i = 0, c = sk_X509_EXTENSION_num(exts); i < c; i++){
			LOGGER_OPENSSL(sk_X509_EXTENSION_value);
			ex = sk_X509_EXTENSION_value(exts, i);

			LOGGER_OPENSSL(X509_add_ext);
			X509_add_ext(*xcert, ex, -1);
		}

		LOGGER_OPENSSL(X509_sign);
		if ( !X509_sign(*xcert, pkey, EVP_sha1()) ){
			if (*xcert){
				LOGGER_OPENSSL(X509_free);
				X509_free(*xcert);
			}

			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_sign 'Unable signs certificate'");
		}
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return 1;
}

int ProviderSystem::writeX509ToFile(CERT_STORE *cert_store, X509 * x509)
{
	LOGGER_FN();

	try{
		BIO *outFile;
		string dirInCertStore = (string)(providerURI.c_str()) + CROSSPLATFORM_SLASH + "MY";
		string full_file_name = dirInCertStore + CROSSPLATFORM_SLASH + generateGuidStr() + ".pem";

		LOGGER_OPENSSL(BIO_new_file);
		outFile = BIO_new_file(full_file_name.c_str(), "wb");
		if ( !outFile ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "BIO_new_file 'Unable creates a new file BIO'");
		}

		LOGGER_OPENSSL(PEM_write_bio_X509);
		if ( !PEM_write_bio_X509(outFile, x509) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "Unable writes X509 to BIO'");
		}

		LOGGER_OPENSSL(BIO_free_all);
		BIO_free_all(outFile);
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return 1;
}

int ProviderSystem::createCertRequest(X509_REQ **xreq, EVP_PKEY *pkey, X509_NAME *xname, STACK_OF(X509_EXTENSION) *exts, int days){
	LOGGER_FN();
	
	try{
		int ret = 0;

		if ( !pkey || !xname ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "EVP_PKEY or X509_NAME value NULL");
		}

		LOGGER_OPENSSL(X509_REQ_new);
		if ( (*xreq = X509_REQ_new()) == NULL ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_REQ_new 'Unable creates new certificate request'");
		}

		LOGGER_OPENSSL(X509_REQ_set_pubkey);
		ret = X509_REQ_set_pubkey(*xreq, pkey);
		if ( ret <= 0 ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_REQ_set_pubkey 'Unable set the public key for certificate to pkey'");
		}

		LOGGER_OPENSSL(X509_REQ_get_subject_name);
		X509_REQ_get_subject_name(*xreq) = xname;

		LOGGER_OPENSSL(sk_X509_EXTENSION_num);
		if (sk_X509_EXTENSION_num(exts) > 0){
			LOGGER_OPENSSL(X509_REQ_add_extensions);
			X509_REQ_add_extensions(*xreq, exts);
		}

		LOGGER_OPENSSL(X509_REQ_sign);
		if ( !X509_REQ_sign(*xreq, pkey, EVP_sha1()) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_REQ_sign 'Unable sign certificate requests'");
		}
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return 1;
}

int ProviderSystem::writeX509ReqToFile(CERT_STORE *cert_store, X509_REQ * xreq){
	LOGGER_FN();

	try{
		BIO *outFile;
		string dirInCertStore = (string)(providerURI.c_str()) + CROSSPLATFORM_SLASH + "MY";
		string full_file_name = dirInCertStore + CROSSPLATFORM_SLASH + generateGuidStr() + ".pem";

		LOGGER_OPENSSL(BIO_new_file);
		outFile = BIO_new_file(full_file_name.c_str(), "wb");
		if ( !outFile ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "BIO_new_file 'Unable creates a new file BIO'");
		}

		LOGGER_OPENSSL(PEM_write_bio_X509_REQ);
		if ( !PEM_write_bio_X509_REQ(outFile, xreq) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "Unable writes  X509_REQ to BIO'");
		}

		LOGGER_OPENSSL(BIO_free_all);
		BIO_free_all(outFile);
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return 1;
}

int ProviderSystem::cert_store_add_csr(CERT_STORE *cert_store, X509_REQ *x){
	LOGGER_FN();

	try{
		LOGGER_OPENSSL(sk_X509_REQ_push);
		if ( !sk_X509_REQ_push(cert_store->request, x ) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "sk_X509_REQ_push 'Unable push request to STACK_OF(X509_REQ)'");
		}
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return 1;
}

int ProviderSystem::cert_store_add_crl(CERT_STORE *cert_store, X509_CRL *xcrl){
	LOGGER_FN();

	try{
		LOGGER_OPENSSL(sk_X509_CRL_push);
		if ( !sk_X509_CRL_push(cert_store->crls, xcrl) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "sk_X509_CRL_push 'Unable push CRL to STACK_OF(X509_CRL)'");
		}
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return 1;
}

int ProviderSystem::cert_store_add_x509_URI(CERT_STORE *cert_store, X509_URI *cpk){
	LOGGER_FN();

	try{
		LOGGER_OPENSSL(sk_X509_URI_push);
		if ( !sk_X509_URI_push(cert_store->cert_pkey, cpk) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "sk_X509_URI_push 'Unable push X509_URI to STACK_OF(X509_URI)'");
		}
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return 1;
}

int ProviderSystem::cert_store_get_issuer(X509 **issuer, CERT_STORE *cert_store, X509 *x){
	LOGGER_FN();

	int ok = 0;

	try{
		int ret;
		X509 *xtempCert = NULL;
		X509_NAME *subName = NULL, *issName = NULL;
		STACK_OF(X509_URI) *skCertsPKeys = cert_store->cert_pkey;

		LOGGER_OPENSSL(sk_X509_URI_num);
		for (int i = 0, c = sk_X509_URI_num(skCertsPKeys); i < c; i++){
			LOGGER_OPENSSL(sk_X509_URI_value);
			xtempCert = (sk_X509_URI_value(skCertsPKeys, i))->cert;
			if ( !xtempCert ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "sk_X509_URI_value 'Unable get element of STACK_OF(X509_URI)'");
			}

			LOGGER_OPENSSL(X509_get_subject_name);
			subName = X509_get_subject_name(xtempCert);
			if ( !subName ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_get_subject_name 'Unable get cert subject name'");
			}

			LOGGER_OPENSSL(X509_CRL_get_issuer);
			issName = X509_get_issuer_name(x);
			if ( !issName ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_get_issuer_name 'Unable get cert issuer name'");
			}

			LOGGER_OPENSSL(X509_NAME_cmp);
			if ( X509_NAME_cmp(subName, issName) == 0 ){
				LOGGER_OPENSSL(X509_check_issued);
				ret = X509_check_issued(xtempCert, x);
				if (ret == X509_V_OK){
					*issuer = xtempCert;
					ok = 1;
					break;
				}
			}
		}
		
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return ok;
}

int ProviderSystem::cert_store_verify(CERT_STORE *cert_store, X509 *x){
	LOGGER_FN();

	int ok = 0;
	EVP_PKEY *pkey = NULL;

	try{
		LOGGER_OPENSSL(X509_get_pubkey);
		if ( (pkey = X509_get_pubkey(x)) == NULL ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_get_pubkey 'Unable to decode issuer  public key'");
		}
		else{
			LOGGER_OPENSSL(X509_verify);
			if (X509_verify(x, pkey) <= 0){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_verify 'Cert signature failure'");
			}			
		}

		LOGGER_OPENSSL(EVP_PKEY_free);
		EVP_PKEY_free(pkey);
		pkey = NULL;

		LOGGER_TRACE("check_cert_time");
		ok = check_cert_time(cert_store, x);
		if ( !ok ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "check_cert_time");
		}
	}
	catch (Handle<Exception> e){
		return 0;
	}

	EVP_PKEY_free(pkey);
	return ok;
}

int ProviderSystem::check_cert_time(CERT_STORE *cert_store, X509 *x){
	LOGGER_FN();

	try{
		time_t ptime = NULL;
		int i;

		LOGGER_TRACE("time")
		ptime = time(0);
		if ( !ptime ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "Unable get current machine time");
		}

		LOGGER_OPENSSL(X509_cmp_time);
		i = X509_cmp_time(X509_get_notBefore(x), &ptime);

		if ( i == 0 ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_cmp_time 'Error in cert not before field'");
		}

		if ( i > 0 ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_cmp_time 'Cert not yet valid'");
		}

		LOGGER_OPENSSL(X509_cmp_time);
		i = X509_cmp_time(X509_get_notAfter(x), &ptime);

		if ( i == 0 ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_cmp_time 'Error in cert not after field'");
		}

		if ( i < 0 ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_cmp_time 'Cert has expired'");
		}
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return 1;
}

int ProviderSystem::check_crl_time(CERT_STORE *cert_store, X509_CRL *crl){
	LOGGER_FN();

	try{
		time_t ptime;
		int i;

		ptime = time(0);
		if ( !ptime ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "Unable get current machine time");
		}

		LOGGER_OPENSSL(X509_cmp_time);
		i = X509_cmp_time(X509_CRL_get_lastUpdate(crl), &ptime);
		if (i == 0){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_cmp_time 'Error in CRL last update field'");
		}

		if (i > 0){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_cmp_time 'CRL not yet valid'");
		}

		LOGGER_OPENSSL(X509_CRL_get_nextUpdate);
		if ( X509_CRL_get_nextUpdate(crl) ){
			LOGGER_OPENSSL(X509_cmp_time);
			i = X509_cmp_time(X509_CRL_get_nextUpdate(crl), &ptime);

			if (i == 0){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_cmp_time 'Error in CRL next update field'");
			}

			if (i < 0){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_cmp_time 'CRL has expired'");
			}
		}
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return 1;	
}

int ProviderSystem::cert_store_get_crl(CERT_STORE *cert_store, X509_CRL **crl, X509 *x){
	LOGGER_FN();

	try{
		const char *crlURL = NULL;

		crlURL = getCRLDistPoint(x);
		if ( !crlURL ){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "getCRLDistPoint 'Unable get CRL dist point'");
		}

		////////////////////////
		//UNSUPPORTED FUNCTION//
		////////////////////////

		THROW_EXCEPTION(0, ProviderSystem, NULL, "Need js function for get CRL from URL");

	}
	catch (Handle<Exception> e){
		return 0;
	}

	return 1;
}

int ProviderSystem::cert_store_get_crl_LOCAL(CERT_STORE *cert_store, X509_CRL **crl, X509 *x){
	LOGGER_FN();

	int ok = 0;

	try{
		int ret;
		STACK_OF(X509_CRL) *skCRL = cert_store->crls;
		X509_CRL *xtempCRL = NULL;
		X509_NAME *certIss = NULL, *crlIss = NULL;

		LOGGER_OPENSSL(sk_X509_CRL_num);
		for (int i = 0, c = sk_X509_CRL_num(skCRL); i < c; i++){
			LOGGER_OPENSSL(sk_X509_CRL_value);
			xtempCRL = sk_X509_CRL_value(skCRL, i);
			if ( !xtempCRL ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "sk_X509_CRL_value 'Unable get element of STACK_OF(X509_CRL)'");
			}

			LOGGER_OPENSSL(X509_get_issuer_name);
			certIss = X509_get_issuer_name(x);
			if ( !certIss ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_get_issuer_name 'Unable get cert issuer name'");
			}

			LOGGER_OPENSSL(X509_CRL_get_issuer);
			crlIss = X509_CRL_get_issuer(xtempCRL);
			if ( !crlIss ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_CRL_get_issuer 'Unable get CRL issuer name'");
			}

			LOGGER_OPENSSL(X509_NAME_cmp);
			if ( X509_NAME_cmp(certIss, crlIss) == 0 ){
				LOGGER_OPENSSL(X509_check_akid);
				ret = X509_check_akid(x, xtempCRL->akid);
				if (ret == X509_V_OK){
					*crl = xtempCRL;
					ok = 1;
					break;
				}
			}
		}
	}
	catch (Handle<Exception> e){
		return 0;
	}

	return ok;
}

int ProviderSystem::writeX509CRLToFile(CERT_STORE *cert_store, X509_CRL *xcrl){
	LOGGER_FN();

	try{
		BIO *outFile;
		string dirInCertStore = (string)(providerURI.c_str()) + CROSSPLATFORM_SLASH + "CRL";
		string full_file_name = dirInCertStore + CROSSPLATFORM_SLASH + generateGuidStr() + ".crl";

		LOGGER_OPENSSL(BIO_new_file);
		outFile = BIO_new_file(full_file_name.c_str(), "wb");
		if ( !outFile ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "BIO_new_file 'Unable creates a new file BIO'");
		}

		LOGGER_OPENSSL(i2d_X509_CRL_bio);
		if ( !i2d_X509_CRL_bio(outFile, xcrl) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "Unable writes the encoding of the structure X509_CRL to BIO'");
		}

		LOGGER_OPENSSL(BIO_free_all);
		BIO_free_all(outFile);
	}
	catch (Handle<Exception> e){
		return 0;
	}
	
	return 1;
}

const char* ProviderSystem::getCRLDistPoint(X509 *cert){
	LOGGER_FN();

	const char *crlsUrl = NULL;

	try{
		bool bFound = false;
		STACK_OF(DIST_POINT)* pStack = NULL;
		LOGGER_OPENSSL(X509_get_ext_d2i);
		pStack = (STACK_OF(DIST_POINT)*) X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
		if (pStack){
			LOGGER_OPENSSL(sk_DIST_POINT_num);
			for (int j = 0; j < sk_DIST_POINT_num(pStack); j++){
				LOGGER_OPENSSL(sk_DIST_POINT_value);
				DIST_POINT *pRes = (DIST_POINT *)sk_DIST_POINT_value(pStack, j);
				if (pRes != NULL){
					STACK_OF(GENERAL_NAME) *pNames = pRes->distpoint->name.fullname;
					if (pNames){
						LOGGER_OPENSSL(sk_GENERAL_NAME_num);
						for (int i = 0; i < sk_GENERAL_NAME_num(pNames); i++){
							LOGGER_OPENSSL(sk_GENERAL_NAME_value);
							GENERAL_NAME *pName = sk_GENERAL_NAME_value(pNames, i);
							if (pName != NULL && pName->type == GEN_URI){
								LOGGER_OPENSSL(ASN1_STRING_data);
								crlsUrl = (const char *)ASN1_STRING_data(pName->d.uniformResourceIdentifier);
								bFound = true;
								break;
							}
						}
						LOGGER_OPENSSL(sk_GENERAL_NAME_free);
						sk_GENERAL_NAME_free(pNames);
						if (bFound) break;
					}
				}
			}
			LOGGER_OPENSSL(sk_DIST_POINT_free);
			sk_DIST_POINT_free(pStack);
		}
	}
	catch (Handle<Exception> e){
		return NULL;
	}

	return crlsUrl;
}

int ProviderSystem::cert_store_check_crl(CERT_STORE *cert_store, X509_CRL *crl){
	LOGGER_FN();

	try{
		int ret;
		X509 *xtempCert = NULL, *issuer = NULL;
		X509_NAME *subName = NULL, *issName = NULL;
		STACK_OF(X509_URI) *skCertsPKeys = cert_store->cert_pkey;
		EVP_PKEY *ikey = NULL;

		LOGGER_OPENSSL(sk_X509_URI_num);
		for (int i = 0, c = sk_X509_URI_num(skCertsPKeys); i < c; i++){
			LOGGER_OPENSSL(sk_X509_URI_value);
			xtempCert = (sk_X509_URI_value(skCertsPKeys, i))->cert;
			if ( !xtempCert ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "sk_X509_URI_value 'Unable get element of STACK_OF(X509_URI)'");
			}

			LOGGER_OPENSSL(X509_get_subject_name);
			subName = X509_get_subject_name(xtempCert);
			if ( !subName ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_get_subject_name 'Unable get cert subject name'");
			}

			LOGGER_OPENSSL(X509_CRL_get_issuer);
			issName = X509_CRL_get_issuer(crl);
			if ( !issName ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_CRL_get_issuer 'Unable get CRL issuer name'");
			}

			LOGGER_OPENSSL(X509_NAME_cmp);
			if (X509_NAME_cmp(subName, issName) == 0){
				LOGGER_OPENSSL(X509_check_akid);
				ret = X509_check_akid(xtempCert, crl->akid);
				if (ret == X509_V_OK){
					issuer = xtempCert;
					break;
				}
			}
		}

		if ( issuer ){
			if ( !check_crl_time(cert_store, crl) ){
				THROW_EXCEPTION(0, ProviderSystem, NULL, "check_crl_time");
			}

			LOGGER_OPENSSL(X509_get_pubkey);
			ikey = X509_get_pubkey(issuer);
			if ( !ikey ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_get_pubkey 'Unable get pubkey for issuer cert'");
			}

			LOGGER_OPENSSL(X509_CRL_verify);
			if ( X509_CRL_verify(crl, ikey) <= 0 ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_CRL_verify 'Bad CRL'");
			}
		}

	}
	catch (Handle<Exception> e){
		return 0;
	}
	
	return 1;
}

int ProviderSystem::cert_store_cert_crl(CERT_STORE *cert_store, X509_CRL *crl, X509 *x){
	LOGGER_FN();

	try{
		X509_REVOKED *rev;

		LOGGER_OPENSSL(X509_CRL_get0_by_cert);
		if ( !X509_CRL_get0_by_cert(crl, &rev, x) ){
			return 1;
		}
		else{
			if (rev->reason == CRL_REASON_REMOVE_FROM_CRL){
				return 2;
			}
			else{
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_CRL_get0_by_cert 'Cert revoked'");
			}
		}
	}
	catch (Handle<Exception> e){
		return 0;		
	}	
}

int ProviderSystem::cert_store_check_revocation(CERT_STORE *cert_store, X509 *x){
	LOGGER_FN();

	int ok = -1;

	try{
		X509_CRL *crl = NULL;
		X509 *iss = NULL, *xtemp = NULL;
		X509_NAME *issName = NULL, *subName = NULL;
		int ret = 0;

		LOGGER_OPENSSL(sk_X509_new_null);
		STACK_OF(X509) *skCertTemp = sk_X509_new_null();

		xtemp = x;

		LOGGER_OPENSSL(sk_X509_push);
		if ( !sk_X509_push(skCertTemp, xtemp) ){
			THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "sk_X509_push 'Unable push X509 cert to STACK_OF(X509)'");
		}

		do{
			ret = cert_store_get_issuer(&iss, cert_store, xtemp);
			if (ret){
				LOGGER_OPENSSL(X509_cmp);
				if (X509_cmp(xtemp, iss) == 0){
					ret = 0;
				}
				else{
					LOGGER_OPENSSL(sk_X509_push);
					if (!sk_X509_push(skCertTemp, iss)){
						THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "sk_X509_push 'Unable push X509 cert to STACK_OF(X509)'");
					}
					xtemp = iss;
				}
			}
		} while (ret);

		LOGGER_OPENSSL(sk_X509_num);
		for ( int i = 0, c = sk_X509_num(skCertTemp); i < c; i++ ){
			LOGGER_OPENSSL(sk_X509_value);
			xtemp = sk_X509_value(skCertTemp, i);
			if ( !xtemp ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "sk_X509_value 'Unable get element of STACK_OF(X509)'");
			}

			LOGGER_OPENSSL(X509_get_subject_name);
			subName = X509_get_subject_name(xtemp);
			if (!subName){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_get_subject_name 'Unable get cert subject name'");
			}

			LOGGER_OPENSSL(X509_CRL_get_issuer);
			issName = X509_get_issuer_name(xtemp);
			if ( !issName ){
				THROW_OPENSSL_EXCEPTION(0, ProviderSystem, NULL, "X509_get_issuer_name 'Unable get cert issuer name'");
			}

			LOGGER_OPENSSL(X509_NAME_cmp);
			if ( X509_NAME_cmp(issName, subName) == 0 ){
				ok = 1;
				THROW_EXCEPTION(0, ProviderSystem, NULL, "X509_NAME_cmp 'Self-signed cert'");
			}

			LOGGER_TRACE("cert_store_get_crl_LOCAL");
			if ( !cert_store_get_crl_LOCAL(cert_store, &crl, xtemp) ){
				LOGGER_TRACE("cert_store_get_crl");
				if ( !cert_store_get_crl(cert_store, &crl, xtemp) ){
					ok = 2;
					THROW_EXCEPTION(0, ProviderSystem, NULL, "cert_store_get_crl 'Unable to get CRL'");
				}
			}

			LOGGER_TRACE("cert_store_check_crl");
			if ( !cert_store_check_crl(cert_store, crl) ){
				LOGGER_TRACE("cert_store_get_crl");
				if ( !cert_store_get_crl(cert_store, &crl, xtemp) ){
					ok = 3; 
					THROW_EXCEPTION(0, ProviderSystem, NULL, "'Unable get new CRL, if bad CRL'");
				}

				LOGGER_TRACE("cert_store_check_crl");
				if ( !cert_store_check_crl(cert_store, crl) ){
					ok =  4;
					THROW_EXCEPTION(0, ProviderSystem, NULL, "cert_store_check_crl 'Check CRL'");
				}
			}

			LOGGER_TRACE("cert_store_cert_crl");
			if ( !cert_store_cert_crl(cert_store, crl, xtemp) ){
				ok = 5;
				THROW_EXCEPTION(0, ProviderSystem, NULL, "cert_store_cert_crl 'Cert has been revoked'");
			}
		}

		LOGGER_OPENSSL("X509_NAME_cmp");
		if ( X509_NAME_cmp(X509_get_issuer_name(xtemp), X509_get_subject_name(xtemp)) != 0 ){
			ok = 6;
			THROW_EXCEPTION(0, ProviderSystem, NULL, "Unable get cert chain");
		}
	}
	catch (Handle<Exception> e){
		return ok;
	}

	return 0;
}