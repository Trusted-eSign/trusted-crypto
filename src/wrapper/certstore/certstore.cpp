#include "../stdafx.h"
#include "certstore.h"
#include "provider_system.h"
#include "provider_tcl.h"
#include "provider_mscrypto.h"
#include "provider_cryptopro.h"
#include "provider_pkcs11.h"
#include "provider_trustednet.h"

CertStore::CertStore(){};

CertStore::CertStore(const char* pvdType){
	LOGGER_FN();

	addCertStore(pvdType);
}

CertStore::CertStore(const char* pvdType, const char* pvdURI){
	LOGGER_FN();

	addCertStore(pvdType, pvdURI);
}

void CertStore::addCertStore(const char* pvdType){
	LOGGER_FN();

	if (strcmp(pvdType, "pvdTCL")==0){
		ProviderTCL* tcl = new ProviderTCL();
		cache_providers.push_back(tcl);
	}else if (strcmp(pvdType, "pvdSystem")==0){
		ProviderSystem* psys = new ProviderSystem();
		cache_providers.push_back(psys);
	}else if (strcmp(pvdType, "pvdMSCrypto")==0){
		ProviderMSCrypto* psys = new ProviderMSCrypto();
		cache_providers.push_back(psys);
	}else if (strcmp(pvdType, "pvdCryptoPro")==0){
		ProviderCryptoPRO* psys = new ProviderCryptoPRO();
		cache_providers.push_back(psys);
	}
}

void CertStore::addCertStore(const char* pvdType, const char* pvdURI){
	LOGGER_FN();

	if (strcmp(pvdType, "pvdTCL")==0){
		ProviderTCL* tcl = new ProviderTCL(pvdURI);
		cache_providers.push_back(tcl);
	}
	else if (strcmp(pvdType, "pvdSystem")==0){
		ProviderSystem* psys = new ProviderSystem(pvdURI);
		cache_providers.push_back(psys);
	}
	else if (strcmp(pvdType, "pvdMSCrypto")==0){
		ProviderMSCrypto* psys = new ProviderMSCrypto();
		cache_providers.push_back(psys);
	}
	else if (strcmp(pvdType, "pvdCryptoPro")==0){
		ProviderCryptoPRO* psys = new ProviderCryptoPRO();
	}
}

void CertStore::removeCertStore(const char* pvdType){
	LOGGER_FN();

	try{
		for (int i = 0, c = cache_providers.size(); i < c; i++){
			if (strcmp(pvdType, (cache_providers[i]->getPvdType()).c_str()) == 0){
				cache_providers.erase(cache_providers.begin() + i);
			}
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CertStore, e, "Cannot remove provider");
	}	
}


void CertStore::createCache(const char *cacheURI){
	LOGGER_FN();

	try{
		std::ofstream cashStore;
		string strJsonPath = (string)(cacheURI);
		cashStore.open(strJsonPath.c_str());

		cashStore.close();
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CertStore, e, "Cannot create new json file");
	}
}

Handle<std::string> CertStore::getCertStore(){
	LOGGER_FN();

	try{
		string strBuf;
		strBuf = "[";
		for (int i = 0, c = cache_providers.size(); i < c; i++){
			strBuf = strBuf + " " + cache_providers[i]->getPvdType();
			if ((i+1) != c){
				strBuf = strBuf + ",";
			}
			else{
				strBuf = strBuf + " ";
			}
		}
		strBuf = strBuf + "]";

		Handle<std::string> strCertStore = new std::string(strBuf.c_str(), strBuf.length());

		return strCertStore;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CertStore, e, "Error get list store");
	}	
}

bool CertStore::getPrvTypePresent(const char *pvdType){
	LOGGER_FN();

	for (int i = 0, c = cache_providers.size(); i < c; i++){
		if ( strcmp(pvdType, (cache_providers[i]->getPvdType()).c_str()) == 0 ){
			return true;
		}
	}
	return false;
}

string CertStoreProvider::getPvdType(){	
	LOGGER_FN();
	
	return pvdType;
}

void CertStore::addCacheSection(const char *cacheURI, const char *pvdType){
	LOGGER_FN();

	try{
		if ( ((string)pvdType).empty() || ((string)cacheURI).empty() ){
			THROW_EXCEPTION(0, CertStore, NULL, "Dont send parameters");
		}

		Json::Value jsnRoot;
		Json::Reader jsnReader;

		string strTextJson;

		FILE *file = fopen(cacheURI, "rb");
		if (!file){
			THROW_EXCEPTION(0, CertStore, NULL, "Cannot open json file");
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

		if (!strTextJson.empty()){
			bool parsingSuccessful = jsnReader.parse(strTextJson, jsnRoot);
			if (!parsingSuccessful){
				THROW_EXCEPTION(0, CertStore, NULL, "Parsing JSON unsuccessful");
			}
		}	

		Json::Value arrayPKIobject(Json::arrayValue);
		Json::Value minParameters;

		minParameters["StoreType"] = pvdType;		
		minParameters["PKIobject"] = arrayPKIobject;
		jsnRoot[pvdType] = minParameters;
		minParameters.clear();

		std::ofstream cashStore;
		string strJsonPath = (string)(cacheURI);
		cashStore.open(strJsonPath.c_str());

		Json::StyledWriter styledWriter;
		cashStore << styledWriter.write(jsnRoot);

		cashStore.close();
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CertStore, e, "Cannot add cache section");
	}
}