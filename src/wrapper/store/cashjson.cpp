#include "../stdafx.h"

#include "cashjson.h"

CashJson::CashJson(Handle<std::string> fileName){
	LOGGER_FN();

	try{
		jsonFileName = fileName;

		FILE *file = fopen(fileName->c_str(), "a");

		if (!file){
			THROW_EXCEPTION(0, CashJson, NULL, "Cannot open json file");
		}

		fclose(file);

		std::ifstream cashStore(jsonFileName->c_str(), std::ifstream::binary);
		if (cashStore.peek() == std::ifstream::traits_type::eof()){
			std::ofstream cashStore;
			cashStore.open(jsonFileName->c_str());
			cashStore << "{}";
			cashStore.close();
		}
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CashJson, e, "Cannot create new json file");
	}
}

Handle<PkiItemCollection> CashJson::exportJson(){
	LOGGER_FN();

	try{
		Handle<PkiItemCollection> items = new PkiItemCollection();
		Handle<PkiItem> itemTemp = new PkiItem();
		
		Json::Value jsnRoot;
		Json::Reader jsnReader;

		std::ifstream jsonFile(jsonFileName->c_str(), std::ifstream::binary);

		bool parsingSuccessful = jsnReader.parse(jsonFile, jsnRoot, false);
		if (!parsingSuccessful){
			THROW_EXCEPTION(0, CashJson, NULL, "Parsing JSON unsuccessful");
		}

		std::string listProviders[] = {
			"SYSTEM",
#if defined(OPENSSL_SYS_WINDOWS)
			"MICROSOFT",
#endif
#if defined(CPROCSP)
			"CRYPTOPRO"
#endif
		};

		for (int i = 0, c = sizeof(listProviders) / sizeof(*listProviders); i < c; i++){
			Json::Value listPkiObj = jsnRoot[listProviders[i]]["PKIobject"];

			for (int i = 0; i < listPkiObj.size(); i++){
				itemTemp->format = new std::string(listPkiObj[i]["Format"].asString());
				itemTemp->type = new std::string(listPkiObj[i]["Type"].asString());
				itemTemp->uri = new std::string(listPkiObj[i]["URI"].asString());
				itemTemp->provider = new std::string(listPkiObj[i]["Provider"].asString());
				itemTemp->category = new std::string(listPkiObj[i]["Category"].asString());
				itemTemp->hash = new std::string(listPkiObj[i]["Hash"].asString());

				if (strcmp(itemTemp->type->c_str(), "CERTIFICATE") == 0){
					itemTemp->certSubjectName = new std::string(listPkiObj[i]["SubjectName"].asString());
					itemTemp->certSubjectFriendlyName = new std::string(listPkiObj[i]["SubjectFriendlyName"].asString());
					itemTemp->certIssuerName = new std::string(listPkiObj[i]["IssuerName"].asString());
					itemTemp->certIssuerFriendlyName = new std::string(listPkiObj[i]["IssuerFriendlyName"].asString());
					itemTemp->certSerial = new std::string(listPkiObj[i]["Serial"].asString());
					itemTemp->certNotBefore = new std::string(listPkiObj[i]["NotBefore"].asString());
					itemTemp->certNotAfter = new std::string(listPkiObj[i]["NotAfter"].asString());
					itemTemp->certKey = new std::string(listPkiObj[i]["Key"].asString());
					itemTemp->certOrganizationName = new std::string(listPkiObj[i]["OrganizationName"].asString());
					itemTemp->certSignatureAlgorithm = new std::string(listPkiObj[i]["SignatureAlgorithm"].asString());
				}
				else if (strcmp(itemTemp->type->c_str(), "CRL") == 0){
					itemTemp->crlIssuerName = new std::string(listPkiObj[i]["IssuerName"].asString());
					itemTemp->crlIssuerFriendlyName = new std::string(listPkiObj[i]["IssuerFriendlyName"].asString());
					itemTemp->crlLastUpdate = new std::string(listPkiObj[i]["LastUpdate"].asString());
					itemTemp->crlNextUpdate = new std::string(listPkiObj[i]["NextUpdate"].asString());
				}
				else if (strcmp(itemTemp->type->c_str(), "REQUEST") == 0){
					itemTemp->csrSubjectName = new std::string(listPkiObj[i]["SubjectName"].asString());
					itemTemp->csrSubjectFriendlyName = new std::string(listPkiObj[i]["SubjectFriendlyName"].asString());
					itemTemp->csrKey = new std::string(listPkiObj[i]["Key"].asString());
				}
				else if (strcmp(itemTemp->type->c_str(), "KEY") == 0){
					itemTemp->keyEncrypted = listPkiObj[i]["Encrypted"].asBool();
				}
				else{
					THROW_EXCEPTION(0, CashJson, NULL, "Unknown pki object type");
				}

				items->push(itemTemp);
			}
		}

		return items;
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CashJson, e, "Error export json");
	}	
}

void CashJson::importJson(Handle<PkiItem> item){
	LOGGER_FN();

	try{		
		if (item.isEmpty()){
			THROW_EXCEPTION(0, CashJson, NULL, "Item empty");
		}

		Json::Value jsnRoot;
		Json::Value jsnBuf, jsnPKIobj;
		Json::Reader jsnReader;

		LOGGER_TRACE("ifstream");
		std::ifstream fileJSON(jsonFileName->c_str(), std::ifstream::binary);
		LOGGER_TRACE("Json::Reader::parse");
		bool parsingSuccessful = jsnReader.parse(fileJSON, jsnRoot, false);
		if (!parsingSuccessful){
			THROW_EXCEPTION(0, ProviderSystem, NULL, "Error parse JSON");
		}
		jsnBuf["Format"] = item->format->c_str();
		jsnBuf["Type"] = item->type->c_str();
		jsnBuf["URI"] = item->uri->c_str();
		jsnBuf["Provider"] = item->provider->c_str();
		jsnBuf["Category"] = item->category->c_str();
		jsnBuf["Hash"] = item->hash->c_str();

		if (strcmp(item->type->c_str(), "CERTIFICATE") == 0){
			jsnBuf["SubjectName"] = item->certSubjectName->c_str();
			jsnBuf["SubjectFriendlyName"] = item->certSubjectFriendlyName->c_str();
			jsnBuf["IssuerName"] = item->certIssuerName->c_str();
			jsnBuf["IssuerFriendlyName"] = item->certIssuerFriendlyName->c_str();
			jsnBuf["Serial"] = item->certSerial->c_str();
			jsnBuf["NotBefore"] = item->certNotBefore->c_str();
			jsnBuf["NotAfter"] = item->certNotAfter->c_str();
			jsnBuf["Key"] = item->certKey->c_str();
			jsnBuf["OrganizationName"] = item->certOrganizationName->c_str();
			jsnBuf["SignatureAlgorithm"] = item->certSignatureAlgorithm->c_str();
		}
		else if (strcmp(item->type->c_str(), "CRL") == 0){
			jsnBuf["IssuerName"] = item->crlIssuerName->c_str();
			jsnBuf["IssuerFriendlyName"] = item->crlIssuerFriendlyName->c_str();
			jsnBuf["LastUpdate"] = item->crlLastUpdate->c_str();
			jsnBuf["NextUpdate"] = item->crlNextUpdate->c_str();
		}
		else if (strcmp(item->type->c_str(), "REQUEST") == 0){
			jsnBuf["SubjectName"] = item->csrSubjectName->c_str();
			jsnBuf["SubjectFriendlyName"] = item->csrSubjectFriendlyName->c_str();
			jsnBuf["Key"] = item->csrKey->c_str();
		}
		else if (strcmp(item->type->c_str(), "KEY") == 0){
			jsnBuf["Encrypted"] = item->keyEncrypted;
		}
		else{
			THROW_EXCEPTION(0, CashJson, NULL, "Unknown pki object type");
		}

		jsnRoot[item->provider->c_str()]["PKIobject"].append(jsnBuf);

		std::ofstream cashStore;
		cashStore.open(jsonFileName->c_str());

		Json::StyledWriter styledWriter;
		cashStore << styledWriter.write(jsnRoot);

		cashStore.close();
	}
	catch (Handle<Exception> e){
		THROW_EXCEPTION(0, CashJson, e, "Error import json");
	}
}