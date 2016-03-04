#include "../stdafx.h"

#include "storehelper.h"

Handle<PkiItemCollection> Provider::getProviderItemCollection(){
	LOGGER_FN();

	return this->providerItemCollection;
}

ProviderCollection::ProviderCollection(){
	LOGGER_FN();

	_items = std::vector<Provider>();
}

ProviderCollection::~ProviderCollection(){
	LOGGER_FN();
}

Handle<Provider> ProviderCollection::items(int index){
	LOGGER_FN();

	return new Provider(_items.at(index));
}

int ProviderCollection::length(){
	LOGGER_FN();

	return _items.size();
}

void ProviderCollection::push(Handle<Provider> v){
	LOGGER_FN();

	_items.push_back((*v.operator->()));
}

void ProviderCollection::push(Provider &v){
	LOGGER_FN();

	_items.push_back(v);
}

PkiItem::PkiItem(){
	LOGGER_FN();

	type = new std::string("");
	provider = new std::string("");
	category = new std::string("");
	hash = new std::string("");
	uri = new std::string("");
	format = new std::string("");

	certSubjectName = new std::string("");
	certSubjectFriendlyName = new std::string("");
	certIssuerName = new std::string("");
	certIssuerFriendlyName = new std::string("");
	certNotBefore = new std::string("");
	certNotAfter = new std::string("");
	certSerial = new std::string("");
	certKey = new std::string("");

	csrSubjectName = new std::string("");
	csrSubjectFriendlyName = new std::string("");
	csrKey = new std::string("");

	crlIssuerName = new std::string("");
	crlIssuerFriendlyName = new std::string("");
	crlLastUpdate = new std::string("");
	crlNextUpdate = new std::string("");

	keyEncrypted = false;
}

void PkiItem::setFormat(Handle<std::string> format){
	LOGGER_FN();

	this->format = format;
}

void PkiItem::setType(Handle<std::string> type){
	LOGGER_FN();

	this->type = type;
}

void PkiItem::setProvider(Handle<std::string> provider){
	LOGGER_FN();

	this->provider = provider;
}

void PkiItem::setCategory(Handle<std::string> category){
	LOGGER_FN();

	this->category = category;
}

void PkiItem::setURI(Handle<std::string> uri){
	LOGGER_FN();

	this->uri = uri;
}

void PkiItem::setHash(Handle<std::string> hash){
	LOGGER_FN();

	this->hash = hash;
}

void PkiItem::setSubjectName(Handle<std::string> subjectName){
	LOGGER_FN();

	this->certSubjectName = subjectName;
	this->csrSubjectName = subjectName;
}

void PkiItem::setSubjectFriendlyName(Handle<std::string> subjectFriendlyName){
	LOGGER_FN();

	this->certSubjectFriendlyName = subjectFriendlyName;
	this->csrSubjectFriendlyName = subjectFriendlyName;
}

void PkiItem::setIssuerName(Handle<std::string> issuerName){
	LOGGER_FN();

	this->certIssuerName = issuerName;
	this->crlIssuerName = issuerName;
}

void PkiItem::setIssuerFriendlyName(Handle<std::string> issuerFriendlyName){
	LOGGER_FN();

	this->certIssuerFriendlyName = issuerFriendlyName;
	this->crlIssuerFriendlyName = issuerFriendlyName;
}

void PkiItem::setSerial(Handle<std::string> serial){
	LOGGER_FN();

	this->certSerial = serial;
}

void PkiItem::setNotBefore(Handle<std::string> notBefore){
	LOGGER_FN();

	this->certNotBefore = notBefore;
}

void PkiItem::setNotAfter(Handle<std::string> notAfter){
	LOGGER_FN();

	this->certNotAfter = notAfter;
}

void PkiItem::setLastUpdate(Handle<std::string> lastUpdate){
	LOGGER_FN();

	this->crlLastUpdate = lastUpdate;
}

void PkiItem::setNextUpdate(Handle<std::string> nextUpdate){
	LOGGER_FN();

	this->crlNextUpdate = nextUpdate;
}

void PkiItem::setKey(Handle<std::string> keyid){
	LOGGER_FN();

	this->certKey = keyid;
	this->csrKey = keyid;
}

void PkiItem::setKeyEncypted(bool enc){
	LOGGER_FN();

	this->keyEncrypted = enc;
}

PkiItemCollection::PkiItemCollection(){
	LOGGER_FN();

	_items = std::vector<PkiItem>();
}

PkiItemCollection::~PkiItemCollection(){
	LOGGER_FN();
}

Handle<PkiItem> PkiItemCollection::items(int index){
	LOGGER_FN();

	return new PkiItem(_items.at(index));
}

int PkiItemCollection::length(){
	LOGGER_FN();

	return _items.size();
}

void PkiItemCollection::push(Handle<PkiItem> v){
	LOGGER_FN();

	_items.push_back((*v.operator->()));
}

void PkiItemCollection::push(PkiItem &v){
	LOGGER_FN();

	_items.push_back(v);
}

Filter::Filter(){
	LOGGER_FN();

	types = std::vector<Handle<std::string>>();
	providers = std::vector<Handle<std::string>>();
	categorys = std::vector<Handle<std::string>>();
	isValid = true;
}

void Filter::setType(Handle<std::string> type){
	LOGGER_FN();

	this->types.push_back(type);
}

void Filter::setProvider(Handle<std::string> provider){
	LOGGER_FN();

	this->providers.push_back(provider);
}

void Filter::setCategory(Handle<std::string> category){
	LOGGER_FN();

	this->categorys.push_back(category);
}

void Filter::setHash(Handle<std::string> hash){
	LOGGER_FN();

	this->hash = hash;
}

void Filter::setSubjectName(Handle<std::string> subjectName){
	LOGGER_FN();

	this->subjectName = subjectName;
}

void Filter::setSubjectFriendlyName(Handle<std::string> subjectFriendlyName){
	LOGGER_FN();

	this->subjectFriendlyName = subjectFriendlyName;
}

void Filter::setIssuerName(Handle<std::string> issuerName){
	LOGGER_FN();

	this->issuerName = issuerName;
}

void Filter::setIssuerFriendlyName(Handle<std::string> issuerFriendlyName){
	LOGGER_FN();

	this->issuerFriendlyName = issuerFriendlyName;
}

void Filter::setSerial(Handle<std::string> serial){
	LOGGER_FN();

	this->serial = serial;
}

void Filter::setIsValid(bool isValid){
	LOGGER_FN();

	this->isValid = isValid;
}