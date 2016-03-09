import * as native from "../native";
import * as object from "../object";
import {Certificate} from "../pki/cert";
import {Crl} from "../pki/crl";
import {CertificationRequest} from "../pki/certReg";
import {Key} from "../pki/key";
import {CashJson} from "./cashjson";

export class Filter extends object.BaseObject<native.PKISTORE.Filter> implements native.PKISTORE.IFilter {

    constructor() {
        handle: native.PKISTORE.Filter;
        super();
        this.handle = new native.PKISTORE.Filter();
    }

    set types(type: string){
        this.handle.setType(type);
    }
    
    set providers(provider: string){
        this.handle.setProvider(provider);
    }
    
    set categorys(category: string){
        this.handle.setCategory(category);
    }
    
    set hash(hash: string){
        this.handle.setHash(hash);
    }
    
    set subjectName(subjectName: string){
        this.handle.setSubjectName(subjectName);
    }
    
    set subjectFriendlyName(subjectFriendlyName: string){
        this.handle.setSubjectFriendlyName(subjectFriendlyName);
    }
    
    set issuerName(issuerName: string){
        this.handle.setIssuerName(issuerName);
    }
    
    set issuerFriendlyName(issuerFriendlyName: string){
        this.handle.setIssuerFriendlyName(issuerFriendlyName);
    }
    
    set serial(serial: string){
        this.handle.setSerial(serial);
    }
}

export class PkiItem extends object.BaseObject<native.PKISTORE.PkiItem> implements native.PKISTORE.IPkiItem {

    constructor() {
        handle: native.PKISTORE.PkiItem;
        super();
        this.handle = new native.PKISTORE.PkiItem();
    }
    
    set format(format: string){
        this.handle.setFormat(format);
    }

    set type(type: string){
        this.handle.setType(type);
    }
    
    set provider(provider: string){
        this.handle.setProvider(provider);
    }
    
    set category(category: string){
        this.handle.setCategory(category);
    }
    
    set uri(uri: string){
        this.handle.setURI(uri);
    }
    
    set hash(hash: string){
        this.handle.setHash(hash);
    }
    
    set subjectName(subjectName: string){
        this.handle.setSubjectName(subjectName);
    }
    
    set subjectFriendlyName(subjectFriendlyName: string){
        this.handle.setSubjectFriendlyName(subjectFriendlyName);
    }
    
    set issuerName(issuerName: string){
        this.handle.setIssuerName(issuerName);
    }
    
    set issuerFriendlyName(issuerFriendlyName: string){
        this.handle.setIssuerFriendlyName(issuerFriendlyName);
    }
    
    set serial(serial: string){
        this.handle.setSerial(serial);
    }
    
    set notBefore(before: string){
        this.handle.setNotBefore(before);
    }
    
    set notAfter(after: string){
        this.handle.setNotAfter(after);
    }
    
    set lastUpdate(lastUpdate: string){
        this.handle.setLastUpdate(lastUpdate);
    }
    
    set nextUpdate(nextUpdate: string){
        this.handle.setNextUpdate(nextUpdate);
    }
    
    set key(key: string){
        this.handle.setKey(key);
    }
    
    set keyEnc(enc: boolean){
        this.handle.setKeyEncrypted(enc);
    }

}

export class PkiStore extends object.BaseObject<native.PKISTORE.PkiStore> {
    constructor(handle: native.PKISTORE.PkiStore);
    constructor(folder: string);
    constructor(param) {
        super();
        if (param instanceof native.PKISTORE.PkiStore)
            this.handle = param;
        else
            this.handle = new native.PKISTORE.PkiStore(param);
    }
    
    get cash(): CashJson {
        return CashJson.wrap<native.PKISTORE.CashJson, CashJson>(this.handle.getCash());
    }

    addProvider(provider: native.PKISTORE.Provider) {
        return this.handle.addProvider(provider);
    }

    find(ifilter?: native.PKISTORE.IFilter): native.PKISTORE.IPkiItem[] {
        let filter = new Filter();
        
        if(!ifilter){
            return this.handle.find(filter.handle);
        }
        
        if (ifilter.type) {
            for (let i in ifilter.type) {
                filter.types = ifilter.type[i];
            }
        }
        
        if (ifilter.provider) {
            for (let i in ifilter.provider) {
                filter.providers = ifilter.provider[i];
            }
        }
        
        if (ifilter.category) {
            for (let i in ifilter.category) {
                filter.categorys = ifilter.category[i];
            }
        }
        
        if (ifilter.hash) {
            filter.hash = ifilter.hash;
        }
        
        if (ifilter.subjectName) {
            filter.subjectName = ifilter.subjectName;
        }
        
        if (ifilter.subjectFriendlyName) {
            filter.subjectFriendlyName = ifilter.subjectFriendlyName;
        }
        
        if (ifilter.issuerName) {
            filter.issuerName = ifilter.issuerName;
        }
        
        if (ifilter.issuerFriendlyName) {
            filter.issuerFriendlyName = ifilter.issuerFriendlyName;
        }
        
        if (ifilter.serial) {
            filter.serial = ifilter.serial;
        }

       return this.handle.find(filter.handle);
    }
    
    findKey(ifilter: native.PKISTORE.IFilter): native.PKISTORE.IPkiItem {
        let filter = new Filter();
                
        if (ifilter.type) {
            for (let i in ifilter.type) {
                filter.types = ifilter.type[i];
            }
        }
        
        if (ifilter.provider) {
            for (let i in ifilter.provider) {
                filter.providers = ifilter.provider[i];
            }
        }
        
        if (ifilter.category) {
            for (let i in ifilter.category) {
                filter.categorys = ifilter.category[i];
            }
        }
        
        if (ifilter.hash) {
            filter.hash = ifilter.hash;
        }
        
        if (ifilter.subjectName) {
            filter.subjectName = ifilter.subjectName;
        }
        
        if (ifilter.subjectFriendlyName) {
            filter.subjectFriendlyName = ifilter.subjectFriendlyName;
        }
        
        if (ifilter.issuerName) {
            filter.issuerName = ifilter.issuerName;
        }
        
        if (ifilter.issuerFriendlyName) {
            filter.issuerFriendlyName = ifilter.issuerFriendlyName;
        }
        
        if (ifilter.serial) {
            filter.serial = ifilter.serial;
        }

       return this.handle.findKey(filter.handle);
    }

    getItem(item: native.PKISTORE.IPkiItem): any {
        let pkiItem = new PkiItem();

        pkiItem.format = item.format;
        pkiItem.type = item.type;
        pkiItem.category = item.category;
        pkiItem.provider = item.provider;
        pkiItem.uri = item.uri;
        pkiItem.hash = item.hash;
        if (item.subjectName) {
            pkiItem.subjectName = item.subjectName;
        }
        if (item.subjectFriendlyName) {
            pkiItem.subjectFriendlyName = item.subjectFriendlyName;
        }
        if (item.issuerName) {
            pkiItem.issuerName = item.issuerName;
        }
        if (item.issuerFriendlyName) {
            pkiItem.issuerFriendlyName = item.issuerFriendlyName;
        }
        if (item.serial) {
            pkiItem.serial = item.serial;
        }
        if (item.notBefore) {
            pkiItem.notBefore = item.notBefore;
        }
        if (item.notAfter) {
            pkiItem.notAfter = item.notAfter;
        }
        if (item.lastUpdate) {
            pkiItem.lastUpdate = item.lastUpdate;
        }
        if (item.nextUpdate) {
            pkiItem.nextUpdate = item.nextUpdate;
        }
        if (item.key) {
            pkiItem.key = item.key;
        }
        if (item.encrypted) {
            pkiItem.keyEnc = item.encrypted;
        }
        
        if (item.type === "CERTIFICATE") {
            return Certificate.wrap<native.PKI.Certificate, Certificate>(this.handle.getItem(pkiItem.handle));
        }
        
        if (item.type === "CRL") {
            return Crl.wrap<native.PKI.CRL, Crl>(this.handle.getItem(pkiItem.handle));
        }
        
        if (item.type === "REQUEST") {
            return CertificationRequest.wrap<native.PKI.CertificationRequest, CertificationRequest>(this.handle.getItem(pkiItem.handle));
        }
        
        if (item.type === "KEY") {
            return Key.wrap<native.PKI.Key, Key>(this.handle.getItem(pkiItem.handle));
        }
    }
}