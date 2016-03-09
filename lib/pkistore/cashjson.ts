import * as native from "../native";
import * as object from "../object";
import {PkiItem} from "./pkistore";

export class CashJson extends object.BaseObject<native.PKISTORE.CashJson> {
    constructor(fileName: string) {
        handle: native.PKISTORE.CashJson;
        super();
        this.handle = new native.PKISTORE.CashJson(fileName);
    }

    export(): native.PKISTORE.IPkiItem[] {
        return this.handle.export();
    }

    import(items: native.PKISTORE.IPkiItem[]): void {
        for(let i in items){
            let pkiItem = new PkiItem();

            pkiItem.format = items[i].format;
            pkiItem.type = items[i].type;
            pkiItem.category = items[i].category;
            pkiItem.provider = items[i].provider;
            pkiItem.uri = items[i].uri;
            pkiItem.hash = items[i].hash.toLocaleLowerCase();
            if (items[i].subjectName) {
                pkiItem.subjectName = items[i].subjectName;
             }
            if (items[i].subjectFriendlyName) {
                pkiItem.subjectFriendlyName = items[i].subjectFriendlyName;
            }
            if (items[i].issuerName) {
                pkiItem.issuerName = items[i].issuerName;
            }
            if (items[i].issuerFriendlyName) {
                pkiItem.issuerFriendlyName = items[i].issuerFriendlyName;
            }
            if (items[i].serial) {
                pkiItem.serial = items[i].serial;
            }
            if (items[i].notBefore) {
                pkiItem.notBefore = items[i].notBefore;
            }
            if (items[i].notAfter) {
                pkiItem.notAfter = items[i].notAfter;
            }
            if (items[i].lastUpdate) {
                pkiItem.lastUpdate = items[i].lastUpdate;
            }
            if (items[i].nextUpdate) {
                pkiItem.nextUpdate = items[i].nextUpdate;
            }
            if (items[i].key) {
                pkiItem.key = items[i].key;
            }
            if (items[i].encrypted) {
                pkiItem.keyEnc = items[i].encrypted;
            }
            
            this.handle.import(pkiItem.handle);
        }
    }

}