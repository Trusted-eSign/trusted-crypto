import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import * as Collection from "../core/collection";
import {Crl} from "./crl";

export class CrlCollection extends object.BaseObject<native.PKI.CrlCollection> implements Collection.ICollectionWrite {
    constructor(handle: native.PKI.CrlCollection);
    constructor();
    constructor(param?) {
        super();
        if (param instanceof native.PKI.CrlCollection) {
            this.handle = param;
        }
        else{
            this.handle = new native.PKI.CrlCollection();
        }
    }

    items(index: number): Crl {
        return  Crl.wrap<native.PKI.CRL, Crl>(this.handle.items(index));
    }

    get length(): number {
        return this.handle.length();
    }

    push(crl: Crl): void {
        this.handle.push(crl.handle);
    }

    pop(): void {
        this.handle.pop();
    }

    removeAt(index: number): void {
        this.handle.removeAt(index);
    }
}
