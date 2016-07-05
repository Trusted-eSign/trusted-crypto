import * as native from "../native";
import * as object from "../object";
import * as Collection from "../core/collection";
import {Crl} from "./crl";

export class CrlCollection extends object.BaseObject<native.PKI.CrlCollection> implements Collection.ICollectionWrite {
    constructor(handle: native.PKI.CrlCollection);
    constructor();
    constructor(param?: any) {
        super();
        if (param instanceof native.PKI.CrlCollection) {
            this.handle = param;
        } else {
            this.handle = new native.PKI.CrlCollection();
        }
    }

    public items(index: number): Crl {
        return  Crl.wrap<native.PKI.CRL, Crl>(this.handle.items(index));
    }

    get length(): number {
        return this.handle.length();
    }

    public push(crl: Crl): void {
        this.handle.push(crl.handle);
    }

    public pop(): void {
        this.handle.pop();
    }

    public removeAt(index: number): void {
        this.handle.removeAt(index);
    }
}
