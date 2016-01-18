import {native} from "../native";
import {BaseObject} from "../object";
import {Oid} from "./oid";

export class Algorithm extends BaseObject {

    constructor();
    constructor(name: string);
    constructor(name?: string) {
        super();

        if (name)
            this.handle = new native.PKI.Algorithm(name);
        else
            this.handle = new native.PKI.Algorithm();
    }

    get name(): string {
        return this.handle.getName();
    }

    get typeId(): Oid {
        return new Oid(this.handle.getTypeId());
    }

    duplicate(): Algorithm {
        let walg = this.handle.duplicate();
        let alg = new Algorithm();
        alg.handle = walg;
        return alg;
    }
    
    isDigest(): boolean{
        return this.handle.isDigest();
    }

}