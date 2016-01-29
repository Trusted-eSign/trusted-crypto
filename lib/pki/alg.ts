import * as native from "../native";
import * as object from "../object";
import {Oid} from "./oid";

export class Algorithm extends object.BaseObject<native.PKI.Algorithm>{

    constructor();
    constructor(handle: native.PKI.Algorithm);
    constructor(name: string);
    constructor(param?: any) {
        super();

        if (param instanceof native.PKI.Algorithm){
            this.handle = param;
        }
        else if (param)
            this.handle = new native.PKI.Algorithm(param);
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