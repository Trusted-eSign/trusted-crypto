import {native} from "../native";
import {BaseObject} from "../object";
import {Oid} from "./oid";

export class Algorithm extends BaseObject {

    constructor();
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

    compare(alg: Algorithm): number {
        var cmp = this.handle.compare(alg.handle);
        if (cmp > 0)
            return 1;
        if (cmp < 0)
            return -1;
        return 0;
    }
    
    equals(alg: Algorithm): boolean {
        return this.compare(alg) === 0;
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