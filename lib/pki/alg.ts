import * as native from "../native";
import * as object from "../object";
import {Oid} from "./oid";

/**
 * Представление X509_ALGOR
 */
export class Algorithm extends object.BaseObject<native.PKI.Algorithm> {
    constructor();
    constructor(handle: native.PKI.Algorithm);
    constructor(name: string);
    constructor(param?: any) {
        super();

        if (param instanceof native.PKI.Algorithm) {
            this.handle = param;
        } else if (param) {
            this.handle = new native.PKI.Algorithm(param);
        } else {
            this.handle = new native.PKI.Algorithm();
        }
    }

    /**
     * возвращает название алгоритма
     */
    get name(): string {
        return this.handle.getName();
    }

    /**
     * возвращает идентификатор алгоритма
     */
    get typeId(): Oid {
        return new Oid(this.handle.getTypeId());
    }

    /**
     * возвращает копию алгоритма
     */
    public duplicate(): Algorithm {
        let walg: any = this.handle.duplicate();
        let alg: any = new Algorithm();
        alg.handle = walg;
        return alg;
    }

    /**
     * возвращает true если алгоритм предназначен для вычисления хэш
     */
    public  isDigest(): boolean {
        return this.handle.isDigest();
    }
}
