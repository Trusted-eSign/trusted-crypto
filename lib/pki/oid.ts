import * as native from "../native";
import * as object from "../object";

/**
 * Представление идентификатора объектов ASN1_OBJECT_IDENTIFIER
 */
export class Oid extends object.BaseObject<native.PKI.OID> {

    constructor(handle: native.PKI.OID);
    constructor(oid: string);
    constructor(param: any) {
        super();
        if (typeof (param) === "string") {
            this.handle = new native.PKI.OID(param);
        } else if (param instanceof native.PKI.OID) {
            this.handle = param;
        } else {
            throw new TypeError("Oid::constructor: Wrong input param");
        }
    }

    /**
     * возвращает текстовое значение идентификатора
     */
    get value(): string {
        return this.handle.getValue();
    }

    /**
     * возвращает полное имя идентификатора
     */
    get longName(): string {
        return this.handle.getLongName();
    }

    /**
     * возвращает короткое имя идентификатора
     */
    get shortName(): string {
        return this.handle.getShortName();
    }
}
