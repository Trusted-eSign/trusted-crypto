import * as native from "../native";
import * as object from "../object";

export class Oid extends object.BaseObject<native.PKI.OID> {

    constructor(handle: native.PKI.OID);
    constructor(oid: string);
    constructor(param: any) {
        super();
        if (typeof (param) === "string")
            this.handle = new native.PKI.OID(param);
        else if (param instanceof native.PKI.OID)
            this.handle = param;
        else
            throw new TypeError("Oid::constructor: Wrong input param");
    }

    get value(): string {
        return this.handle.getValue();
    }

    get longName(): string {
        return this.handle.getLongName();
    }

    get shortName(): string {
        return this.handle.getShortName();
    }

}