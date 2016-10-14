import * as native from "../native";
import * as object from "../object";

/**
 * Wrap ASN1_OBJECT
 *
 * @export
 * @class Oid
 * @extends {object.BaseObject<native.PKI.OID>}
 */
export class Oid extends object.BaseObject<native.PKI.OID> {

    /**
     * Creates an instance of Oid.
     *
     * @param {native.PKI.OID} handle
     *
     * @memberOf Oid
     */
    constructor(handle: native.PKI.OID);

    /**
     * Creates an instance of Oid.
     *
     * @param {string} oid
     *
     * @memberOf Oid
     */
    constructor(oid: string);

    /**
     * Creates an instance of Oid.
     *
     * @param {*} param
     *
     * @memberOf Oid
     */
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
     * Return text value for OID
     *
     * @readonly
     * @type {string}
     * @memberOf Oid
     */
    get value(): string {
        return this.handle.getValue();
    }

    /**
     * Return OID long name
     *
     * @readonly
     * @type {string}
     * @memberOf Oid
     */
    get longName(): string {
        return this.handle.getLongName();
    }

    /**
     * Return OID short name
     *
     * @readonly
     * @type {string}
     * @memberOf Oid
     */
    get shortName(): string {
        return this.handle.getShortName();
    }
}
