import * as native from "../native";
import * as object from "../object";
import * as Collection from "../core/collection";
import {Certificate} from "./cert";

/**
 * Collection of Certificate
 *
 * @export
 * @class CertificateCollection
 * @extends {object.BaseObject<native.PKI.CertificateCollection>}
 * @implements {Collection.ICollectionWrite}
 */
export class CertificateCollection extends object.BaseObject<native.PKI.CertificateCollection>
 implements Collection.ICollectionWrite {

    /**
     * Creates an instance of CertificateCollection.
     *
     * @param {native.PKI.CertificateCollection} handle
     *
     * @memberOf CertificateCollection
     */
    constructor(handle: native.PKI.CertificateCollection);

    /**
     * Creates an instance of CertificateCollection.
     *
     *
     * @memberOf CertificateCollection
     */
    constructor();

    /**
     * Creates an instance of CertificateCollection.
     *
     * @param {*} [param]
     *
     * @memberOf CertificateCollection
     */
    constructor(param?: any) {
        super();
        if (param instanceof native.PKI.CertificateCollection) {
            this.handle = param;
        } else {
            this.handle = new native.PKI.CertificateCollection();
        }
    }

    /**
     * Return element by index from collection
     *
     * @param {number} index
     * @returns {Certificate}
     *
     * @memberOf CertificateCollection
     */
    public items(index: number): Certificate {
        return  Certificate.wrap<native.PKI.Certificate, Certificate>(this.handle.items(index));
    }

    /**
     * Return collection length
     *
     * @readonly
     * @type {number}
     * @memberOf CertificateCollection
     */
    get length(): number {
        return this.handle.length();
    }

     /**
      * Add new element to collection
      *
      * @param {Certificate} cert
      *
      * @memberOf CertificateCollection
      */
     public push(cert: Certificate): void {
        this.handle.push(cert.handle);
    }

    /**
     * Remove last element from collection
     *
     *
     * @memberOf CertificateCollection
     */
    public pop(): void {
        this.handle.pop();
    }

    /**
     * Remove element by index from collection
     *
     * @param {number} index
     *
     * @memberOf CertificateCollection
     */
    public removeAt(index: number): void {
        this.handle.removeAt(index);
    }
}
