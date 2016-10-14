import * as native from "../native";
import * as object from "../object";
import {Key} from "./key";
import {DataFormat} from "../data_format";

const DEFAULT_DATA_FORMAT: DataFormat = DataFormat.PEM;

/**
 * Wrap X509_REQ
 *
 * @export
 * @class CertificationRequest
 * @extends {object.BaseObject<native.PKI.CertificationRequest>}
 */
export class CertificationRequest extends object.BaseObject<native.PKI.CertificationRequest> {

    /**
     * Load request from file
     *
     * @static
     * @param {string} filename File location
     * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
     * @returns {CertificationRequest}
     *
     * @memberOf CertificationRequest
     */
    public static load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): CertificationRequest {
        let req: CertificationRequest = new CertificationRequest();
        req.handle.load(filename, format);
        return req;
    }

    /**
     * Creates an instance of CertificationRequest.
     *
     *
     * @memberOf CertificationRequest
     */
    constructor();

    /**
     * Creates an instance of CertificationRequest.
     *
     * @param {native.PKI.CertificationRequest} handle
     *
     * @memberOf CertificationRequest
     */
    constructor(handle: native.PKI.CertificationRequest);

    /**
     * Creates an instance of CertificationRequest.
     *
     * @param {*} [param]
     *
     * @memberOf CertificationRequest
     */
    constructor(param?: any) {
        super();
        if (param instanceof native.PKI.CertificationRequestInfo) {
             this.handle = new native.PKI.CertificationRequest(param);
        } else {
            this.handle = new native.PKI.CertificationRequest();
        }
    }

    /**
     * Load request from file
     *
     * @param {string} filename File location
     * @param {DataFormat} [format=DEFAULT_DATA_FORMAT] PEM | DER (default)
     *
     * @memberOf CertificationRequest
     */
    public load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.load(filename, format);
    }

    /**
     * Sign request
     *
     * @param {Key} key Private key
     *
     * @memberOf CertificationRequest
     */
    public sign(key: Key): void {
        this.handle.sign(key.handle);
    }

    /**
     * Verify request
     *
     * @returns {boolean}
     *
     * @memberOf CertificationRequest
     */
    public verify(): boolean {
         return this.handle.verify();
    }

     /**
      * Return request in PEM format
      *
      * @readonly
      * @type {Buffer}
      * @memberOf CertificationRequest
      */
     get PEMString(): Buffer {
        return this.handle.getPEMString();
    }
 }
