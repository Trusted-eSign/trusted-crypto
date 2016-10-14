import * as native from "../native";
import * as object from "../object";
import {Algorithm} from "../pki/alg";
import {Attribute} from "../pki/attr";
import {Certificate} from "../pki/cert";
import {SignerAttributeCollection} from "./signer_attrs";

/**
 * Wrap CMS_SignerInfo
 *
 * @export
 * @class Signer
 * @extends {object.BaseObject<native.CMS.Signer>}
 */
export class Signer extends object.BaseObject<native.CMS.Signer> {

    /**
     * Creates an instance of Signer.
     *
     * @param {native.CMS.Signer} handle
     *
     * @memberOf Signer
     */
    constructor(handle: native.CMS.Signer) {
        super();

        this.handle = handle;
    }

    /**
     * Return signer certificate
     *
     * @type {Certificate}
     * @memberOf Signer
     */
    get certificate(): Certificate {
        return new Certificate(this.handle.getCertificate());
    }

    /**
     * Set signer certificate
     * Error if cert no signer
     *
     * @param cert Certificate
     *
     * @memberOf Signer
     */
    set certificate(cert: Certificate) {
        this.handle.setCertificate(cert.handle);
    }

    /**
     * Return digest algorithm
     *
     * @readonly
     * @type {Algorithm}
     * @memberOf Signer
     */
    get digestAlgorithm(): Algorithm {
        let alg: Algorithm = new Algorithm(this.handle.getDigestAlgorithm());
        return alg;
    }

    /**
     * Return signed attributes collection
     *
     * @returns {SignerAttributeCollection}
     *
     * @memberOf Signer
     */
    public signedAttributes(): SignerAttributeCollection;

    /**
     * Return attribute by index
     *
     * @param {number} index
     * @returns {Attribute}
     *
     * @memberOf Signer
     */
    public signedAttributes(index: number): Attribute;

    /**
     * Return signed attributes collection or attribute by index (if request)
     *
     * @param {number} [index]
     * @returns {*}
     *
     * @memberOf Signer
     */
    public signedAttributes(index?: number): any {
        let attrs: SignerAttributeCollection = new SignerAttributeCollection(this.handle.getSignedAttributes());

        if (index === undefined) {
            return attrs;
        } else {
            return attrs.items(index);
        }
    }

    /**
     * Return unsigned attributes collection
     *
     * @returns {SignerAttributeCollection}
     *
     * @memberOf Signer
     */
    public unsignedAttributes(): SignerAttributeCollection;

    /**
     * Return unsigned attribute by index
     *
     * @param {number} index
     * @returns {Attribute}
     *
     * @memberOf Signer
     */
    public unsignedAttributes(index: number): Attribute;

    /**
     * Return unsigned attributes collection or attribute by index (if request)
     *
     * @param {number} [index]
     * @returns {*}
     *
     * @memberOf Signer
     */
    public unsignedAttributes(index?: number): any {
        let attrs: SignerAttributeCollection = new SignerAttributeCollection(this.handle.getUnsignedAttributes());

        if (index === undefined) {
            return attrs;
        } else {
            return attrs.items(index);
        }
    }
}
