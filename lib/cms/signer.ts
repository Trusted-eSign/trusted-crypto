import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {Algorithm} from "../pki/alg";
import {Attribute} from "../pki/attr";
import {Certificate} from "../pki/cert";
import {SignerAttributeCollection} from "./signer_attrs";

/**
 * Представление `CMS SignerInfo`
 */
export class Signer extends object.BaseObject<native.CMS.Signer> {

    constructor(handle: native.CMS.Signer) {
        super();

        this.handle = handle;
    }

    get certificate(): Certificate {
        return new Certificate(this.handle.getCertificate());
    }

    set certificate(val: Certificate) {
        this.handle.setCertificate(val.handle);
    }

    get digestAlgorithm(): Algorithm {
        let alg = new Algorithm(this.handle.getDigestAlgorithm());
        return alg;
    }

    signedAttributes(): SignerAttributeCollection;
    signedAttributes(index: number): Attribute;
    signedAttributes(index?: number): any {
        //get collection
        let attrs = new SignerAttributeCollection(this.handle.getSignedAttributes());

        if (index === undefined) {
            // return collection
            return attrs
        }
        else {
            // return item
            return attrs.items(index);
        }
    }

    unsignedAttributes(): SignerAttributeCollection;
    unsignedAttributes(index: number): Attribute;
    unsignedAttributes(index?: number): any {
        //get collection
        let attrs = new SignerAttributeCollection(this.handle.getUnsignedAttributes());

        if (index === undefined) {
            // return collection
            return attrs
        }
        else {
            // return item
            return attrs.items(index);
        }
    }

}