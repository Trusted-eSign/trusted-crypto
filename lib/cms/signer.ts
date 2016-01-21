import {native} from "../native";
import {BaseObject} from "../object";
import {DataFormat} from "../data_format";
import {Algorithm} from "../pki/alg";
import {Attribute} from "../pki/attr";
import {Certificate} from "../pki/cert";
import {SignerAttributeCollection} from "./signer_attrs";

/**
 * Представление `CMS SignerInfo`
 */
export class Signer extends BaseObject {

    constructor(nativeSigner: any) {
        super();

        this.handle = nativeSigner;
    }

    get certificate(): Certificate {
        return <Certificate>Certificate.nativeCreate(this.handle.getCertificate());
    }

    set certificate(val: Certificate) {
        this.handle.setCertificate(val.handle);
    }

    get digestAlgorithm(): Algorithm {
        let alg = new Algorithm();
        alg.handle = this.handle.getDigestAlgorithm();
        return alg;
    }

    signedAttributes(): SignerAttributeCollection;
    signedAttributes(index: number): Attribute;
    signedAttributes(index?: number): any {
        //get collection
        let attrs = <SignerAttributeCollection>SignerAttributeCollection.nativeCreate(this.handle.getSignedAttributes());

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
        let attrs = <SignerAttributeCollection>SignerAttributeCollection.nativeCreate(this.handle.getUnsignedAttributes());

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