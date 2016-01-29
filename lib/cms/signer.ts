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

    /**
     * Возвращает сертификат подписчика
     */
    get certificate(): Certificate {
        return new Certificate(this.handle.getCertificate());
    }

    /**
     * Задает сертификат подписчика
     * @param val Сертификат
     * - если сенртификат не является сертификатом подписчика, то возникнет ошибка 
     */
    set certificate(val: Certificate) {
        this.handle.setCertificate(val.handle);
    }

    /**
     * возвращает хэш алгоритм проверки содержимого 
     */
    get digestAlgorithm(): Algorithm {
        let alg = new Algorithm(this.handle.getDigestAlgorithm());
        return alg;
    }

    /**
     * возвращает коллекцию подписанных атрибутов
     */
    signedAttributes(): SignerAttributeCollection;
    /**
     * возвращает атрибут из коллекции по заданному индексу
     * @param index индекс элемента в коллекции
     */
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

    /**
     * возвращает коллекцию подписанных атрибутов
     */
    unsignedAttributes(): SignerAttributeCollection;
    /**
     * возвращает атрибут из коллекции по заданному индексу
     * @param index индекс элемента в коллекции
     */
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