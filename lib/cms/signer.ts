import * as native from "../native";
import * as object from "../object";
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
        let alg: Algorithm = new Algorithm(this.handle.getDigestAlgorithm());
        return alg;
    }

    /**
     * возвращает коллекцию подписанных атрибутов
     */
    public signedAttributes(): SignerAttributeCollection;
    /**
     * возвращает атрибут из коллекции по заданному индексу
     * @param index индекс элемента в коллекции
     */
    public signedAttributes(index: number): Attribute;
    public signedAttributes(index?: number): any {
        let attrs: SignerAttributeCollection = new SignerAttributeCollection(this.handle.getSignedAttributes());

        if (index === undefined) {
            return attrs;
        } else {
            return attrs.items(index);
        }
    }

    /**
     * возвращает коллекцию неподписанных подписанных атрибутов
     */
    public unsignedAttributes(): SignerAttributeCollection;
    /**
     * возвращает атрибут из коллекции по заданному индексу
     * @param index индекс элемента в коллекции
     */
    public unsignedAttributes(index: number): Attribute;
    public unsignedAttributes(index?: number): any {
        let attrs: SignerAttributeCollection = new SignerAttributeCollection(this.handle.getUnsignedAttributes());

        if (index === undefined) {
            return attrs;
        } else {
            return attrs.items(index);
        }
    }
}
