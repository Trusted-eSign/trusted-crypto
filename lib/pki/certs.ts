import * as native from "../native";
import * as object from "../object";
import * as Collection from "../core/collection";
import {Certificate} from "./cert";

/**
 * Представление коллекции `X509` сертификатов
 */
export class CertificateCollection extends object.BaseObject<native.PKI.CertificateCollection>
 implements Collection.ICollectionWrite {

    constructor(handle: native.PKI.CertificateCollection);
    constructor();
    constructor(param?: any) {
        super();
        if (param instanceof native.PKI.CertificateCollection) {
            this.handle = param;
        } else {
            this.handle = new native.PKI.CertificateCollection();
        }
    }

    /**
     * Возвращает элемент из коллекции по заданному индексу
     * @param index Индекс элемента в коллекции
     */
    public items(index: number): Certificate {
        return  Certificate.wrap<native.PKI.Certificate, Certificate>(this.handle.items(index));
    }

    /**
     * Возвращает размер коллекции
     */
    get length(): number {
        return this.handle.length();
    }

    /**
     * Добавляет новый элемент в коллекцию
     * @param cert Элемент для добавления в коллекцию
     */
    public push(cert: Certificate): void {
        this.handle.push(cert.handle);
    }

    /**
     * Удаляет последний элемент их коллекции
     */
    public pop(): void {
        this.handle.pop();
    }

    /**
     * Удаляет элемент из коллекции по заданному индексу
     * @param index Индекс элемента в коллекции
     */
    public removeAt(index: number): void {
        this.handle.removeAt(index);
    }
}
