import * as native from "../native";
import * as object from "../object";
import * as Collection from "../core/collection";

/**
 * Представляет коллекцию значений атрибута X509_ATTR
 */
export class AttributeValueCollection extends object.BaseObject<native.PKI.AttributeValueCollection>
 implements Collection.ICollectionWrite {

    constructor(handle: native.PKI.AttributeValueCollection) {
        super();

        this.handle = handle;
    }

    /**
     * возвращает количество элементов в коллекции
     */
    get length(): number {
        return this.handle.length();
    }

    /**
     * добавляет новый элемент в коллекцию
     * @param val новое значение коллекции
     */
    public push(val: Buffer): void {
        this.handle.push(val);
    }

    /**
     * удаляет последний элемент из коллекции
     */
    public pop(): void {
        this.handle.pop();
    }

    /**
     * удаляет элемент коллекции по заданному индексу
     * @param index индекс элемента в коллекции
     */
    public removeAt(index: number): void {
        this.handle.removeAt(index);
    }

    /**
     * возвращает элемент из коллекции по заданному индексу
     * @param index индекс элемента в коллекции
     */
    public items(index: number): Buffer {
        return this.handle.items(index);
    }
}
