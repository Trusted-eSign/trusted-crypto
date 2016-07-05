import * as native from "../native";
import * as object from "../object";
import * as Collection from "../core/collection";
import {Signer} from "./signer";

/**
 * Представление коллекции `Signer`
 */
export class SignerCollection extends object.BaseObject<native.CMS.SignerCollection> implements Collection.ICollection {

    constructor(nativeHandle: native.CMS.SignerCollection) {
        super();

        this.handle = nativeHandle;
    }

    /**
     * Возвращает элемент из коллекции по заданному индексу
     * @param index Индекс элемента в коллекции
     */
    public items(index: number): Signer {
        return new Signer(this.handle.items(index));
    }

    /**
     * Возвращает размер коллекции
     * @param index Индекс элемента в коллекции
     */
    get length(): number {
        return this.handle.length();
    }

}
