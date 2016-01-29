import * as native from "../native";
import * as object from "../object";
import {ICollection} from "../core/collection";
import {DataFormat} from "../data_format";
import {Attribute} from "../pki/attr";

/**
 * Представление коллекции атрибутов подписчика
 */
export class SignerAttributeCollection extends object.BaseObject<native.CMS.SignerAttributeCollection> implements ICollection {
    
    constructor(nativeSigner: native.CMS.SignerAttributeCollection) {
        super();

        this.handle = nativeSigner;
    }
    
    /**
     *  возвращет количество элементов в коллекции 
     */ 
    get length(): number{
        return this.handle.length();
    }
    
    /**
     * добавляет новый элемент в коллекцию
     * @param новый элемент коллекции
     */
    push(attr: Attribute){
        this.handle.push(attr.handle);
    }
    
    /**
     * удаляет элемент из коллекции по заданному индексу
     * @param index индекс элемента в коллекции
     */
    removeAt(index: number){
        this.handle.removeAt(index);
    }
    
    /**
     * возвращает элемент коллекции по заданному индексу
     * @param index индекс элемента в коллекции
     */
    items(index: number): Attribute{
        return new Attribute(this.handle.items(index));
    }    
    
}