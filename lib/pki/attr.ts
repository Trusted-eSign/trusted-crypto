import * as native from "../native";
import * as object from "../object";
import {Oid} from "./oid";
import {AttributeValueCollection} from "./attr_vals";

/**
 * Представление X509_ATTR
 */
export class Attribute extends object.BaseObject<native.PKI.Attribute> {

    constructor(handle: native.PKI.Attribute);
    constructor(param?) {
        super();
        if (param instanceof native.PKI.Attribute){
            this.handle = param;
        }
        else
            this.handle = new native.PKI.Attribute();
    }

    /**
     * Возвращает ASN1 тип атрибута
     */
    get asnType(): number {
        // TODO: Создать enum с перечислением возможных типов ASN1 
        return this.handle.getAsnType();
    }
    
    /**
     * Задает ASN1 тип атрибута
     * @param value ASN1 тип
     */
    set asnType(value: number) { 
        this.handle.setAsnType(value);
    }

    /**
     * возвращает идентификатор атрибута
     */
    get typeId(): Oid {
        return new Oid(this.handle.getTypeId());
    }

    /**
     * задает идентификатор атрибута
     * @param oid идентификатор
     */
    set typeId(oid: Oid) {
        this.handle.setTypeId(oid.handle);
    }

    /**
     * возвращает копию атрибута
     */
    dupicate(): Attribute {
        let nattr = this.handle.duplicate();
        let attr = Attribute.wrap<native.PKI.Attribute, Attribute>(nattr);

        return attr;
    }

    /**
     * возвращает атрибут в DER кодировке 
     */
    export() {
        return this.handle.export();
    }

    /**
     * возвращает коллекцию значений атрибута. Значения представляются в DER формате
     * @param index индекс элемента в коллекции
     */
    values(index: number): Buffer;
    values(): AttributeValueCollection;
    values(index?: number): any {
        let vals = this.handle.values();
        let attr_vals: AttributeValueCollection = AttributeValueCollection.wrap<native.PKI.AttributeValueCollection, AttributeValueCollection>(vals);

        if (index === undefined)
            return attr_vals;
        else
            return attr_vals.items(index);
    }

}