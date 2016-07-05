import * as native from "../native";
import * as object from "../object";
import {Oid} from "./oid";
import {AttributeValueCollection} from "./attr_vals";

/**
 * Представление X509_ATTR
 */
export class Attribute extends object.BaseObject<native.PKI.Attribute> {

    constructor(handle: native.PKI.Attribute);
    constructor(param?: any) {
        super();
        if (param instanceof native.PKI.Attribute) {
            this.handle = param;
        } else {
            this.handle = new native.PKI.Attribute();
        }
    }

    /**
     * Возвращает ASN1 тип атрибута
     */
    get asnType(): number {
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
    public dupicate(): Attribute {
        let nattr: any = this.handle.duplicate();
        let attr: Attribute = Attribute.wrap<native.PKI.Attribute, Attribute>(nattr);

        return attr;
    }

    /**
     * возвращает атрибут в DER кодировке
     */
    public export(): any {
        return this.handle.export();
    }

    /**
     * возвращает коллекцию значений атрибута. Значения представляются в DER формате
     * @param index индекс элемента в коллекции
     */
    public values(index: number): Buffer;
    public values(): AttributeValueCollection;
    public values(index?: number): any {
        let vals: any = this.handle.values();
        let attrVals: AttributeValueCollection =
         AttributeValueCollection.wrap<native.PKI.AttributeValueCollection, AttributeValueCollection>(vals);

        if (index === undefined) {
            return attrVals;
        } else {
            return attrVals.items(index);
        }
    }
}
