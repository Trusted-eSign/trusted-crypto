import * as native from "../native";
import * as object from "../object";
import {Oid} from "./oid";
import {AttributeValueCollection} from "./attr_vals";

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

    get asnType(): number {
        return this.handle.getAsnType();
    }
    set asnType(value: number) { 
        this.handle.setAsnType(value);
    }

    get typeId(): Oid {
        return new Oid(this.handle.getTypeId());
    }

    set typeId(oid: Oid) {
        this.handle.setTypeId(oid.handle);
    }

    dupicate(): Attribute {
        let nattr = this.handle.duplicate();
        let attr = Attribute.wrap<native.PKI.Attribute, Attribute>(nattr);

        return attr;
    }

    export() {
        return this.handle.export();
    }

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