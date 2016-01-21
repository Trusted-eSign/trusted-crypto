import {native} from "../native";
import {BaseObject} from "../object";
import {Oid} from "./oid";
import {AttributeValueCollection} from "./attr_vals";

export class Attribute extends BaseObject {

    constructor() {
        super();

        this.handle = new native.PKI.Certificate();
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
        let attr = Attribute.nativeCreate(nattr);

        return <Attribute>attr;
    }

    export() {
        return this.handle.export();
    }

    values(index: number): Buffer;
    values(): AttributeValueCollection;
    values(index?: number): any {
        let vals = this.handle.values();
        let attr_vals: AttributeValueCollection = <AttributeValueCollection>AttributeValueCollection.nativeCreate(vals);

        if (index === undefined)
            return attr_vals;
        else
            return attr_vals.items(index);
    }

}