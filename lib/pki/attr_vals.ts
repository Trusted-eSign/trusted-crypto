import * as native from "../native";
import * as object from "../object";
import * as Collection from "../core/collection";

export class AttributeValueCollection extends object.BaseObject<native.PKI.AttributeValueCollection> implements Collection.ICollectionWrite {
    
    constructor(handle: native.PKI.AttributeValueCollection){
        super();
        
        this.handle = handle;
    }

    get length(): number {
        return this.handle.length();
    }

    push(val: Buffer) {
        this.handle.push(val);
    }

    pop() {
        this.handle.pop();
    }

    removeAt(index: number) {
        this.handle.removeAt(index);
    }

    items(index: number): Buffer { 
        return this.handle.items(index);
    }

}