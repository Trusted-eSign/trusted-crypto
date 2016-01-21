import {native} from "../native";
import * as Collection from "../core/collection";
import {BaseObject} from "../object";

export class AttributeValueCollection extends BaseObject implements Collection.ICollectionWrite {

    get length(): number {
        return this.handle.length();
    }

    push(val: Buffer) {
        this.handle.push(val.toString("binary"));
    }

    pop() {
        this.handle.pup();
    }

    removeAt(index: number) {
        this.handle.removeAt(index);
    }

    items(index: number): Buffer { 
        return this.handle.items(index);
    }

}