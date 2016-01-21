import {native} from "../native";
import {BaseObject} from "../object";
import {DataFormat} from "../data_format";
import {Attribute} from "../pki/attr";

export class SignerAttributeCollection extends BaseObject {
    
    constructor(nativeSigner: any) {
        super();

        this.handle = nativeSigner;
    }
    
    get length(){
        return this.handle.length();
    }
    
    push(attr: Attribute){
        this.handle.push(attr.handle);
    }
    
    removeAt(index: number){
        this.handle.removeAt(index);
    }
    
    items(index: number): Attribute{
        return <Attribute> Attribute.nativeCreate(this.handle.items(index));
    }    
    
}