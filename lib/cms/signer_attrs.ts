import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {Attribute} from "../pki/attr";

export class SignerAttributeCollection extends object.BaseObject<native.CMS.SignerAttributeCollection> {
    
    constructor(nativeSigner: any) {
        super();

        this.handle = nativeSigner;
    }
    
    get length(): number{
        return this.handle.length();
    }
    
    push(attr: Attribute){
        this.handle.push(attr.handle);
    }
    
    removeAt(index: number){
        this.handle.removeAt(index);
    }
    
    items(index: number): Attribute{
        return new Attribute(this.handle.items(index));
    }    
    
}