import {native} from "../native";
import {BaseObject} from "../object";

export class Oid extends BaseObject {
    
    constructor(oid: string){
        super();
        
        this.handle = new native.PKI.OID(oid);
    }
    
    get value(): string{
        return this.handle.getValue();
    }
    
    get longName(): string{
        return this.handle.getLongName();
    }
    
    get shortName(): string{
        return this.handle.getShortName();
    }
    
}