import {native} from "../native";
import {BaseObject} from "../object";

export class Oid extends BaseObject {
    
    constructor(handle: Object);
    constructor(oid: string);
    constructor(param: any){
        super();
        if (typeof(param) === "string")
            this.handle = new native.PKI.OID(param);
        else if(typeof(param) === "object")
            this.handle = param;
        else
            throw new TypeError("Oid::constructor: Wrong input param");
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