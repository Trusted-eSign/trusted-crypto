import * as native from "../native";
import * as object from "../object";
import {Key} from "./key";
import {CertificationRequestInfo} from "./certRegInfo";
import {DataFormat} from "../data_format";
 const DEFAULT_DATA_FORMAT = DataFormat.PEM;
export class CertificationRequest extends object.BaseObject<native.PKI.CertificationRequest> {

    constructor(csrinfo: CertificationRequestInfo) {       
        handle: native.PKI.CertificationRequest;
        super();   
        this.handle = new native.PKI.CertificationRequest(csrinfo.handle);
    } 

    sign(key: Key){
        this.handle.sign(key.handle);
    }
    
    verify(): boolean{
         return this.handle.verify();
    }
    
     get PEMString(): Buffer {
        return this.handle.getPEMString();
    }
   
 }