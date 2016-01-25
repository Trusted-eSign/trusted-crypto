import {native} from '../native'
import {BaseObject} from "../object"

export class CertStore extends BaseObject{
	
	constructor(){
		super();	
		
		this.handle = new native.PKI.CertStore();
	}
    
    CERT_STORE_NEW(pvdType: string, pvdURI: string){
        return this.handle.CERT_STORE_NEW(pvdType, pvdURI);
    }
    
    newJson(filename: string) {
		return this.handle.newJson(filename);
	}
}