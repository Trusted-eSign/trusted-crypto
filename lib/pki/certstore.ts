import {native} from '../native'
import {BaseObject} from "../object"

export class CertStore extends BaseObject{
	
	constructor(){
		super();	
		
		this.handle = new native.PKI.CertStore();
	}
    
    newJson(filename: string) {
		return this.handle.newJson(filename);
	}
}