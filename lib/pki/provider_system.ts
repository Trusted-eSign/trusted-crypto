import {native} from '../native'
import {BaseObject} from "../object"

export class ProviderSystem extends BaseObject{
	
	constructor(filename: string){
		super();	

		this.handle = new native.PKI.ProviderSystem(filename);
	}
    
    fillingCache(cacheURI: string, pvdURI: string) {
		return this.handle.fillingCache(cacheURI, pvdURI);
	}
	
    readJson(filename: string): string {
		return this.handle.readJson(filename);
	}
}