import {native} from '../native'
import {BaseObject} from "../object"

export class ProviderSystem extends BaseObject{
	
	constructor(filename: string){
		super();	

		this.handle = new native.PKI.ProviderSystem(filename);
	}
    
    fillingJsonFromSystemStore(filename: string) {
		return this.handle.fillingJsonFromSystemStore(filename);
	}
	
    readJson(filename: string): string {
		return this.handle.readJson(filename);
	}
    
    testRead(filename: string): string {
		return this.handle.testRead(filename);
	}
}