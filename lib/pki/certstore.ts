import {native} from '../native'
import {BaseObject} from "../object"

export class CertStore extends BaseObject{
	
	constructor(){
		super();	
		
		this.handle = new native.PKI.CertStore();
	}
       
    addCertStore(pvdType: string, pvdURI: string){
        return this.handle.addCertStore(pvdType, pvdURI);
    }
    
   removeCertStore(pvdType: string){
        return this.handle.removeCertStore(pvdType);
    }
    
    createCache(cacheURI: string) {
		return this.handle.createCache(cacheURI);
	}
    
    addCacheSection(cacheURI: string, pvdType: string) {
		return this.handle.addCacheSection(cacheURI, pvdType);
	}
    
    get listCertStore(): string {
        return this.handle.getCertStore();
    }
    
    getPrvTypePresent(pvdType: string): boolean {
        return this.handle.getPrvTypePresent(pvdType);
    }
}