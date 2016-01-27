import * as native from "../native";
import * as object from "../object";

export class ProviderSystem extends object.BaseObject<native.PKI.ProviderSystem>{

    constructor(handle: native.PKI.ProviderSystem);
    constructor(filename: string);
    constructor(param) {
        super();
        if (param instanceof native.PKI.ProviderSystem)
            this.handle = param;
        else
            this.handle = new native.PKI.ProviderSystem(param);
    }

    fillingCache(cacheURI: string, pvdURI: string) {
        this.handle.fillingCache(cacheURI, pvdURI);
    }

    readJson(filename: string): string {
        return this.handle.readJson(filename);
    }
}