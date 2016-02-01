import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {Key} from "./key";

const DEFAULT_DATA_FORMAT = DataFormat.PEM;

export class CSR extends object.BaseObject<native.PKI.CSR> {
    
    constructor(name: string, key: Key, digest: string){
        handle: native.PKI.CSR;
         super();   
          this.handle = new native.PKI.CSR(name, key.handle, digest);
    } 

    get encoded(): Buffer {
        return this.handle.getEncoded();
    }
    
    /**
     * сохранение структуры в файл
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию PEM
     */
    save(filename: string, dataFormat: DataFormat = DEFAULT_DATA_FORMAT) {
        this.handle.save(filename, dataFormat);
    }

}