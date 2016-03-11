import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {Key} from "./key";
import {CertificationRequest} from "./certReg";

const DEFAULT_DATA_FORMAT = DataFormat.PEM;

export class CSR extends object.BaseObject<native.PKI.CSR> {
    
    constructor(name: string, key: Key, digest: string) {
        super();
        this.handle = new native.PKI.CSR(name, key.handle, digest);
    } 

    get encoded(): Buffer {
        return this.handle.getEncodedHEX();
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