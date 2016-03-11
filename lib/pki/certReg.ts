import * as native from "../native";
import * as object from "../object";
import {Key} from "./key";
import {CertificationRequestInfo} from "./certRegInfo";
import {DataFormat} from "../data_format";
 const DEFAULT_DATA_FORMAT = DataFormat.PEM;
export class CertificationRequest extends object.BaseObject<native.PKI.CertificationRequest> {


    constructor(csrinfo: CertificationRequestInfo) {
        super();
        this.handle = new native.PKI.CertificationRequest(csrinfo.handle);
    }
       
    /**
     * чтение запроса из файла
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.load(filename, format);
    }
    
    /**
     * чтение сертификата из файла
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    static load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): CertificationRequest {
        let csrinfo = new CertificationRequestInfo();
        let req = new CertificationRequest(csrinfo);
        req.handle.load(filename, format);
        return req;
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