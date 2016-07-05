import * as native from "../native";
import * as object from "../object";
import {Key} from "./key";
import {DataFormat} from "../data_format";

const DEFAULT_DATA_FORMAT: DataFormat = DataFormat.PEM;

export class CertificationRequest extends object.BaseObject<native.PKI.CertificationRequest> {
    /**
     * чтение запроса из файла
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    public static load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): CertificationRequest {
        let req: CertificationRequest = new CertificationRequest();
        req.handle.load(filename, format);
        return req;
    }

    constructor();
    constructor(handle: native.PKI.CertificationRequest);
    constructor(param?: any) {
        super();
        if (param instanceof native.PKI.CertificationRequestInfo) {
             this.handle = new native.PKI.CertificationRequest(param);
        } else {
            this.handle = new native.PKI.CertificationRequest();
        }
    }

    /**
     * чтение запроса из файла
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    public load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.load(filename, format);
    }

    public sign(key: Key): void {
        this.handle.sign(key.handle);
    }

    public verify(): boolean {
         return this.handle.verify();
    }

     get PEMString(): Buffer {
        return this.handle.getPEMString();
    }
 }
