import {native} from "../native";
import {BaseObject} from "../object";
import {DataFormat} from "../data_format";

const DEFAULT_DATA_FORMAT = DataFormat.DER;

/**
 * Представление `CMS SignedData`
 */
export class SignedData extends BaseObject {

    constructor() {
        super();

        this.handle = new native.CMS.SignedData();
    }
    
    get certificates(): Array<any>{
        return this.handle.getCertificates();
    }
    
    get signers(): Array<any>{
        return this.handle.getSigners();
    }

    /**
     * чтение подписи из файла
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.load(filename);
    }

    /**
     * чтение подписи из файла
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    static load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): SignedData {
        let cms = new SignedData();
        cms.handle.load(filename, format);
        return cms;
    }

    /**
     * чтение подписи из памяти
     * @param buffer Буфер памяти
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.import(buffer, format);
    }

    /**
     * чтение подписи из памяти
     * @param buffer Буфер памяти
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    static import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): SignedData {
        let cms = new SignedData();
        cms.handle.import(buffer, format);
        return cms;
    }

}