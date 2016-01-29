import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {Certificate} from "./cert";


const DEFAULT_DATA_FORMAT = DataFormat.DER;

export class Crl extends object.BaseObject<native.PKI.CRL>{

    constructor();
    constructor(handle: native.PKI.CRL);
    constructor(param?) {
        super();
        if (param instanceof native.PKI.CRL) {
            this.handle = param;
        }
        else {
            this.handle = new native.PKI.CRL();
        }
    }

    get encoded(): Buffer {
        return this.handle.getEncoded();
    }
    
    /**
     * возвращает значение подписи 
     */
    get signature(): Buffer {
        return this.handle.getSignature();
    }
	
    /**
     * возвращает версию
     */
    get version(): number {
        return this.handle.getVersion();
    }
	
    /**
     * возвращает имя издателя
     */
    get issuerName(): string {
        return this.handle.getIssuerName();
    }
	
    /**
     * возвращает дату последнего обновления
     */
    get lastUpdate(): Date {
        return new Date(this.handle.getLastUpdate());
    }

    /**
     * возвращает дату следующего обновления
     */
    get nextUpdate(): Date {
        return new Date(this.handle.getNextUpdate());
    }

    /**
     * возвращает отпечаток (SHA1)
     */
    get thumbprint(): string {
        return this.handle.getThumbprint().toString("hex");
    }

    get sigAlgName(): string {
        return this.handle.getSigAlgName();
    }

    get sigAlgShortName(): string {
        return this.handle.getSigAlgShortName();
    }

    get sigAlgOID(): string {
        return this.handle.getSigAlgOID();
    }

    getRevokedCertificateCert(cer: Certificate): native.PKI.RevokedCertificate {
        return this.handle.getRevokedCertificateCert(cer.handle);
    }

    getRevokedCertificateSerial(serial: string): native.PKI.RevokedCertificate {
        return this.handle.getRevokedCertificateSerial(serial);
    }

    /**
     * чтение структуры из файла
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.load(filename, format);
    }

    /**
     * чтение структуры из файла
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    static load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): Crl {
        let crl = new Crl();
        crl.load(filename, format);
        return crl;
    }

    /**
     * чтение структуры из памяти
     * @param buffer Буфер памяти
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.import(buffer, format);
    }

    /**
     * чтение структуры из памяти
     * @param buffer Буфер памяти
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    static import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): Crl {
        let crl = new Crl();
        crl.import(buffer, format);
        return crl;
    }

    /**
     * сохранение структуры в память
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    export(format: DataFormat = DEFAULT_DATA_FORMAT) {
        return this.handle.export(format);
    }

    /**
     * сохранение структуры в файл
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    save(filename: string, dataFormat: DataFormat = DEFAULT_DATA_FORMAT) {
        this.handle.save(filename, dataFormat);
    }

    /**
     * сравнение
     * @param crl Список отзыва сертификтов
     */
    equals(crl: Crl): boolean {
        return this.handle.equals(crl.handle);
    }

    /**
     * возвращает хэш структуры по заданному алгоритму
     * @param algorithm название хэш алгоритма
     */
    hash(algorithm: string = "sha1"): String {
        return this.handle.hash(algorithm).toString("hex");
    }

    /**
     * создает копию элемента
     */
    duplicate(): Crl {
        let crl = new Crl();
        crl.handle = this.handle.duplicate();
        return crl;
    }

}