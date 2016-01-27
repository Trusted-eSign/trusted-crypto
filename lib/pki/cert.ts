import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";

const DEFAULT_DATA_FORMAT = DataFormat.DER;

/**
 * Представление `X509` сертификата
 */
export class Certificate extends object.BaseObject<native.PKI.Certificate> {

    constructor();
    constructor(handle: native.PKI.Certificate);
    constructor(param?) {
        super();
        if (param instanceof native.PKI.Certificate){
            this.handle = param;
        }
        else{
            this.handle = new native.PKI.Certificate();
        }
    }
    
    /**
     * возвращает версию сертификата
     */
    get version(): number {
        return this.handle.getVersion();
    }

    /**
     * возвращает серийный номер сертификата
     */
    get serialNumber(): string {
        return this.handle.getSerialNumber().toString("hex");
    }

    /**
     * возвращает тип сертификата
     */
    get type(): number {
        return this.handle.getType();
    }

    /**
     * возвращает набор флагов KeyUsageFlags, задающих назначение ключа сертификата
     */
    get keyUsage(): number {
        return this.handle.getKeyUsage();
    }

    /**
     * возвращает пользовательское имя издателя сертификата
     */
    get issuerFriendlyName(): string {
        return this.handle.getIssuerFriendlyName();
    }

    /**
     * возвращает полное имя издателя сертификата
     */
    get issuerName(): string {
        return this.handle.getIssuerName();
    }

    /**
     * возвращает пользовательское имя владельца сертификата
     */
    get subjectFriendlyName(): string {
        return this.handle.getSubjectFriendlyName();
    }

    /**
     * возвращает полное имя владельца сертификата
     */
    get subjectName(): string {
        return this.handle.getSubjectName();
    }

    /**
     * возвращает время с которого сертификат считается действительным
     */
    get notBefore(): Date {
        return new Date(this.handle.getNotBefore());
    }

    /**
     * возвращает время до которого сертификат считается действительным
     */
    get notAfter(): Date {
        return new Date(this.handle.getNotAfter());
    }

    /**
     * возвращает отпечаток сертификата SHA-1
     */
    get thumbprint(): string {
        return this.handle.getThumbprint().toString("hex");
    }

    /**
     * сравнение сертификатов
     * @param cert Сертификат для сравнения
     */
    compare(cert: Certificate): number {
        let cmp = this.handle.compare(cert.handle);
        if (cmp < 0)
            return -1;
        if (cmp > 0)
            return 1;
        return 0;
    }

    /**
     * сравнение сертификатов
     * @param cert Сертификат для сравнения
     */
    equals(cert: Certificate): boolean {
        return this.handle.equals(cert.handle);
    }

    /**
     * вычисление значения хэша сертификата
     * @param algorithm Имя хэш алгоритма. Опционально. По умолчанию sha1
     */
    hash(algorithm: string = "sha1"): String {
        return this.handle.hash(algorithm).toString("hex");
    }
    
    /**
     * Создает копию сертификата
     */
    duplicate(): Certificate {
        let cert = new Certificate();
        cert.handle = this.handle.duplicate();
        return cert;
    }

    /**
     * чтение сертификата из файла
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
    static load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): Certificate {
        let cert = new Certificate();
        cert.handle.load(filename, format);
        return cert;
    }

    /**
     * чтение сертификата из памяти
     * @param buffer Буфер памяти
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.import(buffer, format);
    }

    /**
     * чтение сертификата из памяти
     * @param buffer Буфер памяти
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    static import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): Certificate {
        let cert = new Certificate();
        cert.handle.import(buffer, format);
        return cert;
    }

    /**
     * сохранение сертификата в память
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    export(format: DataFormat = DEFAULT_DATA_FORMAT): Buffer {
        return this.handle.export(format);
    }

    /**
     * сохранение сертификата в файл
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    save(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.save(filename, format);
    }

}