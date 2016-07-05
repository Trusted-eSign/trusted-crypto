import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";

const DEFAULT_DATA_FORMAT: DataFormat  = DataFormat.DER;

/**
 * Представление `X509` сертификата
 */
export class Certificate extends object.BaseObject<native.PKI.Certificate> {
     /**
      * чтение сертификата из файла
      * @param filename Путь к файлу
      * @param format Формат данных. Опционально. По умолчанию DER
      */
    public static load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): Certificate {
        let cert: Certificate = new Certificate();
        cert.handle.load(filename, format);
        return cert;
    }

    /**
     * чтение сертификата из памяти
     * @param buffer Буфер памяти
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    public static import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): Certificate {
        let cert: Certificate = new Certificate();
        cert.handle.import(buffer, format);
        return cert;
    }

    constructor();
    constructor(handle: native.PKI.Certificate);
    constructor(param?: any) {
        super();
        if (param instanceof native.PKI.Certificate) {
            this.handle = param;
        } else {
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
        return this.handle.getSerialNumber().toString();
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
     * возвращает алгоритм подписи
     */
    get signatureAlgorithm(): string {
        return this.handle.getSignatureAlgorithm();
    }

    /**
     * возвращает название организации
     */
    get organizationName(): string {
        return this.handle.getOrganizationName();
    }

    /**
     * сравнение сертификатов
     * @param cert Сертификат для сравнения
     */
    public compare(cert: Certificate): number {
        let cmp: any = this.handle.compare(cert.handle);
        if (cmp < 0) {
            return -1;
        }
        if (cmp > 0) {
            return 1;
        }

        return 0;
    }

    /**
     * сравнение сертификатов
     * @param cert Сертификат для сравнения
     */
    public equals(cert: Certificate): boolean {
        return this.handle.equals(cert.handle);
    }

    /**
     * вычисление значения хэша сертификата
     * @param algorithm Имя хэш алгоритма. Опционально. По умолчанию sha1
     */
    public hash(algorithm: string = "sha1"): String {
        return this.handle.hash(algorithm).toString("hex");
    }

    /**
     * Создает копию сертификата
     */
    public duplicate(): Certificate {
        let cert: Certificate = new Certificate();
        cert.handle = this.handle.duplicate();
        return cert;
    }

    /**
     * чтение сертификата из файла
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    public load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.load(filename, format);
    }

    /**
     * чтение сертификата из памяти
     * @param buffer Буфер памяти
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    public import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.import(buffer, format);
    }

    /**
     * сохранение сертификата в память
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    public export(format: DataFormat = DEFAULT_DATA_FORMAT): Buffer {
        return this.handle.export(format);
    }

    /**
     * сохранение сертификата в файл
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    public save(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.save(filename, format);
    }
}
