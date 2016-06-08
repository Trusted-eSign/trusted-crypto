import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {Signer} from "./signer";
import {SignerCollection} from "./signers";
import {Certificate} from "../pki/cert";
import {CertificateCollection} from "../pki/certs";
import {Key} from "../pki/key";

const DEFAULT_DATA_FORMAT = DataFormat.DER;

export enum SignedDataContentType {
    url,
    buffer
}

export interface ISignedDataContent {
    type: SignedDataContentType;
    data: string | Buffer;
}

/**
 * Политики подписи
 */
enum SignedDataPolicy {
    text = 0x1,
    noCertificates = 0x2,
    noContentVerify = 0x4,
    noAttributeVerify = 0x8,
    noSignatures = noAttributeVerify | noContentVerify,
    noIntern = 0x10,
    noSignerCertificateVerify = 0x20,
    noVerify = 0x20,
    detached = 0x40,
    binary = 0x80,
    noAttributes = 0x100,
    noSmimeCap = 0x200,
    noOldMimeType = 0x400,
    crlFEOL = 0x800,
    stream = 0x1000,
    noCrtl = 0x2000,
    partial = 0x4000,
    reuseDigest = 0x8000,
    useKeyId = 0x10000,
    debugDecrypt = 0x20000
}

function EnumGetName(e: any, name: string) {
    for (let i in e) {
        if (i.toString().toLowerCase() === name.toLowerCase()) {
            return { name: i, value: e[i] };
        }
    }
    return null;
}

/**
 * Представление `CMS SignedData`
 */
export class SignedData extends object.BaseObject<native.CMS.SignedData> {

    constructor() {
        super();

        this.handle = new native.CMS.SignedData();
    }

    private content_: ISignedDataContent = null;
    
    /**
     * Возвращает содержимое подписи
     */
    get content(): ISignedDataContent {
        if (!this.content_ && !this.isDetached()) {
            // Извлечь содержимое из подписи
            let buf: Buffer = this.handle.getContent();
            this.content_ = {
                type: SignedDataContentType.buffer,
                data: buf
            }
        }
        return this.content_;
    }

    /**
     * Задает содержимое подписи
     * @param содержимое 
     */
    set content(v: ISignedDataContent) {
        let data;
        if (v.type === SignedDataContentType.url) {
            data = v.data.toString();
        }
        else {
            data = new Buffer(<any>v.data);
        }
        this.handle.setContent(data)
        this.content_ = v;
    }
    
    /**
     * Возвращает политики подписи
     */
    get policies(): Array<string> {
        let p = new Array<string>();

        let flags = this.handle.getFlags();



        for (let i in SignedDataPolicy) {
            if (+i & flags) p.push(SignedDataPolicy[i]);
        }

        return p;
    }

    /**
     * Задает политики подписи
     * @param Набор политик
     */
    set policies(v: string[]) {
        let flags = 0;
        for (let i in v) {
            let flag = EnumGetName(SignedDataPolicy, v[i]);
            if (flag) {
                flags |= +flag.value;
            }
        }

        this.handle.setFlags(flags);
    }

    /**
     * Возвращает true если подпись открепленная
     */
    isDetached(): boolean {
        return this.handle.isDetached();
    }

    /**
     * Возвращает сертификат по индексу
     * @param index Индекс элемента в коллекции
     */
    certificates(index: number): Certificate;
    /**
     * Возвращает коллекцию сертификатов
     */
    certificates(): CertificateCollection;
    certificates(index?: number): any {
        let certs: CertificateCollection = new CertificateCollection(this.handle.getCertificates());
        if (index !== undefined){
            return certs.items(index);
        }
        return certs;
    }

    /**
     * Возвращает подписчика по индексу
     * @param index индекс элемента в коллекции
     */
    signers(index: number): Signer;
    /**
     * Возвращает коллекцию подписчиков
     */
    signers(): SignerCollection;
    signers(index?: number): any {
        let signers = new SignerCollection (this.handle.getSigners());
        if (index !== undefined){
            return signers.items(index);
        }
        return signers;
    }

    /**
     * чтение подписи из файла
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.load(filename, format);
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
    
    /**
    * сохранение подписи в память
    * @param format Формат данных. Опционально. По умолчанию DER
    */
    export(format: DataFormat = DEFAULT_DATA_FORMAT): Buffer {
        return this.handle.export(format);
    }

    /**
     * сохранение подписи в файл
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    save(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.save(filename, format);
    }

    /**
     * создает нового подписчика
     * @param cert Сертификат подписчика
     * @param key Закрытый ключ подписчика
     * @param digestName имя хэш алгоритма
     */
    createSigner(cert: Certificate, key: Key, digestName: string): Signer {
        let signer:any = this.handle.createSigner(cert.handle, key.handle, digestName);
        return new Signer(signer);
    }
    
    /**
     * Проверяет подпись
     * @param certs Коллекция дополнительных сертификатов
     */
    verify(certs?: CertificateCollection): boolean {
        let certs_ = certs;
        if (!certs) {
            certs_ = new CertificateCollection();
        }
            return this.handle.verify(certs_.handle);
    }

    /**
     * Создает подпись
     */
    sign(): void {
        this.handle.sign();
    }
}