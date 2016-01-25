import {native} from "../native";
import {BaseObject} from "../object";
import {DataFormat} from "../data_format";
import {Signer} from "./signer";
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
 * Представление `CMS SignedData`
 */
export class SignedData extends BaseObject {

    constructor() {
        super();

        this.handle = new native.CMS.SignedData();
    }

    private content_: ISignedDataContent = null;

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

    isDetached(): boolean {
        return this.handle.isDetached();
    }

    certificates(index: number): Buffer;
    certificates(): Array<Certificate>;
    certificates(index?: number): any {
        let certs = this.handle.getCertificates();
        // certs.items = function(index: number): Certificate { return this[index]; }
        for (let i in certs) {
            let cert = new Certificate();
            cert.handle = certs[i];
            certs[i] = cert;
        }
        if (index === undefined) {
            return certs;
        }
        else {
            return certs[index];
        }
    }

    signers(index: number): Buffer;
    signers(): Array<Signer>;
    signers(index?: number): any {
        let signers = this.handle.getSigners();
        // signers.items = function(index: number): Signer { return this[index]; }
        for (let i in signers) {
            signers[i] = new Signer(signers[i]);
        }
        if (index === undefined) {
            return signers;
        }
        else {
            return signers[index];
        }
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

    createSigner(cert: Certificate, key: Key, digestName: string, flags?: number): Signer {
        var nsigner = this.handle.createSigner(cert.handle, key.handle, digestName, flags);
        return new Signer(nsigner);
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