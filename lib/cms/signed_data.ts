/* tslint:disable:no-bitwise */

import * as native from "../native";
import * as object from "../object";
import {DataFormat} from "../data_format";
import {Signer} from "./signer";
import {SignerCollection} from "./signers";
import {Certificate} from "../pki/cert";
import {CertificateCollection} from "../pki/certs";
import {Key} from "../pki/key";

const DEFAULT_DATA_FORMAT: DataFormat = DataFormat.DER;

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

function EnumGetName(e: any, name: string): any {
    "use strict";

    for (let i in e) {
        if (i.toString().toLowerCase() === name.toLowerCase()) {
            return { name: i, value: e[i] };
        }
    }
    return undefined;
}

/**
 * Представление `CMS SignedData`
 */
export class SignedData extends object.BaseObject<native.CMS.SignedData> {
    /**
     * чтение подписи из файла
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    public static load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): SignedData {
        let cms: SignedData = new SignedData();
        cms.handle.load(filename, format);
        return cms;
    }

    /**
     * чтение подписи из памяти
     * @param buffer Буфер памяти
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    public static import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): SignedData {
        let cms: SignedData = new SignedData();
        cms.handle.import(buffer, format);
        return cms;
    }

    private prContent: ISignedDataContent = undefined;

    constructor() {
        super();

        this.handle = new native.CMS.SignedData();
    }

    /**
     * Возвращает содержимое подписи
     */
    get content(): ISignedDataContent {
        if (!this.prContent && !this.isDetached()) {
            // Извлечь содержимое из подписи
            let buf: Buffer = this.handle.getContent();
            this.prContent = {
                data: buf,
                type: SignedDataContentType.buffer,
            };
        }
        return this.prContent;
    }

    /**
     * Задает содержимое подписи
     * @param содержимое
     */
    set content(v: ISignedDataContent) {
        let data: any;
        if (v.type === SignedDataContentType.url) {
            data = v.data.toString();
        } else {
            data = new Buffer(<any> v.data);
        }
        this.handle.setContent(data);
        this.prContent = v;
    }

    /**
     * Возвращает политики подписи
     */
    get policies(): Array<string> {
        let p: Array<string> = new Array<string>();

        let flags: number = this.handle.getFlags();

        for (let i in SignedDataPolicy) {
            if (+i & flags) {
                p.push(SignedDataPolicy[i]);
            }
        }

        return p;
    }

    /**
     * Задает политики подписи
     * @param Набор политик
     */
    set policies(v: string[]) {
        let flags: number = 0;
        for (let i: number = 0; i < v.length; i++) {
            let flag: any = EnumGetName(SignedDataPolicy, v[i]);
            if (flag) {
                flags |= +flag.value;
            }
        }

        this.handle.setFlags(flags);
    }

    /**
     * Возвращает true если подпись открепленная
     */
    public isDetached(): boolean {
        return this.handle.isDetached();
    }

    /**
     * Возвращает сертификат по индексу
     * @param index Индекс элемента в коллекции
     */
    public certificates(index: number): Certificate;
    /**
     * Возвращает коллекцию сертификатов
     */
    public certificates(): CertificateCollection;
    public certificates(index?: number): any {
        let certs: CertificateCollection = new CertificateCollection(this.handle.getCertificates());
        if (index !== undefined) {
            return certs.items(index);
        }
        return certs;
    }

    /**
     * Возвращает подписчика по индексу
     * @param index индекс элемента в коллекции
     */
    public signers(index: number): Signer;
    /**
     * Возвращает коллекцию подписчиков
     */
    public signers(): SignerCollection;
    public signers(index?: number): any {
        let signers: SignerCollection = new SignerCollection (this.handle.getSigners());
        if (index !== undefined) {
            return signers.items(index);
        }
        return signers;
    }

    /**
     * чтение подписи из файла
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    public load(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.load(filename, format);
    }

    /**
     * чтение подписи из памяти
     * @param buffer Буфер памяти
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    public import(buffer: Buffer, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.import(buffer, format);
    }

    /**
     * сохранение подписи в память
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    public export(format: DataFormat = DEFAULT_DATA_FORMAT): Buffer {
        return this.handle.export(format);
    }

    /**
     * сохранение подписи в файл
     * @param filename Путь к файлу
     * @param format Формат данных. Опционально. По умолчанию DER
     */
    public save(filename: string, format: DataFormat = DEFAULT_DATA_FORMAT): void {
        this.handle.save(filename, format);
    }

    /**
     * создает нового подписчика
     * @param cert Сертификат подписчика
     * @param key Закрытый ключ подписчика
     * @param digestName имя хэш алгоритма
     */
    public createSigner(cert: Certificate, key: Key, digestName: string): Signer {
        let signer: any = this.handle.createSigner(cert.handle, key.handle, digestName);
        return new Signer(signer);
    }

    /**
     * Проверяет подпись
     * @param certs Коллекция дополнительных сертификатов
     */
    public verify(certs?: CertificateCollection): boolean {
        let certsD: CertificateCollection  = certs;
        if (!certs) {
            certsD = new CertificateCollection();
        }
        return this.handle.verify(certsD.handle);
    }

    /**
     * Создает подпись
     */
    public sign(): void {
        this.handle.sign();
    }
}
