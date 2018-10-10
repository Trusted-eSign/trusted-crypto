import {BaseObject} from "../lib/object";
import * as trusted from "../lib/trusted";

export interface IPkiItem extends IPkiCrl, IPkiCertificate, IPkiRequest, IPkiKey{
    /**
     * DER | PEM
     */
    format: string;
    /**
     * CRL | CERTIFICATE | KEY | REQUEST
     */
    type: string;
    uri: string;
    provider: string;
    categoty: string;
    hash: string;
}

export interface IPkiKey{
    encrypted?: boolean;
    hash: string;
}

export interface IPkiCrl {
    authorityKeyid?: string;
    crlNumber?: string;
    issuerName?: string;
    issuerFriendlyName?: string;
    lastUpdate?: Date;
    nextUpdate?: Date;
    hash: string; // thumbprint SHA1
}

export interface IPkiRequest{
    subjectName?: string;
    subjectFriendlyName?: string;
    key?: string; // thumbprint ket SHA1
    hash: string; // thumbprint SHA1
}

export interface IPkiCertificate{
    subjectName?: string;
    subjectFriendlyName?: string;
    issuerName?: string;
    issuerFriendlyName?: string;
    notAfter?: Date;
    notBefore?: Date;
    serial?: string;
    key?: string; // thumbprint ket SHA1
    hash: string; // thumbprint SHA1
}

export interface IFilter {
    /**
     * PkiItem
     * CRL | CERTIFICATE | KEY | REQUEST
     */
    type?: string[];
    /**
     * Provider
     * SYSTEM, MICROSOFT, CRYPTOPRO, TSL, PKCS11, TRUSTEDNET
     */
    provider?: string[];
    /**
     * MY, OTHER, CA, TRUSTED
     */
    category?: string[];
    hash?: string;
    subjectName?: string;
    subjectFriendlyName?: string;
    issuerName?: string;
    issuerFriendlyName?: string;
    isValid?: boolean;
    serial?: string;
}

export declare abstract class Provider {
    type: string;

    /**
     * Возвращает полный список хранимых элементов
     */
    items: IPkiItem[];

    /**
     * Возвращает коллекцию элементов по заданным критериям
     */
    find(filter: IFilter): IPkiItem[];
    toJSON();
    static fromJSON(): Provider;
    fromJSON();
}

export declare class ProviderSystem extends Provider {
    constructor(folder: string);
}

export declare class ProviderMicrosoft extends Provider {
    constructor();
}

export declare class ProviderTSL extends Provider {
    constructor(url: string);
}

export declare class PkiStore {
    constructor(json: string);

    cash: CashJson;

    items: IPkiItem[];
    /**
     * Возвращает набор элементов по фильтру
     * - если фильтр пустой, возвращает все элементы
     */
    find(filter?: IFilter): IPkiItem[];
    /**
     * ?
     */
    find(item: IPkiItem, filter: IFilter): IPkiItem[];
    /**
     * Возвращает ключ по фильтру
     * - фильтр задается относительно элементов, которые могут быть связаны с ключом
     */
    findKey(filter: IFilter): IPkiItem;

    /**
     * Возвращает объект из структуры
     */
    getItem(item: IPkiItem): any;

    /**
     * Коллекция провайдеров
     */
    providers: Provider[];
}

export declare class CashJson {
    filenName: string;
    contructor(fileName: string);
    save(fileName: string);
    load(fileName: string);
    export(): IPkiItem[];
    import(items: IPkiItem[]);
}
