import {BaseObject} from "../lib/object";
import * as trusted from "../lib/trusted";

export interface IPkiItem {
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
    keyId?: string;
    hash: string;
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
}

export interface IProvider {
    type: string;
    items: IPkiItem[];
    find(filter: IFilter): IPkiItem[];
    toJSON();
    fromJSON();
}

export declare abstract class Provider implements IProvider {
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
    static fromJSON(): IProvider;
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
    constructor();

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
    providers: IProvider[];
}