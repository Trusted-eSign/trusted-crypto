export interface ICollection {
    /**
     * возвращает количество элементов в коллекции
     */
    length: number;
    /**
     * возвращает элемент коллекции по заданному индексу
     * @param index индекс элемента в коллекции [0..n]
     */
    items(index: number): any;
}

export interface ICollectionWrite extends ICollection {
    push(item: any): void;
    pop(): void;
    removeAt(index: number): void;
}
