export interface ICollection {
    /**
     * Collection length
     *
     * @type {number}
     * @memberOf ICollection
     */
    length: number;

    /**
     * Return element by index from collection
     *
     * @param {number} index value of [0..n]
     * @returns {*}
     *
     * @memberOf ICollection
     */
    items(index: number): any;
}

export interface ICollectionWrite extends ICollection {
    /**
     * Add new element to collection
     *
     * @param {*} item
     *
     * @memberOf ICollectionWrite
     */
    push(item: any): void;

    /**
     * Remove last element from collection
     *
     *
     * @memberOf ICollectionWrite
     */
    pop(): void;

    /**
     * Remove element by index from collection
     *
     * @param {number} index
     *
     * @memberOf ICollectionWrite
     */
    removeAt(index: number): void;
}
