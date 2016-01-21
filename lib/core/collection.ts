export interface ICollection{
    length: number;
    items(index:number): any
}

export interface ICollectionWrite extends ICollection{
    push(item: any);
    pop();
    removeAt(index: number);
}