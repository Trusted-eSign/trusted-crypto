namespace trusted {
    export interface IBaseObject {
        handle;
    }

    export class BaseObject<T> implements IBaseObject {
        public static wrap<TIn, TOut extends IBaseObject>(obj: TIn): TOut {
            if (!obj) {
                throw TypeError("BaseObjectCheck::Wrong incoming object for wrap function");
            }

            const newObj: any = new this();
            newObj.handle = obj;
            return newObj as TOut;
        }

        public handle: T;
    }
}
