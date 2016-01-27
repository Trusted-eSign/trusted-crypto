export interface IBaseObject{
    handle;
}

export class BaseObject <T> implements IBaseObject{
	public handle: T;

    static wrap<TIn, TOut extends IBaseObject>(obj: TIn): TOut{
        let cast_obj = obj;
        if (!obj){
            throw TypeError("BaseObjectCheck::Wrong incoming object for wrap function");
        }
        
        let new_obj = new this();
        new_obj.handle = obj;
        return <TOut> new_obj;
    }
}