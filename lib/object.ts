export class BaseObject{
	public handle: any;
    
    static nativeCreate(handle: any): BaseObject{
        let obj = new this();
        obj.handle = handle;
        
        return obj;
    }
}