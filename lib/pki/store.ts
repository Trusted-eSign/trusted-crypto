import * as fs from "fs";

import {Certificate} from "./cert";

export class Store {

    load(dirname: string) {
        if (!(fs.existsSync(dirname))) {
            throw new Error(`Directory '${dirname}' is not found`);
        }
        let stat = fs.statSync(dirname);
        if (!stat.isDirectory){
            throw new Error(`Path '${dirname}' must be a directory`);
        }
    }
    /*
    static load(dirname: string): Store {

    }
    */

}