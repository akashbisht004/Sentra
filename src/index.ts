import { AuthConfig } from "./types/auth.js";
import {Auth} from "./core/auth.js";

function createAuth(config: AuthConfig): Auth{

    let auth=new Auth(config.adapter,config.secret);
    return auth;
}

export {createAuth};