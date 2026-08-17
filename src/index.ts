import { AuthConfig } from "./types/auth.js";
import {Auth} from "./core/auth.js";
import { AuthError } from "./errors/auth-error.js";
import type { AuthErrorCode } from "./errors/auth-error.js";

function createAuth(config: AuthConfig): Auth{

    let auth=new Auth(config.adapter,config.secret);
    return auth;
}

export {createAuth, AuthError};
export type {AuthErrorCode};