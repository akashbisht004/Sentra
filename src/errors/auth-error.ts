
export type AuthErrorCode =
    | "USER_ALREADY_EXISTS"
    | "INVALID_CREDENTIALS";


export class AuthError extends Error {
    public code: AuthErrorCode;

    constructor(message:string, code: AuthErrorCode) {
        super(message);
        this.name="AuthError";
        this.code = code;
    }
}