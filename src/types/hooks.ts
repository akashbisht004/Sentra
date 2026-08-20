import type { User } from "./adapter.js";

export interface AuthHooks {
    beforeLogin?: (
        user: User
    ) => Promise<void>;

    afterLogin?: (
        user: User
    ) => Promise<void>;

    beforeSignUp?: (
        data: SignUpHookData
    ) => Promise<void>;

    afterSignUp?: (
        user:User
    ) => Promise<void>;

}

export interface SignUpHookData {
    email: string;
}