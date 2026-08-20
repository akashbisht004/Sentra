import type { User } from "./adapter.js";
import { AuthResult } from "./auth.js";

export interface AuthHooks {
    beforeLogin?: (
        user: User
    ) => Promise<void>;

    afterLogin?: (
        user: User
    ) => Promise<void>;
}
