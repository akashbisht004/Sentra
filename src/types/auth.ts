import { UserAdapter } from "./adapter.js";

export interface AuthConfig{
    adapter: UserAdapter;
    secret: string;
}