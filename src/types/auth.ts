import type { User, UserAdapter,RefreshTokenAdapter } from "./adapter.js";
import type { AuthHooks } from "./hooks.js";

export interface AuthConfig{
    adapter: UserAdapter;
    refreshTokenAdapter: RefreshTokenAdapter;
    secret: string;
    tokenExpiry?: string;
    refreshTokenExpiry?: string;
    hooks?: AuthHooks;
}

export interface SignUpData{
    email: string;
    password: string;
}

export interface LoginData{
    email: string;
    password: string;
}  

export interface AuthResult{
    user: User;
    token: string;
    refreshToken: string;
}