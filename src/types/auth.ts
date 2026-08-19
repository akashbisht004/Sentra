import { User, UserAdapter,RefreshTokenAdapter } from "./adapter.js";

export interface AuthConfig{
    adapter: UserAdapter;
    refreshTokenAdapter: RefreshTokenAdapter;
    secret: string;
    tokenExpiry?: string;
    refreshTokenExpiry?: string;
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