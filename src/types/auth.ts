import { User, UserAdapter } from "./adapter.js";

export interface AuthConfig{
    adapter: UserAdapter;
    secret: string;
    tokenExpiry?: string;
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
}