import { UserAdapter } from "./adapter.js";

export interface AuthConfig{
    adapter: UserAdapter;
    secret: string;
}

export interface SignUpData{
    email: string;
    password: string;
}

export interface LoginData{
    email: string;
    password: string;
}