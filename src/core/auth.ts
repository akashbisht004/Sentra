import { AuthError } from "../errors/auth-error.js";
import { createToken, verifyToken } from "../jwt/token.js";
import type { UserAdapter, User } from "../types/adapter.js";
import type { AuthResult, LoginData, SignUpData } from "../types/auth.js";
import bcrypt from "bcrypt";

class Auth {
    private adapter: UserAdapter;
    private secret: string;
    private expiry: string;

    constructor(adapter: UserAdapter, secret: string, expiry: string) {
        this.adapter = adapter;
        this.secret = secret;
        this.expiry = expiry;
    }

    async signUp(data: SignUpData): Promise<User> {
        const user = await this.adapter.findUserByEmail(data.email);

        if (user != null) {
            throw new AuthError("User already exists with same mail", "USER_ALREADY_EXISTS");
        }

        const passwordHash = await bcrypt.hash(data.password, 10);

        const newUser = await this.adapter.createUser({
            email: data.email,
            passwordHash
        });

        return {
            id: newUser.id,
            email: newUser.email
        };
    }

    async login(data: LoginData): Promise<AuthResult> {
        const user = await this.adapter.findUserByEmail(data.email);
        if (user == null) throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");

        const valid = await bcrypt.compare(data.password, user.passwordHash);

        if (!valid) throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");

        const token = await createToken(user.id, this.secret, this.expiry)

        return {
            user: {
                id: user.id,
                email: user.email,
            }, token
        };

    }

    async authenticate(token: string): Promise<User> {
        const userId = await verifyToken(token, this.secret);
        const user = await this.adapter.findUserById(userId);
        if (user == null) throw new AuthError("Authorization failed", "AUTHENTICATION_FAILED");

        return {
            id: user.id,
            email: user.email
        };
    }

}
export { Auth };

