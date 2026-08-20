interface RefreshSession {
    sessionId: string;
    familyId: string;
    userId: string;
    refreshTokenHash: string;
    expiresAt: Date;
    revokedAt: Date | null;
}

interface User {
    id: string;
    email: string;
}
interface UserRecord extends User {
    passwordHash: string;
}
interface CreateUser {
    email: string;
    passwordHash: string;
}
interface UserAdapter {
    findUserByEmail(email: string): Promise<UserRecord | null>;
    createUser(data: CreateUser): Promise<UserRecord>;
    findUserById(userId: string): Promise<UserRecord | null>;
}
interface RefreshTokenAdapter {
    findSessionByTokenHash(refreshTokenHash: string): Promise<RefreshSession | null>;
    revokeSession(sessionId: string): Promise<void>;
    createSession(session: RefreshSession): Promise<RefreshSession>;
    revokeFamily(familyId: string): Promise<void>;
}

interface AuthHooks {
    beforeLogin?: (user: User) => Promise<void>;
    afterLogin?: (user: User) => Promise<void>;
    beforeSignUp?: (data: SignUpHookData) => Promise<void>;
    afterSignUp?: (user: User) => Promise<void>;
}
interface SignUpHookData {
    email: string;
}

interface AuthConfig {
    adapter: UserAdapter;
    refreshTokenAdapter: RefreshTokenAdapter;
    secret: string;
    tokenExpiry?: string;
    refreshTokenExpiry?: string;
    hooks?: AuthHooks;
}
interface SignUpData {
    email: string;
    password: string;
}
interface LoginData {
    email: string;
    password: string;
}
interface AuthResult {
    user: User;
    token: string;
    refreshToken: string;
}

declare class Auth {
    private adapter;
    private secret;
    private expiry;
    private refreshTokenAdapter;
    private refreshTokenExpiry;
    private hooks?;
    constructor(adapter: UserAdapter, refreshTokenAdapter: RefreshTokenAdapter, secret: string, expiry: string, refreshTokenExpiry: string, hooks?: AuthHooks);
    signUp(data: SignUpData): Promise<User>;
    login(data: LoginData): Promise<AuthResult>;
    authenticate(token: string): Promise<User>;
    refresh(refreshToken: string): Promise<AuthResult>;
}

type AuthErrorCode = "USER_ALREADY_EXISTS" | "INVALID_CREDENTIALS" | "AUTHENTICATION_FAILED";
declare class AuthError extends Error {
    code: AuthErrorCode;
    constructor(message: string, code: AuthErrorCode);
}

declare function createAuth(config: AuthConfig): Auth;

export { AuthError, type AuthErrorCode, createAuth };
