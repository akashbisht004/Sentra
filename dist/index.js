// src/errors/auth-error.ts
var AuthError = class extends Error {
  code;
  constructor(message, code) {
    super(message);
    this.name = "AuthError";
    this.code = code;
  }
};

// src/jwt/refresh-token.ts
import { randomBytes, createHash } from "crypto";
function generateRefreshToken() {
  return randomBytes(32).toString("hex");
}
function hashRefreshToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

// src/jwt/token.ts
import { SignJWT, jwtVerify } from "jose";
async function createToken(userId, secret, tokenExpiry) {
  const key = new TextEncoder().encode(secret);
  const jwt = new SignJWT({ sub: userId });
  jwt.setExpirationTime(tokenExpiry);
  jwt.setIssuedAt();
  jwt.setProtectedHeader({ alg: "HS256" });
  const token = await jwt.sign(key);
  return token;
}
async function verifyToken(token, secret) {
  const key = new TextEncoder().encode(secret);
  let payload;
  try {
    payload = (await jwtVerify(token, key)).payload;
  } catch (error) {
    throw new AuthError("Invalid token", "AUTHENTICATION_FAILED");
  }
  const sub = payload.sub;
  if (typeof sub !== "string") {
    throw new AuthError("Invalid token", "AUTHENTICATION_FAILED");
  }
  return sub;
}

// src/core/auth.ts
import bcrypt from "bcrypt";
import { randomBytes as randomBytes2 } from "crypto";

// src/utils/duration.ts
function durationToDate(duration) {
  const match = duration.match(/^(\d+)([dhm])$/i);
  if (!match) {
    throw new Error("Invalid duration");
  }
  const value = Number(match[1]);
  const unit = match[2].toLowerCase();
  const multipliers = {
    d: 24 * 60 * 60 * 1e3,
    h: 60 * 60 * 1e3,
    m: 60 * 1e3
  };
  const milliseconds = value * multipliers[unit];
  return new Date(Date.now() + milliseconds);
}

// src/core/auth.ts
var Auth = class {
  adapter;
  secret;
  expiry;
  refreshTokenAdapter;
  refreshTokenExpiry;
  hooks;
  constructor(adapter, refreshTokenAdapter, secret, expiry, refreshTokenExpiry, hooks) {
    this.adapter = adapter;
    this.secret = secret;
    this.expiry = expiry;
    this.refreshTokenAdapter = refreshTokenAdapter;
    this.refreshTokenExpiry = refreshTokenExpiry;
    this.hooks = hooks;
  }
  async signUp(data) {
    if (this.hooks?.beforeSignUp) {
      await this.hooks.beforeSignUp({ email: data.email });
    }
    const user = await this.adapter.findUserByEmail(data.email);
    if (user != null) {
      throw new AuthError("User already exists with same mail", "USER_ALREADY_EXISTS");
    }
    const passwordHash = await bcrypt.hash(data.password, 10);
    const newUser = await this.adapter.createUser({
      email: data.email,
      passwordHash
    });
    const result = {
      id: newUser.id,
      email: newUser.email
    };
    if (this.hooks?.afterSignUp) {
      try {
        await this.hooks.afterSignUp(result);
      } catch (error) {
        console.error("after signup hook failed", error);
      }
    }
    return result;
  }
  async login(data) {
    const user = await this.adapter.findUserByEmail(data.email);
    if (user == null) throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");
    if (this.hooks?.beforeLogin) await this.hooks.beforeLogin({ id: user.id, email: user.email });
    const valid = await bcrypt.compare(data.password, user.passwordHash);
    if (!valid) throw new AuthError("Invalid credentials", "INVALID_CREDENTIALS");
    const refreshToken = generateRefreshToken();
    const refreshTokenHash = hashRefreshToken(refreshToken);
    const sessionId = randomBytes2(16).toString("hex");
    const familyId = randomBytes2(16).toString("hex");
    const refreshSession = {
      sessionId,
      familyId,
      userId: user.id,
      refreshTokenHash,
      expiresAt: durationToDate(this.refreshTokenExpiry),
      revokedAt: null
    };
    await this.refreshTokenAdapter.createSession(refreshSession);
    const token = await createToken(user.id, this.secret, this.expiry);
    const result = {
      user: {
        id: user.id,
        email: user.email
      },
      token,
      refreshToken
    };
    if (this.hooks?.afterLogin) {
      try {
        await this.hooks.afterLogin(result.user);
      } catch (error) {
        console.error("After login hook failed", error);
      }
    }
    return result;
  }
  async authenticate(token) {
    const userId = await verifyToken(token, this.secret);
    const user = await this.adapter.findUserById(userId);
    if (user == null) throw new AuthError("Authorization failed", "AUTHENTICATION_FAILED");
    return {
      id: user.id,
      email: user.email
    };
  }
  async refresh(refreshToken) {
    const refreshTokenHash = hashRefreshToken(refreshToken);
    const session = await this.refreshTokenAdapter.findSessionByTokenHash(refreshTokenHash);
    if (session == null) {
      throw new AuthError("Invalid refresh token", "AUTHENTICATION_FAILED");
    }
    if (session.revokedAt !== null) {
      await this.refreshTokenAdapter.revokeFamily(
        session.familyId
      );
      throw new AuthError(
        "Refresh token reuse detected",
        "AUTHENTICATION_FAILED"
      );
    }
    if (session.expiresAt.getTime() <= Date.now()) {
      throw new AuthError("Refresh token has been expired", "AUTHENTICATION_FAILED");
    }
    const user = await this.adapter.findUserById(session.userId);
    if (user == null) {
      throw new AuthError("User no longer exists", "AUTHENTICATION_FAILED");
    }
    const newRefreshToken = generateRefreshToken();
    const newRefreshTokenHash = hashRefreshToken(newRefreshToken);
    const newSessionId = randomBytes2(16).toString("hex");
    const newSession = {
      sessionId: newSessionId,
      familyId: session.familyId,
      userId: user.id,
      refreshTokenHash: newRefreshTokenHash,
      expiresAt: durationToDate(this.refreshTokenExpiry),
      revokedAt: null
    };
    await this.refreshTokenAdapter.revokeSession(session.sessionId);
    await this.refreshTokenAdapter.createSession(newSession);
    const token = await createToken(
      user.id,
      this.secret,
      this.expiry
    );
    return {
      user: {
        id: user.id,
        email: user.email
      },
      token,
      refreshToken: newRefreshToken
    };
  }
};

// src/index.ts
function createAuth(config) {
  let auth = new Auth(config.adapter, config.refreshTokenAdapter, config.secret, config.tokenExpiry ?? "7d", config.refreshTokenExpiry ?? "30d", config.hooks);
  return auth;
}
export {
  AuthError,
  createAuth
};
//# sourceMappingURL=index.js.map