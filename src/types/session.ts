export interface RefreshSession{
    sessionId: string;
    userId: string;
    refreshTokenHash: string;
    expiresAt: Date;
    revokedAt: Date|null;
}
