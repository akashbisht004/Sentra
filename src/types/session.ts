export interface RefreshSession{
    sessionId: string;
    familyId: string;
    userId: string;
    refreshTokenHash: string;
    expiresAt: Date;
    revokedAt: Date|null;
}
