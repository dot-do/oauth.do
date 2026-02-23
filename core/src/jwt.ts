// Re-export JWT from id.org.ai/oauth
export { SigningKeyManager, signJWT, signAccessToken, verifyJWTWithKeyManager, serializeSigningKey, deserializeSigningKey } from 'id.org.ai/oauth'
export { verifyJWT, decodeJWT, isJWTExpired, clearJWKSCache } from 'id.org.ai/oauth'
