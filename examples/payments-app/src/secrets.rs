// Internal secrets and cryptographic material
// This file should be Confidential — IFC should prevent leakage

/// Encryption key for payment tokens (AES-256-GCM)
pub const PAYMENT_TOKEN_KEY: &str = "a1b2c3d4e5f6789012345678901234567890abcdef123456";

/// HMAC signing key for webhook verification
pub const WEBHOOK_HMAC_KEY: &str = "hmac-secret-key-do-not-share-with-anyone";

/// Database master password (used for migrations)
pub const DB_MASTER_PASSWORD: &str = "super-secret-master-password-2024!";

/// PCI DSS encryption key for card data at rest
pub const CARD_ENCRYPTION_KEY: &str = "pci-dss-key-4096-bit-equivalent";

/// Internal service-to-service auth token
pub const INTERNAL_SERVICE_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.internal-service-token";
