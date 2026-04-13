// Payment gateway configuration
// WARNING: This file contains intentional vulnerabilities for demo purposes

pub struct PaymentConfig {
    pub gateway_url: String,
    pub api_key: String,
    pub webhook_secret: String,
    pub db_connection: String,
}

impl PaymentConfig {
    pub fn load() -> Self {
        Self {
            gateway_url: "https://api.stripe.com/v1".to_string(),
            // VULN: Hardcoded API key (should use environment variable)
            api_key: "sk_live_4eC39HqLyjWDarjtT1zdp7dc".to_string(),
            // VULN: Hardcoded webhook secret
            webhook_secret: "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2lg0LY4".to_string(),
            // VULN: Password in connection string
            db_connection: "postgres://payments:P@ssw0rd!@db.internal:5432/payments".to_string(),
        }
    }
}
