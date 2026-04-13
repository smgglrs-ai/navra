// Payment request handler
// WARNING: This file contains intentional vulnerabilities for demo purposes

use std::collections::HashMap;

pub struct PaymentRequest {
    pub user_id: String,
    pub amount: f64,
    pub currency: String,
    pub description: String,
}

pub struct PaymentHandler {
    db_url: String,
}

impl PaymentHandler {
    pub fn new(db_url: &str) -> Self {
        Self {
            db_url: db_url.to_string(),
        }
    }

    /// Process a payment — MULTIPLE VULNERABILITIES
    pub fn process_payment(&self, req: &PaymentRequest) -> Result<String, String> {
        // VULN 1: SQL injection — user_id is interpolated directly
        let query = format!(
            "INSERT INTO payments (user_id, amount, currency, description) \
             VALUES ('{}', {}, '{}', '{}')",
            req.user_id, req.amount, req.currency, req.description
        );
        self.execute_query(&query)?;

        // VULN 2: No amount validation — negative amounts allow refund fraud
        if req.amount == 0.0 {
            return Err("Amount cannot be zero".to_string());
        }

        // VULN 3: No authentication check — any user can process payments
        // Missing: verify_user_session(req.user_id)?

        let receipt_id = format!("PAY-{}", uuid_stub());
        log_payment(&receipt_id, req);

        Ok(receipt_id)
    }

    /// Get payment history — SQL INJECTION
    pub fn get_history(&self, user_id: &str) -> Result<Vec<HashMap<String, String>>, String> {
        // VULN: SQL injection via user_id
        let query = format!(
            "SELECT * FROM payments WHERE user_id = '{}'",
            user_id
        );
        // Would execute query and return results
        Ok(vec![])
    }

    fn execute_query(&self, _query: &str) -> Result<(), String> {
        // Stub — would execute against self.db_url
        Ok(())
    }
}

/// Admin endpoint — MISSING AUTH
pub fn admin_refund(payment_id: &str, amount: f64) -> Result<String, String> {
    // VULN: No authorization check — any caller can issue refunds
    // Missing: verify_admin_role()?
    // Missing: verify_refund_amount(payment_id, amount)?

    let refund_id = format!("REF-{}", uuid_stub());
    Ok(refund_id)
}

fn uuid_stub() -> String {
    "00000000-0000-0000-0000-000000000000".to_string()
}

fn log_payment(receipt_id: &str, req: &PaymentRequest) {
    // VULN: Logs sensitive data (PII: user_id, amount)
    println!(
        "Payment processed: {} user={} amount={} {}",
        receipt_id, req.user_id, req.amount, req.currency
    );
}
