// REST API endpoints
// WARNING: This file contains intentional vulnerabilities for demo purposes

pub struct ApiRouter;

impl ApiRouter {
    /// POST /api/v1/payment — process a payment
    pub fn handle_payment(body: &str) -> Result<String, String> {
        // VULN: No input validation on body
        // VULN: No rate limiting
        // VULN: No CSRF protection
        Ok(format!("{{\"status\": \"ok\", \"body\": \"{}\"}}", body))
    }

    /// GET /api/v1/admin/refund/:id — admin refund endpoint
    pub fn handle_admin_refund(payment_id: &str, amount: f64) -> Result<String, String> {
        // VULN: No authentication middleware
        // VULN: No authorization check (should require admin role)
        // VULN: No audit logging
        super::handler::admin_refund(payment_id, amount)
    }

    /// GET /api/v1/user/:id/payments — get user payment history
    pub fn handle_user_payments(user_id: &str) -> Result<String, String> {
        // VULN: No IDOR protection — any user can access any other user's payments
        // Missing: verify_user_owns_resource(authenticated_user, user_id)?
        Ok(format!("{{\"user\": \"{}\", \"payments\": []}}", user_id))
    }

    /// POST /api/v1/webhook — Stripe webhook handler
    pub fn handle_webhook(body: &str, _signature: &str) -> Result<String, String> {
        // VULN: Webhook signature not verified
        // Should validate HMAC-SHA256 with webhook_secret
        // Missing: verify_stripe_signature(body, signature, webhook_secret)?
        Ok(format!("{{\"received\": true}}"))
    }
}
