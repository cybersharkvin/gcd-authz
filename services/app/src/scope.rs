//! Identity → [`AuthScope`] resolution at the trust boundary.
//!
//! The scope is derived from the **authenticated caller** (here, a static
//! identity registry — the policy printed verbatim), never from request content
//! or model output. This is the edge that turns "who is calling" into "what is
//! authorized"; the compiled grammar and the executor backstop both flow from it.

use bank_types::{
    AccountId, Amount, AuthScope, BeneficiaryAccountId, BoundedVec, CallerId, EmailRecipient,
    KbCorpusId, RawAuthScope, ReferencePrefix, Role, ScopeError, Tier, ToolName, TransactionId,
    ValidationError, MAX_ACCTS, MAX_BENE, MAX_PREFIX, MAX_RCPT,
};
use std::collections::{BTreeMap, BTreeSet};

/// Failure resolving an authenticated identity to a scope.
#[derive(Debug, thiserror::Error)]
pub enum ScopeResolveError {
    #[error("unknown caller: {0}")]
    UnknownCaller(String),
    #[error("malformed policy value: {0}")]
    Value(#[from] ValidationError),
    #[error("policy violates scope invariant: {0}")]
    Scope(#[from] ScopeError),
}

/// The callers this back-office serves (the identity registry).
pub const KNOWN_CALLERS: &[&str] = &["cust-alice", "cust-bob", "emp-dana"];

/// Resolve an authenticated caller id to its authorization scope.
pub fn resolve_scope(caller: &CallerId) -> Result<AuthScope, ScopeResolveError> {
    let raw = match caller.as_str() {
        "cust-alice" => customer(caller, "acct-0000000001", "acct-0000000002")?,
        "cust-bob" => customer(caller, "acct-0000000003", "acct-0000000004")?,
        "emp-dana" => employee(caller)?,
        other => return Err(ScopeResolveError::UnknownCaller(other.to_string())),
    };
    Ok(AuthScope::build(raw)?)
}

fn bene(
    from: &str,
    to: &str,
) -> Result<BTreeMap<AccountId, BoundedVec<BeneficiaryAccountId, MAX_BENE>>, ValidationError> {
    let mut m = BTreeMap::new();
    m.insert(AccountId::new(from)?, BoundedVec::build(vec![BeneficiaryAccountId::new(to)?])?);
    Ok(m)
}

fn tools(ts: &[ToolName]) -> BTreeSet<ToolName> {
    ts.iter().copied().collect()
}

/// A customer owning `a1` (checking) and `a2` (savings); may pay `a2`.
fn customer(caller: &CallerId, a1: &str, a2: &str) -> Result<RawAuthScope, ValidationError> {
    Ok(RawAuthScope {
        caller: caller.clone(),
        tier: Tier::ExternalCustomer,
        role: None,
        in_scope_accounts: BoundedVec::<_, MAX_ACCTS>::build(vec![AccountId::new(a1)?, AccountId::new(a2)?])?,
        beneficiaries: bene(a1, a2)?,
        refundable_txns: BoundedVec::default(),
        amount_limit: Amount::new(500_000)?,
        allowed_tools: tools(&[
            ToolName::GetAccount,
            ToolName::ListTransactions,
            ToolName::InitiateTransfer,
            ToolName::SearchKnowledgeBase,
            ToolName::RespondToUser,
        ]),
        kb_corpus: KbCorpusId::Public,
        allowed_recipients: BoundedVec::default(),
        allowed_ref_prefixes: BoundedVec::<_, MAX_PREFIX>::build(vec![ReferencePrefix::new("INV")?])?,
    })
}

/// The ops employee (acct-0000000010/0011); may refund a known transaction and
/// email customers.
fn employee(caller: &CallerId) -> Result<RawAuthScope, ValidationError> {
    Ok(RawAuthScope {
        caller: caller.clone(),
        tier: Tier::InternalEmployee,
        role: Some(Role::OpsLead),
        in_scope_accounts: BoundedVec::<_, MAX_ACCTS>::build(vec![
            AccountId::new("acct-0000000010")?,
            AccountId::new("acct-0000000011")?,
        ])?,
        beneficiaries: bene("acct-0000000010", "acct-0000000011")?,
        refundable_txns: BoundedVec::build(vec![TransactionId::new("txn-0000000000a1")?])?,
        amount_limit: Amount::new(5_000_000)?,
        allowed_tools: tools(&[
            ToolName::GetAccount,
            ToolName::ListTransactions,
            ToolName::InitiateTransfer,
            ToolName::IssueRefund,
            ToolName::SearchKnowledgeBase,
            ToolName::SendEmail,
            ToolName::RespondToUser,
        ]),
        kb_corpus: KbCorpusId::Internal,
        allowed_recipients: BoundedVec::<_, MAX_RCPT>::build(vec![EmailRecipient::new("customer@example.com")?])?,
        allowed_ref_prefixes: BoundedVec::<_, MAX_PREFIX>::build(vec![ReferencePrefix::new("REF")?])?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_customer() {
        let s = resolve_scope(&CallerId::new("cust-alice").unwrap()).unwrap();
        assert!(s.tier() == Tier::ExternalCustomer && s.owns_account(&AccountId::new("acct-0000000001").unwrap()));
    }

    #[test]
    fn resolves_employee_with_role() {
        let s = resolve_scope(&CallerId::new("emp-dana").unwrap()).unwrap();
        assert!(s.tier() == Tier::InternalEmployee && s.role() == Some(Role::OpsLead));
    }

    #[test]
    fn rejects_unknown_caller() {
        assert!(matches!(resolve_scope(&CallerId::new("mallory").unwrap()), Err(ScopeResolveError::UnknownCaller(_))));
    }
}
