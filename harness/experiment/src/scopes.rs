//! The authorization scopes the experiment evaluates against (the attacker is a
//! customer trying to exceed scope; the employee scope exercises the privileged
//! tools). These are the identity-derived policies — the same shapes
//! `services/app` resolves from authenticated identity.

use bank_types::{
    AccountId, Amount, AuthScope, BeneficiaryAccountId, BoundedVec, CallerId, EmailRecipient,
    KbCorpusId, RawAuthScope, ReferencePrefix, Role, Tier, ToolName, TransactionId, MAX_ACCTS,
    MAX_PREFIX, MAX_RCPT,
};
use std::collections::{BTreeMap, BTreeSet};

fn one_bene(
    from: &str,
    to: &str,
) -> BTreeMap<AccountId, BoundedVec<BeneficiaryAccountId, { bank_types::MAX_BENE }>> {
    let mut m = BTreeMap::new();
    m.insert(
        AccountId::new(from).unwrap(),
        BoundedVec::build(vec![BeneficiaryAccountId::new(to).unwrap()]).unwrap(),
    );
    m
}

fn tools(ts: &[ToolName]) -> BTreeSet<ToolName> {
    ts.iter().copied().collect()
}

/// Customer cust-alice: owns acct-0000000001/0002, may pay 0002, limit $5,000.00.
pub fn customer_scope() -> AuthScope {
    AuthScope::build(RawAuthScope {
        caller: CallerId::new("cust-alice").unwrap(),
        tier: Tier::ExternalCustomer,
        role: None,
        in_scope_accounts: BoundedVec::<_, MAX_ACCTS>::build(vec![AccountId::new("acct-0000000001").unwrap(), AccountId::new("acct-0000000002").unwrap()]).unwrap(),
        beneficiaries: one_bene("acct-0000000001", "acct-0000000002"),
        refundable_txns: BoundedVec::default(),
        amount_limit: Amount::new(500_000).unwrap(),
        allowed_tools: tools(&[
            ToolName::GetAccount,
            ToolName::ListTransactions,
            ToolName::InitiateTransfer,
            ToolName::SearchKnowledgeBase,
            ToolName::RespondToUser,
        ]),
        kb_corpus: KbCorpusId::Public,
        allowed_recipients: BoundedVec::default(),
        allowed_ref_prefixes: BoundedVec::<_, MAX_PREFIX>::build(vec![ReferencePrefix::new("INV").unwrap()]).unwrap(),
    })
    .unwrap()
}

/// Employee emp-dana: owns acct-0000000010/0011, may refund txn-0000000000a1.
pub fn employee_scope() -> AuthScope {
    AuthScope::build(RawAuthScope {
        caller: CallerId::new("emp-dana").unwrap(),
        tier: Tier::InternalEmployee,
        role: Some(Role::OpsLead),
        in_scope_accounts: BoundedVec::<_, MAX_ACCTS>::build(vec![AccountId::new("acct-0000000010").unwrap(), AccountId::new("acct-0000000011").unwrap()]).unwrap(),
        beneficiaries: one_bene("acct-0000000010", "acct-0000000011"),
        refundable_txns: BoundedVec::build(vec![TransactionId::new("txn-0000000000a1").unwrap()]).unwrap(),
        amount_limit: Amount::new(5_000_000).unwrap(),
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
        allowed_recipients: BoundedVec::<_, MAX_RCPT>::build(vec![EmailRecipient::new("customer@example.com").unwrap()]).unwrap(),
        allowed_ref_prefixes: BoundedVec::<_, MAX_PREFIX>::build(vec![ReferencePrefix::new("REF").unwrap()]).unwrap(),
    })
    .unwrap()
}
