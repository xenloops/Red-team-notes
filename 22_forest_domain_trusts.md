# Forest and Domain Trusts

A trust relationship enables users in one domain to authenticate and access resources in another domain, by allowing authentication traffic to flow between them using referrals. When a user requests access to a resource outside of the domain, their KDC will return a referral ticket pointing to the KDC of the target domain. The user's TGT is encrypted using an inter-realm trust key (rather than the local krbtgt), often called an inter-realm TGT. The foreign domain decrypts this ticket, recovers the user's TGT and decides whether they should be granted access. Trusts can be:

* **One-way** allows principals in the trusted domain to access resources in the trusting domain, but not vice versa.
* **Two-way** allows users in each domain to access resources in the other.
* **Transitive** is a trust that can be chained, e.g. (domain) A trusts B and B trusts C, then A trusts C implicitly.
* **Intransitive** is trust is not implied.

The direction of trust is the opposite to the direction of access.

## Parent/Child

When a child domain is added to a forest, it automatically creates a transitive, two-way trust with its parent. (In the lab: dev.cyberbotic.io is a child domain of cyberbotic.io.)

    beacon> getuid
    [*] You are DEV\bfarmer
    beacon> powershell Get-DomainTrust
    SourceName      : dev.cyberbotic.io
    TargetName      : cyberbotic.io


