otterca
=======

Otter Certificate Authority

This is a simple Certificate Authority. It consists of three
separate but codependent webservices. This separation is overkill
on the smallest sites but it serves "separation of responsibilities"
and allows the most critical services to be deployed on a highly
secured system.

_Registration Authority_ 

The Registration Authority (RA) is responsible for collecting information 
and vetting information about subjects. In this design it is also
responsible for final approval for issuing a certificate.

Operating a general purpose RA is a significant undertaking but
for internal uses it is sufficient to look up entries in an
Active Directory or LDAP server. Even public RAs can provide a
minimal level of authentication by verifying email address,
domain ownership (e.g., by making a nonce visible on the DNS
entry), or successful completion of a small (and possibly reversed)
charge on a credit card. This is why the RA is will usually need
customization.

Upon approval the RA passes the request to the CA for signing.

_Certificate Authority_

The Certificate Authority (CA) is responsible for actually signing
certificates. It is not responsible for vetting subjects or seeking
approval. In this design the CA can immediately sign certificates,
in the wild it's not uncommon for the most critical certificates
to require manual intervention, perhaps even the use of specialized
hardware.

The CA is also responsible for signing CRLs.

The CA is the only webservice that requires cryptographic methods.

The CA gets requests from the RA. For security reasons the CA:

 - should block all inbound traffic except from the RA
 - should use an encrypted channel with mutual authentication
 - require all requests be signed with a known and valid RA certificate.
 - should maintain its own signatures in a secure manner, e.g.,
   in a local keystore.

After signature the CA passes the certificate to the Repository.

_Repository_

The Repository (Repository) is responsible for publishing the
certificates. The required API is defined by various RFCs. (List
to be added).

For security reasons the Repository should:

 - should block management traffic from all sites except the CA.
   (Retrieval traffic needs to be public.)
 - should only store certificates signed by the CA.
