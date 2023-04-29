# Federated Auth Network

The notion of an "authentication network" assumes that numerous participants
are involved in the authentication process. Federation allows this network to
function without any party beholden to the other to function; notably, an
authenticating service does not rely on the authenticating agent or the
authenticating user being a reliable resource to perform its function. This
specification intends to provide a way for users to take control of their
authentication steps, while not preventing a trusted entity from being able to
provide this service for others. It does this in a way that does not preclude
one or the other, allowing them to work in harmony to achieve the same goal.

In the same stroke, the innate nature of the protocol stands to drastically
increase the security of websites as a whole, as this method does not require
any notion of a password or passphrase to be stored, instead relying on strong
encryption to provide authentication in all circumstances, reducing the attack
potential of a database compromise. To further this goal, it is also not a
requirement for the implementing website to store any key material at all,
making wide-scale authentication compromise virtually impossible.

## License

This specification is &copy; 2023 Erik Hollensbe <erik@hollensbe.org>, and is
licensed as Creative Commons
[CC-BY-SA](https://creativecommons.org/licenses/by-sa/4.0/) and should not be
replicated or modified without attribution to the author.

The implementation in this repository is &copy; 2023 Erik Hollensbe
<erik@hollensbe.org>. It is additionally licensed [GNU Affero GPL
3.0](https://www.gnu.org/licenses/agpl-3.0.en.html) which gives you rights to
reproduce this work as long as the license terms are followed and not modified.

## Rationale

OAuth and OpenID both require two-way participation from both the
authenticating website and an authentication agent, which also normally acts as
a web service. Due to this co-dependent nature, the result has been that a
small handful of authentication agents that are trusted exist. Libraries exist
with a handful of authentication agents presented as sources, and additional
open methods for standards like OpenID are consolidated onto a handful of large
providers due to the complexity of integrating with others.

The FAN intends to provide an alternative to this approach. Instead of
depending on specific authentication agents, one can determine whether or not
authentication for a specific identity can be performed by routing through the
target agent. Additionally, authentication will be performed without exchanging
any private material, allowing the user to have full control of its private
material, regardless of authentication agent.

Finally, this results in a situation where web sites that wish to implement or
consume FAN protocols do not need to keep any authentication materials, instead
opting to look them up on demand, which allows for numerous improvements to
overall web security in the event of database compromise.

## Specification

### Protocol Inspiration and Background

This protocol is somewhat inspired by the exchange that happens during
authentication of a key pair in the OpenSSH 2 protocol, as well as the handling
of the key material used in the OpenSSH Agent for the purposes of
authenticating with a private key. It leverages the notion of [Decentralized
Identity Documents](https://www.w3.org/TR/did-core/) and prescribes an
authentication method that further authenticates the origin of the document for
the purposes of identifying an agent.

### Terms

-   User: an identifying party, for the purposes of authentication. This can
    either be an interactive entity, such as a person, or a non-interactive
    entity such as a computer program.
-   Agent: A party involved in the establishment of authentication. An Agent is
    responsible for servicing identity documents, and may additionally be
    involved in servicing private key material, and potentially authentication
    itself.
-   Web Site: an agent that requires authentication, typically to take advantage
    of the services it provides.
-   Public Material: Material that is shared with the Agent and Web Site for the
    purposes of authentication.
-   Private Material: Material that is not shared with the Web Site, and may
    optionally not be shared with the Agent, allowing only the User to possess
    this material.
-   Key Pair: Materials provided for the purpose of public key encryption. This
    typically consists of a private and public key, which uses are defined by
    "Public Material" and "Private Material" above.
-   Signing / Signature: the process to verify that someone in possession of a
    private key actually possesses it, and claims responsibility for further uses
    of the material as designed.

### Conforms to Specifications

-   [Decentralized Identity Documents, W3C Recommendation](https://www.w3.org/TR/did-core/)
-   [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517): JSON Web Key
-   [RFC7515](https://datatracker.ietf.org/doc/rfc7515/): JSON Web Signature
-   [RFC7516](https://datatracker.ietf.org/doc/rfc7516/): JSON Web Encryption
-   [RFC3629](https://www.rfc-editor.org/rfc/rfc3629): UTF-8
-   [RFC5890](https://www.rfc-editor.org/rfc/rfc5890.html): Internationalized Domain Names
-   [RFC9110](https://datatracker.ietf.org/doc/html/rfc9110): HTTP 1.1 Semantics

### General Implementation Requirements

These definitions should be interpreted as in-line with the definitions
provided in [RFC2119](https://www.rfc-editor.org/rfc/rfc2119).

-   It is REQUIRED that all remote exchanges are handled over HTTP utilizing TLS
    1.3 at a minimum. TLS certificates are REQUIRED to be verified against a
    trusted certificate authority by industry standard means.
-   Certain HTTP URL paths are fixed, in other words they MUST be queried at this
    place and a document MUST be returned via HTTP GET request for authentication
    to succeed.
-   In some situations, signing is REQUIRED to verify credentials. These
    signatures MUST be validated for authentication to occur.
-   In some situations, random data must be generated. This data MUST be
    generated from a reliably random source, and MUST NOT be repeated for
    multiple invocations of generation routines, either for the current
    identity or across identities.
-   In some situations, private key material will be used to handle different
    portions of the transaction. Neither the Web Site nor the Agent is REQUIRED
    to handle this key material, and it is a strong recommendation that it does
    not. It is NOT REQUIRED for an Agent to use the private key for any reason,
    store it, or review it in any way. The authenticating Web Site MUST NOT
    request or store the private key material for any reason.

### Protocol

The over-arching goals of the protocol involve several transactions over HTTP
with TLS to fetch Decentralized Identity Documents, with the purposes of
performing operations based on the data enclosed in those documents.
Additionally, a scheme is prescribed to assist in the user experience of DID
lookup, to ease adoption amongst users.

#### Translation of Identifiers

An identifier is used to determine where to look up documents, so a scheme for
dictating the identifier's format and translation to a hypertext-centric URL is
an important concern.

##### Address Specification

Address specification is modeled after [RFC2822, Section
3.4.1](https://datatracker.ietf.org/doc/html/rfc2822#section-3.4.1) but has
many changes to modernize the format, make it more suitable for look up, as
well as assist in the ease of translation.

The ABNF is as follows:

```
addr-spec = identifier "@" domain [ ":" port ]
identifier = 1*UTF-8
domain = <RFC 5890-compatible domain name>
```

In this ABNF, the following definitions are assumed:

-   UTF-8 is defined by [RFC3629](https://www.rfc-editor.org/rfc/rfc3629). There
    are no exceptions for characters that can be used.
-   [RFC5890](https://www.rfc-editor.org/rfc/rfc5890.html) is the most recent
    approved standard for resolving domain names through the domain name system
    and the surrounding protocols. It is assumed that any compliant
    implementation will be capable of leveraging internationalized domain names
    for the sake of including those who leverage non-latin characters in their
    internet addressing.
-   `port` is an optional section, separated by a colon (`:`), with the port
    itself being an integer value without a leading 0. This translates literally
    to a TCP port.

For the sake of handling the literal `@` in the wake of identifiers that may
include an `@`, it is prescribed that the last `@` in the addr-spec denote the
start of the domain. The attempt in specifying this way is to avoid large
exclusions of the Unicode character set while still keeping parsing simple.

##### Translating an Identifier to DID

Identifiers are translated to Decentralized Identity URLs, per did-core
specification. Translation to the DID follows the following ABNF, with the
previous definitions in the previous section re-used to identify how the
address is re-used in the DID. Please note that additional rules related to the
ABNF for DIDs apply, notably around percent-encoding of the identifier to
ASCII.

```
spec = did-scheme ":" method-id ":" domain [ "%3F" port ] ":" identifier
did-scheme = "did"
method-id = "fan"
```

##### Examples of Translation

-   `alice@fan.example.org`: `did:fan:fan.example.org:alice`
-   `alice@fan.example.org:5309`: `did:fan:fan.example.org%3F5309:alice`
-   `無爲@example.com`: `did:fan:example.com:%e7%84%a1%e7%88%b2`

#### Signing Requirements to Identify Trusted Agents

Agents must present the Decentralized Identity Document signed by a key present
in the Decentralized Identity Document provided by the agent itself. This agent
must present a document at the following path of the domain's website, over
HTTP with TLS (https). This path is `/fan.did`, the format of which is provided
as a MIME description by the `Content-Type` presented as a HTTP header. A failure
to retrieve this document is REQUIRED to fail authentication. See "MIME
formats" for more information.

The signed user DID must be presented in JSON Web Signature format, described
in [RFC7515](https://datatracker.ietf.org/doc/rfc7515/), and contain the
Decentralized Identity Document in the `payload` section, to be decoded by
client implementations. The signature MUST be verified against any of the
verification methods in the `authentication` section of the site's
Decentralized Identity Document, provided at the path `/fan.did`, so the user
identity document MUST be signed by all methods provided in the
`authentication` section in the site's document for it to be possible to verify
it. A failure to verify the signature is REQUIRED to fail authentication. A
failure to verify the TLS certificate against a well known certificate
authority is REQUIRED to fail authentication.

#### Looking up a Decentralized Identity Document for a User from a Client

The steps are as follows:

-   The user's identifier is translated to a DID according to the rules defined
    in this specification.
-   The DID is translated to a well known HTTP over TLS (https) URL following the
    rules below:
    -   `https` is used as the scheme
    -   The domain is used as the domain, with the port translated to a `":" port`
        scheme typically used in URLs, from the escaped form in the DID.
    -   The identifier retains its percent-encoded, ASCII form.
    -   The path `"/did-fan/user/" identifier ".did"` is constructed as the path.
    -   Example:
        -   `did:fan:example.org:alice` is translated to `https://example.org/did-fan/user/alice.did`
-   This document is requested via HTTP GET.
-   A JSON Web Signature is received; the signature is verified against the
    Agent's Decentralized Identity Document according to the rules defined in
    this specification.
-   The outer document of the `payload` is a JSON map with the following properties:
    -   `document`, which is the Decentralized Identity Document, presented in
        Base64 encoding.
    -   `content-type`, which is the MIME type of the `document` content.
-   The document is de-serialized from the Base64 `document` property in the
    `payload`, according to the rules for the specified MIME type presented in
    the `content-type`.
-   The document can now be used as a Decentralized Identity Document that
    corresponds with the user's identity.

If any of these steps cannot be performed, it is REQUIRED that authentication
fail.

#### Alternatives to DID Lookup - Sovereign DIDs

The authenticating website is NOT REQUIRED to implement this method, but is
STRONGLY RECOMMENDED for websites that do not want to expect users to rely on
an authority by means of a participating agent. A website MAY also choose to
only allow pre-identified users to authenticate with this method, exchanging
the DID through "out of band" means prematurely.

The user is provided with an option to provide the DID directly, unsigned by a
website's underlying DID, as a valid means of authentication. This DID will
have the domain `_sovereign_` (underscores included). As such, the lookup rules
are ignored when this option is employed.

This DID, when provided through automated means, is signed with a JWS format by
a private key that corresponds to a public key in the user's
`capabilityInvocation` verification method set. Since these keys are expected
to be provided as a part of the signed DID, a website MAY disallow
authentication against this DID for any reason, as there are systemic issues
with proving the user is in fact, the identity provided. `_sovereign_` methods
should be validated with utmost caution, notably as they provide a global
namespace, and implementing websites should be cautious as to not allow a
potential attacker to assume the identity of someone else.

Regardless, assuming the website has allowed the DID, the JWS is validated
against the `capabilityInvocation` keys, and then the DID can be used for
authentication in the standard form.

For the purposes of lookup, the same scheme is used; so for example:
`alice@_sovereign_` will look up a document that corresponds to the sovereign
DID `did:fan:_sovereign_:alice`.

#### Authenticating a User

Briefly, authenticating a user involves the web site producing encrypting
material encrypted by the public keys associated to the user's DID and
expecting the user to decrypt it with the private key, and reproduce the
decrypted material also signed by the private key.

Notably, the steps utilized are as follows. The website is REQUIRED to reject
authentication if any of the following steps cannot be performed.

-   The user makes a request to an authentication endpoint via HTTP GET over TLS.
    The user's agent is required to verify the TLS certificate against a set of
    certificate authorities.
-   The user's DID is obtained through "DID Lookup" or via a "Sovereign DID".
-   Random data is generated by the authenticating web site. It is REQUIRED
    that no less than 16 bytes of data be generated per authentication attempt.
    Random data MUST NOT be re-used for any purposes, and instead by generated
    every time random data is required, including multiple authentication
    attempts or any form of authentication re-attempt.
-   This random data is then used in a JWE payload, which is represented as a
    JSON map with the following fields:
    -   `data`: This is the random data generated by the website, in Base64 encoding.
    -   `identifier`: This is an identifier provided by the website for the
        purposes of identifying this unique authentication attempt. Its format is
        deliberately arbitrary and it is the responsibility of the website to
        generate it. It is REQUIRED that it is unique for each attempt.
-   The JWE is encrypted with all keys in the user's `authentication` section of
    the DID, and serialized to JWE Compact Form.
-   This data is then relayed to the user as a response to the authentication request.
-   The user decrypts the data according to the rules supplied by JWE, and
    obtains the random data.
-   The user replies with a POST request to the same endpoint with a JWS. The
    `payload` contains a JSON map with the `data` and `identifier` fields that
    were provided in the JWE. It is signed by the same key used to decrypt the
    random data.
-   The website verifies that the identifier exists and looks up the random
    data supplied with it.
-   The website compares the random data provided by the client with the data
    it generated as the original step in this request.

If all steps are completed, the user is hereby authenticated at the website. It
is REQUIRED that all steps succeed without issue.

#### DID Caching Options

Caching is possible for the DID documents that are looked up in this process,
thereby skipping potentially expensive HTTP GET requests on each authentication
attempt. An implementing website is NOT REQUIRED to cache documents, and MAY
fetch them on demand. If the website chooses to cache documents, the rules in
[RFC9110](https://datatracker.ietf.org/doc/html/rfc9110#name-if-modified-since)
apply specifically in relationship to the `If-Modified-Since` and
`Last-Modified` headers for the purposes of caching. HTTP status `304 Not
Modified` is expected to be returned by agents per the HTTP standard, but it is
NOT REQUIRED and the agent may choose to return the full document every time
using a `200 OK` HTTP status code.

An authenticated website, when caching, is REQUIRED to compare the user DID's
`Last-Modified` with the agent DID's `Last-Modified`, and if the agent's is
newer, it is REQUIRED to fetch an updated user DID.

An authenticating website is REQUIRED, when caching, to attempt to request an
updated DID for every authentication attempt. If unable to reach the
authenticating agent, a website MAY decide to rely on a cached document, but is
NOT REQUIRED to do so. If it chooses not to, it MUST fail authentication.

The DID document must be cached as a JWS, and its signature must be checked
according to the rules for verifying an agent's authority. This caching process
may also be leveraged for the agent's DID as well as the user.

This solution allows DIDs to be served appropriately by a "Content Delivery
Network", acting as an intermediary for the agent, instead of a single entity.

#### Private Key Considerations and Recommendations

These are recommendations, not requirements.

Private key material SHOULD be encrypted by a strong symmetric cipher, which
can be unlocked via passphrase. Passphrase decryption should be employed
whenever the key needs to be unlocked. Private key material holders should
additionally should be able to keep the key unprotected, which may be useful in
automated situations.

Private key material MUST NOT be divulged from where it is stored, for any
reason, including authentication.

Agents can implement private key storage for the ease of use of the user, but
this is not only not recommended, but beyond the scope of this document.
Private key storage by an agent does not need to be a part of the same
authentication agent, and can be a separate storage service.

For the purposes of easing authentication, an agent (not the authenticating
agent) designed to intercept the final calls of authentication that are
user-facing and ease the user experience of handling the challenge is strongly
recommended to avoid bearing this complexity on the user itself. The design of
such an agent is beyond the scope of this document.

Agents SHOULD, but are NOT REQUIRED to expire the public keys it serves after a
certain interval. This is to prevent domain compromise by registration
after-the-fact.

#### MIME Types of Documents Described in this Specification

-   JWS & JWE: `application/jose`
-   DID JSON: `application/json+did`
-   DID JSON-LD: `application/jsonld+did`
-   DID CBOR: `application/cbor+did`

#### Notes on DNS compromise

This scheme is susceptible to a situation in which the account can be
compromised if the domain is re-registered by a malicious registering party,
and a new agent is configured to compromise the user accounts. It is very
important that both the user trust the agent to not lose the domain, and the
agent only be deployed in stable environments.

## Author

Erik Hollensbe <erik@hollensbe.org>

## Reviewers

This specification was reviewed and corrections were made according to the
review comments. The following reviewers graciously offered their time and
engaged in discussions around it.

-   James Tucker
