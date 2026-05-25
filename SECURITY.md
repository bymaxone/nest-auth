# Security Policy

`@bymax-one/nest-auth` ships authentication primitives — JWT, MFA, OAuth, sessions, brute-force protection — that downstream applications rely on for their identity and access boundaries. We take vulnerability reports seriously and triage them ahead of feature work.

## Supported versions

Security patches are issued for the most recent minor on the active `1.x` line. Older lines stop receiving fixes when a new minor ships.

| Version | Status                              |
| ------- | ----------------------------------- |
| `1.x`   | ✅ Active — receives security fixes |
| `< 1.0` | ❌ End-of-life                      |

If you are stuck on an older line and need a backport, open a private advisory (see below) and we will discuss feasibility on a case-by-case basis.

## Reporting a vulnerability

**Do not report security issues through public GitHub Issues, Discussions, or pull requests.** Public reports give attackers a window between disclosure and patch deployment.

Use GitHub **Private Vulnerability Reporting**, which is enabled on this repository:

➡️ [Open a private security advisory](https://github.com/bymaxone/nest-auth/security/advisories/new)

If you cannot use the GitHub form (e.g., you do not have an account), email **support@bymax.one** with `[security] @bymax-one/nest-auth` in the subject line.

### What to include

A useful report contains:

- A clear description of the vulnerability and its impact (CIA triad — confidentiality, integrity, availability)
- Step-by-step reproduction against the latest `1.x` release
- The affected subpath (`./`, `./client`, `./react`, `./nextjs`, `./shared`)
- A suggested fix or mitigation, if you have one
- Whether you would like to be credited in the published advisory (and how — name, handle, affiliation)

### Response timeline

| Phase                                       | Target                            |
| ------------------------------------------- | --------------------------------- |
| Acknowledgement of receipt                  | within **72 hours**               |
| Initial assessment and severity rating      | within **7 days**                 |
| Coordinated fix for **Critical / High**     | within **90 days** of acknowledgement |
| Coordinated fix for **Medium / Low**        | best effort, tracked in advisory  |

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure) and publish the advisory only after a fixed version is on npm, unless active exploitation forces an earlier publication.

Reporters are credited in the GitHub Security Advisory and CHANGELOG entry unless they request anonymity.

## In-scope vulnerabilities

The following classes are explicitly in scope:

- **Authentication bypass** — any path that returns an authenticated state without valid credentials
- **Privilege escalation** — RBAC bypass, role spoofing, tenant boundary violation
- **Cryptographic weaknesses** — timing attacks on secret comparison, broken JWT signature validation (`alg:none`, algorithm confusion, key confusion), weak password hashing parameters
- **Session attacks** — fixation, hijacking via cookie misconfiguration, replay
- **Token leakage** — access/refresh tokens exposed via logs, error responses, HTTP headers, or `localStorage` recommendations
- **Open redirect** — in the OAuth callback flow or the Next.js silent-refresh handler
- **Header smuggling** — CR/LF injection in `Set-Cookie` propagation, header spoofing across the Next.js proxy
- **Brute-force bypass** — circumventing the rate limiter, IPv6 normalization issues, account-status enumeration
- **Supply-chain integrity** — compromised dependency, malicious typosquat, tampered release artifact
- **CodeQL `security-extended` alerts** — anything the automated scan surfaces in the Security tab

## Out of scope

These are not vulnerabilities in `@bymax-one/nest-auth` itself:

- Issues only reproducible in versions older than `1.0.0`
- Misconfigurations in the **consuming application** (weak `JWT_SECRET`, plaintext cookies, missing HTTPS) unless they reproduce with the documented default configuration
- Issues in optional peer dependencies (`ioredis`, `next`, `react`) when the upstream maintainer has already accepted them or when the dependency is not exercised by the library
- Self-XSS, social engineering, denial of service via legitimate authenticated load
- Theoretical attacks without a practical demonstration (e.g., quantum-break of HS256)

## Security best practices for consumers

The repository documentation covers production deployment hardening:

- [docs/guidelines/JWT-AUTH-GUIDELINES.md](docs/guidelines/JWT-AUTH-GUIDELINES.md) — token management, secret rotation, algorithm pinning
- [docs/guidelines/REDIS-IOREDIS-GUIDELINES.md](docs/guidelines/REDIS-IOREDIS-GUIDELINES.md) — session storage, brute-force protection
- [docs/guidelines/NODE-CRYPTO-GUIDELINES.md](docs/guidelines/NODE-CRYPTO-GUIDELINES.md) — cryptographic primitives and `timingSafeEqual` usage
- [docs/guidelines/NEXTJS-GUIDELINES.md](docs/guidelines/NEXTJS-GUIDELINES.md) — Edge-Runtime proxy hardening, cookie attributes

Pin the package to an exact version in production, verify the publish provenance (`npm audit signatures`), and subscribe to the repository's security advisories so you receive notifications when a CVE is published.

## Acknowledgements

We are grateful to the security community and to every reporter who takes the time to investigate and disclose responsibly.
