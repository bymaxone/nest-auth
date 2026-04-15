# Plano de Desenvolvimento — @bymax-one/nest-auth

> **Versão:** 1.2.0
> **Criado em:** 2026-04-10
> **Última revisão:** 2026-04-13 (adição de Fases 7-9 frontend, guards nativos NestJS, criptografia via node:crypto)
> **Baseado em:** [Especificação Técnica v1.0.0](./technical_specification.md)
> **Estimativa total:** ~8-9 semanas (1 desenvolvedor + agente IA)

---

## Índice

1. [Visão Geral do Plano](#1-visão-geral-do-plano)
2. [Fase 1 — Fundação e Infraestrutura](#2-fase-1--fundação-e-infraestrutura)
3. [Fase 2 — Autenticação Core](#3-fase-2--autenticação-core)
4. [Fase 3 — Autenticação Multi-Fator (MFA)](#4-fase-3--autenticação-multi-fator-mfa)
5. [Fase 4 — Sessões e Reset de Senha](#5-fase-4--sessões-e-reset-de-senha)
6. [Fase 5 — Plataforma, OAuth e Convites](#6-fase-5--plataforma-oauth-e-convites)
7. [Fase 6 — Integração, Polimento e Publicação](#7-fase-6--integração-polimento-e-publicação)
8. [Fase 7 — Shared + Client Subpath](#8-fase-7--shared--client-subpath)
9. [Fase 8 — React Subpath](#9-fase-8--react-subpath)
10. [Fase 9 — Next.js Subpath](#10-fase-9--nextjs-subpath)
11. [Critérios de Qualidade por Fase](#11-critérios-de-qualidade-por-fase)
12. [Riscos e Mitigações](#12-riscos-e-mitigações)
13. [Dependências entre Fases](#13-dependências-entre-fases)
14. [Registro de Auditoria](#14-registro-de-auditoria)

---

## 1. Visão Geral do Plano

### 1.1 Estratégia de desenvolvimento

O desenvolvimento segue uma abordagem **incremental por camadas**, onde cada fase produz artefatos testáveis e funcionais que servem de base para a próxima. A ordem das fases respeita a cadeia de dependências: infraestrutura → autenticação básica → extensões de segurança → extensões de plataforma → polimento.

### 1.2 Princípios orientadores

- **TDD em cada fase:** Testes unitários são escritos junto com o código, não acumulados ao final. Cobertura mínima de 80% por fase.
- **Compilação limpa:** Cada fase deve compilar (`tsc`) sem erros antes de ser considerada completa.
- **Barrel export incremental:** O `index.ts` é atualizado a cada fase com os novos exports públicos. Distinguir `export type` (interfaces, type aliases) de `export` (classes, constantes, decorators, guards).
- **Validação de segurança:** Cada fase inclui revisão explícita dos pontos de segurança listados no Apêndice B da especificação.
- **Zero `any` disciplinado:** Zero uso de `any` em código de produção. `Record<string, unknown>` deve ser evitado onde o tipo é estaticamente conhecido. Para fronteiras com dados externos não tipados (OAuth profiles), usar tipos explícitos ou `Record<string, unknown>` com narrowing documentado via JSDoc.
- **Shallow merge para configuração:** `resolveOptions()` deve usar shallow merge por grupo (não `JSON.parse/stringify`) para preservar propriedades que são funções (`maxSessionsResolver`, `tenantIdResolver`, `resolveDomains`).

### 1.3 Cronograma resumido

| Fase | Semana   | Foco                              | Dependência |
| ---- | -------- | --------------------------------- | ----------- |
| 1    | Semana 1 | Fundação e infraestrutura         | —           |
| 2    | Semana 2 | Autenticação core                 | Fase 1      |
| 3    | Semana 3 | MFA (TOTP)                        | Fase 2      |
| 4    | Sem 3-4  | Sessões + password reset          | Fase 2      |
| 5    | Sem 4-5  | Plataforma + OAuth + convites     | Fases 2-4   |
| 6    | Sem 5-6  | Integração, polimento, publicação | Fases 1-5   |
| 7    | Sem 6-7  | Shared + Client subpath           | Fase 6      |
| 8    | Semana 7 | React subpath                     | Fase 7      |
| 9    | Sem 7-8  | Next.js subpath                   | Fase 7      |

---

## 2. Fase 1 — Fundação e Infraestrutura

**Duração:** 1 semana
**Objetivo:** Criar toda a estrutura base do pacote — scaffold, interfaces, configuração, Redis, serviços fundamentais e utilitários de criptografia. Ao final desta fase, o pacote compila e possui toda a infraestrutura necessária para construir os fluxos de autenticação.

### 2.1 Scaffold do projeto

**Arquivos a criar:**

| Arquivo               | Descrição                                                                                                                                                                            |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `package.json`        | Nome `@bymax-one/nest-auth`, versão `1.0.0`, peer dependencies conforme seção 18 da spec, `"dependencies": {}` (zero dependências diretas), scripts `"build": "tsup"`, `lint`, `test`, `test:cov`, `prepublishOnly`. devDependencies inclui `tsup ^8.0.0` |
| `tsconfig.json`       | Target ES2022, module CommonJS, strict mode habilitado, decorators experimentais, emitDecoratorMetadata                                                                              |
| `tsconfig.build.json` | Extends `tsconfig.json`, exclui `**/*.spec.ts` e `test/`, outDir `dist`                                                                                                              |
| `.eslintrc.js`        | Configuração ESLint com `@typescript-eslint`, regras de NestJS                                                                                                                       |
| `jest.config.ts`      | Preset `ts-jest`, raiz `src/`, coverage threshold 80%                                                                                                                                |
| `.gitignore`          | `node_modules/`, `dist/`, `coverage/`, `.env`                                                                                                                                        |
| `.npmignore`          | Tudo exceto `dist/`, `package.json`, `README.md`, `LICENSE`                                                                                                                          |
| `LICENSE`             | Licença MIT conforme seção 1.4 da spec                                                                                                                                               |
| `CHANGELOG.md`        | Arquivo inicial vazio — será populado com entrada v1.0.0 na Fase 6                                                                                                                   |
| `src/server/index.ts`        | Barrel export inicial (vazio, será populado incrementalmente)                                                                                                                        |

**Tarefas detalhadas:**

1. Executar `pnpm init` com escopo `@bymax-one`
2. Instalar peer dependencies como devDependencies para desenvolvimento local
3. Confirmar que `"dependencies": {}` — o pacote não possui dependências diretas (toda criptografia usa `node:crypto` nativo)
4. Instalar devDependencies: `@nestjs/testing`, `jest`, `ts-jest`, `typescript`, `tsup ^8.0.0`
5. Configurar `package.json` com `"files": ["dist"]` (preferido sobre `.npmignore` para controle preciso do conteúdo publicado)
6. Configurar `tsconfig.json` com:
   - `"target": "ES2022"`
   - `"module": "commonjs"`
   - `"strict": true`
   - `"experimentalDecorators": true`
   - `"emitDecoratorMetadata": true`
   - `"declaration": true`
   - `"declarationMap": true`
   - `"sourceMap": true`
   - `"outDir": "./dist"`
   - `"rootDir": "./src"`
7. Configurar `tsconfig.build.json` excluindo testes
8. Configurar Jest com preset `ts-jest`, coverage mínima de 80% (branches, functions, lines, statements)
9. Criar estrutura de diretórios: `src/server/` (diretório principal do backend), `src/shared/`, `src/client/`, `src/react/`, `src/nextjs/`, e dentro de `src/server/`: `interfaces/`, `config/`, `services/`, `controllers/`, `guards/`, `decorators/`, `redis/`, `dto/`, `crypto/`, `errors/`, `oauth/`, `constants/`, `providers/`, `hooks/`
10. Verificar que `pnpm build` compila sem erros (mesmo com barrel export vazio)

### 2.2 Interfaces e contratos

**Arquivos a criar:**

| Arquivo                                                | Conteúdo                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/interfaces/auth-module-options.interface.ts`      | Interface `BymaxAuthModuleOptions` completa conforme seção 4.1 da spec — todos os 15 grupos de opções (jwt, password, tokenDelivery, cookies, mfa, sessions, bruteForce, passwordReset, emailVerification, platformAdmin, invitations, roles, blockedStatuses, oauth, controllers)                                                                                                                                                                       |
| `src/server/interfaces/user-repository.interface.ts`          | Interface `AuthUser` (15 campos) e `IUserRepository` (11 métodos: findById, findByEmail, create, updatePassword, updateMfa, updateLastLogin, updateStatus, updateEmailVerified, findByOAuthId, linkOAuth, createWithOAuth)                                                                                                                                                                                                                               |
| `src/server/interfaces/platform-user-repository.interface.ts` | Interface `AuthPlatformUser` (13 campos) e `IPlatformUserRepository` (6 métodos: findById, findByEmail, updateLastLogin, updateMfa, updatePassword, updateStatus)                                                                                                                                                                                                                                                                                        |
| `src/server/interfaces/email-provider.interface.ts`           | Interface `IEmailProvider` com 7 métodos: sendPasswordResetToken, sendPasswordResetOtp, sendEmailVerificationOtp, sendMfaEnabledNotification, sendMfaDisabledNotification, sendNewSessionAlert, sendInvitation — todos com parâmetro `locale?`                                                                                                                                                                                                           |
| `src/server/interfaces/auth-hooks.interface.ts`               | Interface `IAuthHooks` (12 hooks opcionais), `HookContext`, `BeforeRegisterResult`, `OAuthLoginResult`, `OAuthProfile`                                                                                                                                                                                                                                                                                                                                   |
| `src/server/interfaces/jwt-payload.interface.ts`              | Interfaces `DashboardJwtPayload` (com jti, sub, tenantId, role, type, status, mfaVerified, iat, exp), `PlatformJwtPayload` (com jti, sub, role, type, mfaVerified, iat, exp), `MfaTempPayload` (com sub, type, context, iat, exp). **Nota:** `emailVerified` NÃO é um claim do JWT (apesar de mencionado na spec seção 6.1 como disponível no JWT). O app host deve verificar via `AuthUser.emailVerified` do endpoint `/me` ou do hook `afterRegister`. |
| `src/server/interfaces/auth-result.interface.ts`              | Interfaces `AuthResult` (user, accessToken, rawRefreshToken, sessionHash?), `PlatformAuthResult` (admin, accessToken, rawRefreshToken), `MfaChallengeResult` (mfaRequired, mfaToken). **Nota:** Definidos na Fase 1 para que a Fase 3 possa compilar `MfaService.challenge()` que retorna `AuthResult \| PlatformAuthResult`.                                                                                                                            |
| `src/server/interfaces/authenticated-request.interface.ts`    | Interfaces `AuthenticatedRequest` (Request + user: DashboardJwtPayload) e `PlatformAuthenticatedRequest` (Request + user: PlatformJwtPayload)                                                                                                                                                                                                                                                                                                            |
| `src/server/interfaces/oauth-provider.interface.ts`           | Interface `OAuthProviderPlugin` (name, strategy, guard, extractProfile). Fluxo OAuth baseado em `fetch` nativo — sem dependências externas. `extractProfile(rawProfile: Record<string, unknown>)` converte o perfil bruto do provider para `OAuthProfile`.                                                                                                                                                                                                                               |

**Tarefas detalhadas:**

1. Implementar cada interface conforme a especificação técnica, respeitando tipos exatos
2. Garantir que `AuthUser.mfaEnabled`, `mfaSecret` e `mfaRecoveryCodes` são opcionais (`?`)
3. Garantir que `IUserRepository.create()` aceita `passwordHash: string | null` (para OAuth)
4. Garantir que todos os métodos do `IEmailProvider` aceitam `locale?: string`
5. Garantir que todos os hooks do `IAuthHooks` são opcionais (`?` no nome do método)
6. Em `NoOpAuthHooks`, usar tipos explícitos do `IAuthHooks` — nunca `any` para `sessionInfo` (usar `{ device: string; ip: string; sessionHash: string }`). **Desvio da spec:** A spec seção 9.3 usa `_sessionInfo: any` — implementar com o tipo correto da interface `IAuthHooks`
7. Implementar função utilitária `sanitizeHeaders(headers)` para o `HookContext`: blocklist explícita de `['authorization', 'cookie', 'x-api-key', 'x-auth-token', 'x-csrf-token', 'x-session-id']` + pattern match `/^x-.*-token$/i`. Incluir testes unitários
8. Tipar `tenantIdResolver` como `(req: import('express').Request) => string | Promise<string>` em vez de `(req: any)` para type safety na API pública
9. Definir `AuthResult`, `PlatformAuthResult` e `MfaChallengeResult` como interfaces em `auth-result.interface.ts` — necessários desde a Fase 1 para compilação de fases subsequentes. Usar `rawRefreshToken` (nunca `refreshToken`) como nome do campo em toda a documentação e código
   - **Desvio da spec:** A spec exporta esses tipos de `./services/auth.service` e `./services/platform-auth.service`. Como os services não existem na Fase 1, o barrel export deve usar `export type { AuthResult, MfaChallengeResult } from './interfaces/auth-result.interface'` e `export type { PlatformAuthResult } from './interfaces/auth-result.interface'`. Os services das fases posteriores devem importar de `./interfaces/`, nunca re-definir esses tipos
10. Adicionar JSDoc em cada interface explicando propósito e contrato
11. Exportar todas as interfaces no `index.ts` — usar `export type` para interfaces/type aliases e `export` para classes/constantes
12. Verificar compilação limpa

### 2.3 Constantes e configuração

**Arquivos a criar:**

| Arquivo                                | Conteúdo                                                                                                                                                                                                                                                                                                             |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/bymax-auth.constants.ts` | 6 Symbols: `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, `BYMAX_AUTH_PLATFORM_USER_REPOSITORY`, `BYMAX_AUTH_EMAIL_PROVIDER`, `BYMAX_AUTH_HOOKS`, `BYMAX_AUTH_REDIS_CLIENT`                                                                                                                                     |
| `src/server/config/default-options.ts`        | Objeto com todos os valores padrão conforme tabela 4.2 da spec                                                                                                                                                                                                                                                       |
| `src/server/config/resolved-options.ts`       | Tipo `ResolvedOptions` (opções com defaults aplicados) + função `resolveOptions(userOptions)` que faz deep merge com defaults + validação de `jwt.secret` (mín 32 chars, entropia Shannon >= 3.5 bits/char, rejeita padrões repetitivos) + validação de `mfa.encryptionKey` (32 bytes quando decodificado de base64) |
| `src/server/constants/index.ts`               | Re-export de constantes públicas                                                                                                                                                                                                                                                                                     |
| `src/server/constants/throttle-configs.ts`    | Objeto `AUTH_THROTTLE_CONFIGS` com 14 configurações de rate limiting conforme seção 16.2                                                                                                                                                                                                                             |
| `src/server/constants/error-codes.ts`         | Re-export de `AUTH_ERROR_CODES`                                                                                                                                                                                                                                                                                      |

**Tarefas detalhadas:**

1. Criar os 6 Symbols com nomes descritivos (ex: `Symbol('BYMAX_AUTH_OPTIONS')`)
2. Implementar `default-options.ts` cobrindo todos os defaults da tabela 4.2
3. Implementar `resolveOptions()` com:
   - **Shallow merge por grupo** (não `JSON.parse/stringify`) para preservar propriedades que são funções (`maxSessionsResolver`, `tenantIdResolver`, `resolveDomains`). Usar spread operator por nível: `{ ...defaults.jwt, ...userOptions.jwt }`
   - Validação obrigatória de `jwt.secret`: comprimento >= 32, entropia >= 3.5, rejeição de strings repetitivas
   - Validação de `jwt.algorithm`: se fornecido, deve ser exatamente `'HS256'` — lançar erro se outro valor
   - Validação condicional de `mfa.encryptionKey`: se `mfa` fornecido, `encryptionKey` obrigatório, verificar que decodifica para exatamente 32 bytes
   - Validação de `roles.hierarchy`: não pode ser vazio
   - Validação de `platformHierarchy`: obrigatório se `platformAdmin.enabled`
   - Validação de `passwordReset.otpLength`: se fornecido, deve ser <= 8 (acima de 8, `crypto.randomInt(0, 10**length)` excede `Number.MAX_SAFE_INTEGER` e lança `RangeError`)
   - Aviso (log warning, não erro) se `routePrefix` difere de `'auth'` e `cookies.refreshCookiePath` não está explicitamente configurado — o cookie de refresh pode não ser enviado para o endpoint correto
   - Lançar exceção descritiva para cada validação falhada
4. Implementar `AUTH_THROTTLE_CONFIGS` com os 14 endpoints conforme seção 16.2. **Nota:** requer `@nestjs/throttler` >= 6.0.0 (API de named throttlers com `{ default: { limit, ttl } }`)
5. Escrever testes unitários para `resolveOptions()`: cenários de sucesso, secret fraco, secret curto, encryptionKey inválida, hierarchy vazia, algorithm inválido, função preservada após merge
6. Exportar constantes no `index.ts`

### 2.4 Sistema de erros

**Arquivos a criar:**

| Arquivo                          | Conteúdo                                                                                                                                                                                 |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/errors/auth-error-codes.ts` | Constante `AUTH_ERROR_CODES` (33 códigos) + `AUTH_ERROR_MESSAGES` (mapeamento código → mensagem em português) conforme seção 15                                                          |
| `src/server/errors/auth-exception.ts`   | Classe `AuthException extends HttpException` com construtor `(code, statusCode?, details?)` que formata resposta no padrão `{ error: { code, message, details } }`                       |
| `src/server/utils/sleep.ts`             | Função `sleep(ms: number): Promise<void>` — wrapper de `setTimeout` em Promise. Usada para normalização de timing em endpoints anti-enumeração                                           |
| `src/server/utils/roles.util.ts`        | Função `hasRole(userRole, requiredRole, hierarchy): boolean` — lógica de verificação hierárquica extraída para reutilização por `RolesGuard`, `PlatformRolesGuard` e `InvitationService` |

**Tarefas detalhadas:**

1. Implementar todos os **33 códigos de erro** da tabela 15.3 da spec (incluindo `ACCOUNT_BANNED`, `FORBIDDEN`, `PENDING_APPROVAL`, `SESSION_LIMIT_REACHED`, `SESSION_NOT_FOUND`, `OAUTH_FAILED`, `OAUTH_EMAIL_MISMATCH`, `PLATFORM_AUTH_REQUIRED`)
2. Implementar `AuthException` conforme seção 15.1, com lookup automático da mensagem em `AUTH_ERROR_MESSAGES`
3. Garantir que `AUTH_ERROR_CODES` é tipado como `as const` para inferência de tipo literal
4. Escrever testes unitários: verificar formato da resposta, lookup de mensagem, status code padrão (401)
5. Exportar ambos no `index.ts` com `export` (valor, não `export type`)

### 2.5 Utilitários de criptografia

**Arquivos a criar:**

| Arquivo                      | Conteúdo                                                                                                                                                                                                                                                             |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/crypto/aes-gcm.ts`      | Funções `encrypt(plaintext, key)` e `decrypt(ciphertext, key)` usando AES-256-GCM. IV de 12 bytes gerado com `crypto.randomBytes(12)`. Formato de saída: `base64(iv):base64(authTag):base64(ciphertext)`. Usa `crypto.createCipheriv('aes-256-gcm', ...)` do Node.js |
| `src/server/crypto/secure-token.ts` | Funções `generateSecureToken(bytes?)` (retorna hex de `crypto.randomBytes`) e `sha256(input)` (retorna hex de `crypto.createHash('sha256')`)                                                                                                                         |
| `src/server/crypto/scrypt.ts`       | Funções `scryptHash(plain)` e `scryptCompare(plain, hash)` usando `node:crypto` scrypt. Parâmetros: N=2^15, r=8, p=1, keyLen=64, salt=16 bytes via `crypto.randomBytes`. Formato de saída: `scrypt:{salt_hex}:{derived_hex}`. Comparação via `crypto.timingSafeEqual` |
| `src/server/crypto/totp.ts`         | Implementação nativa de TOTP usando `node:crypto`. Inclui: `base32Decode(encoded)` (helper de decodificação Base32), `hotp(secret, counter)` (HMAC-SHA1 conforme RFC 4226), `totp(secret, period?)` (RFC 6238 com counter = `Math.floor(Date.now() / 1000 / period)`), `verifyTotp(secret, code, window?)` (verificação com janela configurável), `buildTotpUri(secret, email, issuer)` (gera URI `otpauth://totp/...` para QR code) |

**Tarefas detalhadas:**

1. Implementar `encrypt()`:
   - Gerar IV com `crypto.randomBytes(12)` — NUNCA reutilizar
   - Decodificar key de base64 para Buffer
   - Criar cipher com `crypto.createCipheriv('aes-256-gcm', keyBuffer, iv)`
   - Retornar `base64(iv):base64(authTag):base64(ciphertext)`
2. Implementar `decrypt()`:
   - Parsear o formato `iv:authTag:ciphertext`
   - Criar decipher com `crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv)`
   - Setar authTag com `decipher.setAuthTag(authTagBuffer)`
   - Retornar plaintext
3. Implementar `generateSecureToken(bytes = 32)` usando `crypto.randomBytes`
4. Implementar `sha256(input)` usando `crypto.createHash('sha256')`
5. Escrever testes unitários:
   - Round-trip de encrypt/decrypt com dados variados
   - Verificar que IVs são diferentes entre chamadas (não reutilização)
   - Verificar que decrypt falha com authTag adulterado (integridade)
   - Verificar que decrypt falha com key diferente
   - Verificar formato de saída do `generateSecureToken` e `sha256`
6. Implementar `scryptHash(plain)`:
   - Gerar salt de 16 bytes com `crypto.randomBytes(16)`
   - Derivar chave com `crypto.scrypt(plain, salt, 64, { N: 2**15, r: 8, p: 1 })` (promisificado)
   - Retornar `scrypt:{salt_hex}:{derived_hex}`
7. Implementar `scryptCompare(plain, hash)`:
   - Parsear formato `scrypt:{salt_hex}:{derived_hex}`
   - Derivar chave com mesmos parâmetros usando o salt extraído
   - Comparar com `crypto.timingSafeEqual(derivedBuffer, storedBuffer)` para prevenir timing attacks
8. Implementar `base32Decode(encoded)`: converter string Base32 (RFC 4648) para Buffer
9. Implementar `hotp(secret, counter)`: HMAC-SHA1 conforme RFC 4226 — `crypto.createHmac('sha1', secret)`, dynamic truncation, retorna string de 6 dígitos zero-padded
10. Implementar `totp(secret, period = 30)`: calcula counter como `Math.floor(Date.now() / 1000 / period)`, delega para `hotp()`
11. Implementar `verifyTotp(secret, code, window = 1)`: verifica código contra `totp()` com janela configurável (counter ± window)
12. Implementar `buildTotpUri(secret, email, issuer)`: retorna `otpauth://totp/${issuer}:${email}?secret=${base32Secret}&issuer=${issuer}`
13. Escrever testes unitários para scrypt e TOTP:
    - scrypt: round-trip hash/compare, formato de saída correto, rejeição de hash adulterado, timing-safe comparison
    - TOTP: geração de código com vetor de teste RFC 6238, verificação com janela, base32 decode, URI format

### 2.6 Módulo Redis

**Arquivos a criar:**

| Arquivo                           | Conteúdo                                                                                                                                                                                                                                                                                                                                                                                                   |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/redis/auth-redis.service.ts` | Serviço `AuthRedisService` que wrapa a instância `ioredis` injetada via `BYMAX_AUTH_REDIS_CLIENT`. Métodos: `get(key)`, `set(key, value, ttl?)`, `del(key)`, `incr(key)`, `expire(key, ttl)`, `ttl(key)`, `sadd(setKey, member)`, `srem(setKey, member)`, `smembers(setKey)`, `sismember(setKey, member)`, `eval(script, keys, args)`. Todos os métodos prefixam a key com `{namespace}:` automaticamente. |
| `src/server/redis/auth-redis.module.ts`  | Módulo NestJS interno que registra `AuthRedisService` como provider                                                                                                                                                                                                                                                                                                                                        |

**Tarefas detalhadas:**

1. Injetar `BYMAX_AUTH_REDIS_CLIENT` (instância ioredis) e `BYMAX_AUTH_OPTIONS` (para namespace)
2. Implementar prefixação automática: todas as chaves recebem `{namespace}:` como prefixo
3. Implementar cada método delegando para a instância ioredis
4. O método `eval()` deve suportar execução de scripts Lua (usado na rotação de refresh token)
5. Escrever testes unitários com mock de ioredis:
   - Verificar prefixação de namespace em cada operação
   - Verificar que `set` com TTL chama `SET key value EX ttl`
   - Verificar operações de SET (sadd, srem, smembers, sismember)
6. Exportar `AuthRedisService` internamente (não no barrel export público)

> **Chaves Redis adicionais (não presentes na spec, adicionadas pelo plano):**
>
> | Prefixo     | Padrão da Chave                                      | Valor                                             | TTL               | Propósito                                         |
> | ----------- | ---------------------------------------------------- | ------------------------------------------------- | ----------------- | ------------------------------------------------- |
> | `mfa_setup` | `auth:mfa_setup:{sha256(userId)}`                    | JSON: `{ encryptedSecret, hashedCodes }`          | 600s              | Dados temporários de setup MFA (Fase 3)           |
> | `psess`     | `auth:psess:{userId}`                                | SET de session hashes de plataforma               | = max refresh TTL | Rastreamento de sessões ativas de admins (Fase 5) |
> | `psd`       | `auth:psd:{sessionHash}`                             | JSON: `{ device, ip, createdAt, lastActivityAt }` | = max refresh TTL | Detalhes de sessão de plataforma (Fase 5)         |
> | `resend`    | `auth:resend:{purpose}:{sha256(tenantId+':'+email)}` | `'1'`                                             | 60s               | Cooldown entre reenvios de OTP (Fase 4)           |
>
> **Nota:** `mfa_setup` usa `sha256(userId)` como chave (não userId em plaintext) para seguir o princípio da spec de que todos os identificadores sensíveis são hasheados com SHA-256.

### 2.7 Serviços fundamentais

**Arquivos a criar:**

| Arquivo                                  | Conteúdo                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/services/password.service.ts`       | `PasswordService` com `hash(plain)` e `compare(plain, hash)` usando `node:crypto` scrypt. Delega para `scryptHash()` e `scryptCompare()` de `src/server/crypto/scrypt.ts`. Parâmetros: N=2^15, r=8, p=1, keyLen=64, salt=16 bytes. Formato: `scrypt:{salt_hex}:{derived_hex}`.                                                                                                                                                             |
| `src/server/services/token-manager.service.ts`  | `TokenManagerService` com `issueAccess()`, `issueTokens()`, `issuePlatformTokens()`, `reissueTokens()`, `decodeToken()`, `issueMfaTempToken()`, `verifyMfaTempToken()`. Usa `@nestjs/jwt` para operações JWT. Refresh tokens são UUID v4 opacos armazenados no Redis. `issuePlatformTokens()` emite JWT com `type: 'platform'` e refresh com prefixo `prt:` — necessário para `MfaService.challenge()` com `context: 'platform'`. |
| `src/server/services/token-delivery.service.ts` | `TokenDeliveryService` com `deliverAuthResponse()`, `deliverRefreshResponse()`, `extractAccessToken()`, `extractRefreshToken()`, `clearAuthSession()`, `resolveCookieDomains()`, `extractDomain()`. Comportamento muda conforme `tokenDelivery` (cookie/bearer/both).                                                                                                                                                             |
| `src/server/services/brute-force.service.ts`    | `BruteForceService` com `isLockedOut(identifier)`, `recordFailure(identifier)`, `resetFailures(identifier)`, `getRemainingLockoutSeconds(identifier)`. Usa chaves Redis `lf:{identifier}`.                                                                                                                                                                                                                                        |

**Tarefas detalhadas para PasswordService:**

1. Injetar `BYMAX_AUTH_OPTIONS`
2. Implementar `hash(plain)` delegando para `scryptHash(plain)` de `src/server/crypto/scrypt.ts` — usa `node:crypto` scrypt com N=2^15, r=8, p=1, keyLen=64, salt de 16 bytes. Formato de saída: `scrypt:{salt_hex}:{derived_hex}`
3. Implementar `compare(plain, hash)` delegando para `scryptCompare(plain, hash)` — usa `crypto.timingSafeEqual` para comparação em tempo constante
4. Escrever testes: hash gera string no formato `scrypt:...`, compare retorna true/false corretamente, comparação é timing-safe

**Tarefas detalhadas para TokenManagerService:**

1. Injetar `JwtService` do `@nestjs/jwt`, `BYMAX_AUTH_OPTIONS`, `AuthRedisService`
2. Implementar `issueAccess(payload: Omit<DashboardJwtPayload, 'jti' | 'iat' | 'exp'>)`:
   - Gerar `jti` internamente com `crypto.randomUUID()` — o caller NÃO deve fornecer `jti`, `iat` ou `exp`
   - Assinar JWT com claims do payload + `jti` gerado
   - Usar algoritmo HS256 e expiração de `accessExpiresIn`
3. Implementar `issueTokens()`:
   - Gerar access JWT via `issueAccess()`
   - Gerar refresh token com `crypto.randomUUID()` (token opaco)
   - Armazenar no Redis: `rt:{sha256(refreshToken)}` → JSON com `{ userId, tenantId, role, device, ip, createdAt }`
   - TTL = `refreshExpiresInDays * 86400` segundos
   - Retornar `AuthResult`
4. Implementar `reissueTokens()` com script Lua atômico (seção 12.4):
   - Buscar sessão antiga no Redis
   - Gerar novo refresh token
   - Criar ponteiro de rotação: `rp:{sha256(old)}` → novo token (TTL = `refreshGraceWindowSeconds`)
   - Criar nova sessão: `rt:{sha256(new)}` → dados atualizados
   - Deletar sessão antiga
   - Se token antigo não existe, verificar grace window
   - Se nenhum encontrado, lançar `REFRESH_TOKEN_INVALID`
5. Implementar `decodeToken()`: decodificar JWT sem validar expiração (para blacklist)
6. Implementar `issueMfaTempToken()`:
   - JWT com `type: 'mfa_challenge'`, `context` ('dashboard' ou 'platform'), expiração 5 minutos
   - Armazenar no Redis: `mfa:{sha256(token)}` → userId, TTL 300s
7. Implementar `verifyMfaTempToken()`:
   - Verificar JWT e buscar no Redis
   - Se não encontrado, lançar `MFA_TEMP_TOKEN_INVALID`
   - Consumir (deletar do Redis) após verificação
   - **Retornar `{ userId: string; context: 'dashboard' | 'platform' }`** (não apenas `string`) — o `context` é necessário para que `MfaService.challenge()` saiba qual repositório e tipo de resultado usar
   - **Nota:** A spec seção 6.3 foi atualizada para retornar `{ userId, context }` — ambos (spec e plano) estão agora sincronizados. A assinatura correta é `verifyMfaTempToken(token: string): Promise<{ userId: string; context: 'dashboard' | 'platform' }>`.
8. Implementar `decodeToken()`: decodificar JWT sem validar expiração. **SEGURANÇA:** Adicionar JSDoc `@internal — NUNCA usar para decisões de autorização, apenas para extração de jti/exp durante logout/blacklist`. Validar que o payload contém `jti` — se ausente, lançar `TOKEN_INVALID`
9. Escrever testes unitários com mocks de JwtService e Redis:
   - Token válido, token expirado, token na blacklist
   - Token sem `jti` → `TOKEN_INVALID`
   - `verifyMfaTempToken` retorna userId + context corretamente

**Tarefas detalhadas para TokenDeliveryService:**

1. Injetar `BYMAX_AUTH_OPTIONS` para acessar `tokenDelivery` e `cookies`
2. Implementar `deliverAuthResponse()`:
   - Modo `cookie`: setar cookies (access, refresh, session signal) + retornar `{ user }`
   - Modo `bearer`: não setar cookies + retornar `{ user, accessToken, refreshToken }`
   - Modo `both`: setar cookies + retornar `{ user, accessToken, refreshToken }`
3. Implementar `deliverRefreshResponse()` com mesma lógica adaptada para refresh
4. Implementar `extractAccessToken()`:
   - Modo `cookie`: ler de `req.cookies[accessTokenName]`
   - Modo `bearer`: ler de `Authorization: Bearer <token>`
   - Modo `both`: tentar cookie primeiro, depois header
5. Implementar `extractRefreshToken()`:
   - Modo `cookie`: ler de `req.cookies[refreshTokenName]`
   - Modo `bearer`: ler de `req.body.refreshToken`
   - Modo `both`: tentar cookie primeiro, depois body
6. Implementar `clearAuthSession()`:
   - Limpar todos os cookies de auth nos domínios resolvidos
   - Modo `bearer`: no-op
7. Implementar `resolveCookieDomains()` e `extractDomain()` conforme seção 14.2:
   - **SEGURANÇA:** `extractDomain()` deve validar que o hostname extraído de `req.hostname` corresponde a um padrão de domínio seguro (`/^[a-z0-9.-]+$/i`). Rejeitar hostnames com caracteres inválidos — usar domínio padrão configurado como fallback
   - **SEGURANÇA:** Antes de passar `req.hostname` para `resolveDomains`, strip de portas e validação de formato
   - Documentar no README (Fase 6) que `resolveDomains` DEVE validar contra allowlist de domínios configurados
8. Configurar cookies conforme tabela 14.1: HttpOnly, Secure (em prod), SameSite, paths
9. **Tipagem do retorno:** Definir tipos discriminados para os retornos de `deliverAuthResponse` e `deliverRefreshResponse` em vez de `Record<string, unknown>`:
   - Modo `cookie`: `{ user: AuthUser }`
   - Modo `bearer`/`both`: `{ user: AuthUser; accessToken: string; refreshToken: string }`
10. Escrever testes unitários com mocks de Request/Response para cada modo:
    - Teste de cada modo (cookie, bearer, both) para cada operação (auth, refresh, extract, clear)
    - Teste de `extractDomain` com hostname malformado → fallback seguro
    - Teste de `extractAccessToken` e `extractRefreshToken` com cookie e header

**Tarefas detalhadas para BruteForceService:**

1. Injetar `AuthRedisService` e `BYMAX_AUTH_OPTIONS`
2. Implementar `isLockedOut()`: ler `lf:{identifier}`, comparar com `maxAttempts`
3. Implementar `recordFailure()`: `INCR lf:{identifier}`, `EXPIRE lf:{identifier} windowSeconds`
4. Implementar `resetFailures()`: `DEL lf:{identifier}`
5. Implementar `getRemainingLockoutSeconds()`: `TTL lf:{identifier}`, retornar 0 se não bloqueado
6. Escrever testes unitários: lockout após N tentativas, reset, TTL correto

### 2.8 Providers padrão

**Arquivos a criar:**

| Arquivo                                 | Conteúdo                                                                                                                                                                                                                     |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/providers/no-op-email.provider.ts` | `NoOpEmailProvider implements IEmailProvider` — todos os métodos logam no console via `Logger` do NestJS, não enviam email real. Útil para desenvolvimento.                                                                  |
| `src/server/hooks/no-op-auth.hooks.ts`         | `NoOpAuthHooks implements IAuthHooks` — `beforeRegister` retorna `{ allowed: true }`, demais hooks são no-op. `onOAuthLogin` implementa lógica padrão segura (link se email bate, create se novo, reject se email não bate). |

**Tarefas detalhadas:**

1. Implementar `NoOpEmailProvider` com logs para cada método conforme seção 10.3
2. Implementar `NoOpAuthHooks` conforme seção 9.3, com verificação de email no `onOAuthLogin`
3. Exportar ambos no `index.ts`
4. Escrever testes unitários básicos

### 2.9 Atualização do barrel export

Atualizar `src/server/index.ts` com todos os exports da Fase 1:

- Constantes de injeção (6 Symbols)
- Todas as interfaces (8 arquivos)
- `AuthException` e `AUTH_ERROR_CODES`
- `AUTH_THROTTLE_CONFIGS`
- `NoOpEmailProvider` e `NoOpAuthHooks`

### 2.10 Validação da Fase 1

- [ ] `pnpm build` compila sem erros
- [ ] `pnpm test` passa com cobertura >= 80%
- [ ] Todas as interfaces estão exportadas e tipadas corretamente (`export type` para interfaces, `export` para valores)
- [ ] `AuthResult`, `PlatformAuthResult` e `MfaChallengeResult` definidos e exportados
- [ ] `resolveOptions()` valida jwt.secret, mfa.encryptionKey, jwt.algorithm e preserva funções após merge
- [ ] Encrypt/decrypt AES-256-GCM funciona em round-trip; IVs são únicos; authTag adulterado falha
- [ ] Prefixação de namespace Redis funciona corretamente
- [ ] `PasswordService` hash/compare round-trip funciona corretamente (scrypt com formato `scrypt:{salt}:{derived}`)
- [ ] `scrypt.ts` hash/compare com timing-safe comparison funciona corretamente
- [ ] `totp.ts` gera códigos válidos, verifica com janela, base32 decode funciona, URI builder correto
- [ ] `BruteForceService` bloqueia após N tentativas e reseta com sucesso
- [ ] `TokenManagerService` emite e verifica tokens; rejeita tokens sem `jti`
- [ ] `TokenDeliveryService` funciona nos 3 modos (cookie, bearer, both)
- [ ] 33 códigos de erro implementados em `AUTH_ERROR_CODES`
- [ ] `extractDomain()` valida hostname e rejeita formatos maliciosos

---

## 3. Fase 2 — Autenticação Core

**Duração:** 1 semana
**Dependência:** Fase 1 completa
**Objetivo:** Implementar o fluxo completo de autenticação — registro, login, logout, refresh, /me — incluindo guards, decorators, DTOs e o módulo dinâmico. Ao final desta fase, um usuário pode se registrar, logar, renovar tokens e deslogar.

### 3.1 Guards

**Arquivos a criar:**

| Arquivo                           | Conteúdo                                                                                                                                                                                                                                                                                  |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/guards/jwt-auth.guard.ts`    | `JwtAuthGuard implements CanActivate` — guard nativo NestJS (sem dependências externas de autenticação). Extrai token via `TokenDeliveryService.extractAccessToken()`, verifica com `jwtService.verify(token, { algorithms: ['HS256'] })`, valida claims (`type`, `jti`), consulta blacklist Redis, popula `request.user`. Respeita decorator `@Public()` via `Reflector`. |
| `src/server/guards/roles.guard.ts`       | `RolesGuard implements CanActivate` — lê roles requeridas do metadata `roles` (via `Reflector`), compara com `request.user.role` usando a hierarquia configurada em `roles.hierarchy`. Implementar `hasRole(userRole, requiredRole)` que verifica herança hierárquica.                    |
| `src/server/guards/user-status.guard.ts` | `UserStatusGuard implements CanActivate` — busca status do usuário no cache Redis (`us:{userId}`), se não encontrado busca no banco via `IUserRepository.findById()` e cacheia com TTL. Compara contra `blockedStatuses`. Lança erro específico por status (BANNED, INACTIVE, SUSPENDED). |

**Tarefas detalhadas:**

1. **JwtAuthGuard:**
   - Injetar `Reflector`, `JwtService` do `@nestjs/jwt`, `TokenDeliveryService`, `AuthRedisService`, `BYMAX_AUTH_OPTIONS`
   - Implementar `canActivate(context)`:
     - Checar `IS_PUBLIC_KEY` no metadata via `Reflector` — se `@Public()`, retornar `true` sem validar JWT
     - Extrair token via `TokenDeliveryService.extractAccessToken(request)` — suporta cookie e/ou header conforme `tokenDelivery`
     - Se token ausente, lançar `TOKEN_MISSING`
     - Verificar com `jwtService.verify(token, { algorithms: ['HS256'] })` — **OBRIGATÓRIO** pinar algoritmo para prevenir algorithm confusion (CVE-2015-9235)
     - Verificar que `payload.jti` existe e é string — se ausente, lançar `TOKEN_INVALID`
     - Verificar `payload.type === 'dashboard'` — rejeitar tokens `platform` e `mfa_challenge`
     - Consultar blacklist Redis via `authRedis.isBlacklisted(jti)` (`rv:{jti}`) — se blacklisted, lançar `TOKEN_REVOKED`
     - Popular `request.user` com o payload decodificado
     - Retornar `true`
   - Tratar erros de JWT (expirado, malformado, assinatura inválida) com `AuthException` e códigos específicos

2. **RolesGuard:**
   - Injetar `Reflector` e `BYMAX_AUTH_OPTIONS`
   - Ler roles requeridas do metadata `ROLES_KEY`
   - Se nenhum role requerido, permitir acesso
   - Implementar `hasRole()` conforme seção 8.2: verificar igualdade direta + herança na hierarquia (lookup single-level, não recursivo)
   - **IMPORTANTE:** A hierarquia deve ser totalmente denormalizada — cada role deve listar TODOS os descendentes transitivos, não apenas filhos diretos. Ex: `OWNER: ['ADMIN', 'MEMBER', 'VIEWER']`, não apenas `OWNER: ['ADMIN']`. Documentar no README com aviso proeminente
   - Lançar `INSUFFICIENT_ROLE` se role não satisfaz

3. **UserStatusGuard:**
   - Injetar `AuthRedisService`, `BYMAX_AUTH_USER_REPOSITORY`, `BYMAX_AUTH_OPTIONS`
   - Implementar fluxo conforme seção 8.3:
     1. Extrair `user.sub` do request
     2. Buscar `us:{userId}` no Redis
     3. Se cache miss, buscar no banco e cachear com `userStatusCacheTtlSeconds`
     4. Verificar contra `blockedStatuses`
     5. Mapear status para erro específico (BANNED → `ACCOUNT_BANNED`, etc.)
   - Se rota pública (sem user), retornar true

4. Escrever testes unitários para cada guard:
   - JwtAuthGuard: rota pública, token válido, token ausente, token expirado, token de tipo errado, token na blacklist, token sem jti
   - RolesGuard: role exato, role herdado, role insuficiente
   - UserStatusGuard: status ACTIVE, BANNED, INACTIVE, cache hit, cache miss

### 3.2 Decorators

**Arquivos a criar:**

| Arquivo                                    | Conteúdo                                                                                                 |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| `src/server/decorators/current-user.decorator.ts` | `@CurrentUser(property?)` — `createParamDecorator` que extrai `request.user` ou `request.user[property]` |
| `src/server/decorators/roles.decorator.ts`        | `@Roles(...roles)` — `SetMetadata(ROLES_KEY, roles)` para uso com `RolesGuard`                           |
| `src/server/decorators/public.decorator.ts`       | `@Public()` — `SetMetadata(IS_PUBLIC_KEY, true)` para pular `JwtAuthGuard`                               |

**Tarefas detalhadas:**

1. Implementar `@CurrentUser()` com suporte a extração de propriedade específica (ex: `@CurrentUser('sub')`). **Nota sobre tipagem:** `createParamDecorator` do NestJS retorna `any` por design — narrowing no call site requer overloads de tipo exportados separadamente ou instrução para o consumidor usar type assertion (ex: `@CurrentUser('sub') userId: string`). Documentar no JSDoc que o parâmetro deve ser tipado explicitamente pelo consumidor
2. Implementar `@Roles()` com chave `ROLES_KEY` consistente com o `RolesGuard`
3. Implementar `@Public()` com chave `IS_PUBLIC_KEY` consistente com o `JwtAuthGuard`
4. Escrever testes unitários para cada decorator
5. Exportar todos no `index.ts`

### 3.3 DTOs

**Arquivos a criar:**

| Arquivo                   | Conteúdo                                                                                                                                                                                                                                                        |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/dto/register.dto.ts` | `RegisterDto` com validadores: `@IsEmail() email`, `@IsString() @MinLength(8) @MaxLength(128) password`, `@IsString() @MinLength(2) name`, `@IsString() @IsNotEmpty() tenantId`                                                                                  |
| `src/server/dto/login.dto.ts`    | `LoginDto` com validadores: `@IsEmail() email`, `@IsString() @MaxLength(128) password`, `@IsString() @IsNotEmpty() tenantId`. **Sem `@MinLength` na senha** — deliberado para não revelar se a senha é muito curta antes da comparação scrypt (anti-enumeração). |

**Tarefas detalhadas:**

1. Implementar DTOs com validadores do `class-validator`
2. `@MaxLength(128)` na senha como limite razoável de input — prevenir DoS via payloads excessivamente grandes no scrypt
3. `@IsNotEmpty()` em `tenantId` em todos os DTOs que o utilizam (Register, Login, ForgotPassword, ResetPassword) para prevenir empty string passando pelo `@IsString()`
4. Adicionar JSDoc no `LoginDto.password`: "Deliberadamente sem `@MinLength` — toda senha passa para comparação scrypt para não revelar se é muito curta"
5. Escrever testes de validação: email inválido, senha curta, senha longa, nome curto, tenantId vazio
6. Exportar DTOs no `index.ts`

### 3.4 AuthService

**Arquivo:** `src/server/services/auth.service.ts`

**Tarefas detalhadas:**

1. Injetar: `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, `BYMAX_AUTH_EMAIL_PROVIDER`, `BYMAX_AUTH_HOOKS`, `PasswordService`, `TokenManagerService`, `BruteForceService`, `AuthRedisService`, `OtpService`, `@Optional() SessionService`

> **Nota de dependência:** `OtpService` é movido para a Fase 2 (originalmente planejado na Fase 4) pois `AuthService.register()` e `verifyEmail()` o utilizam quando `emailVerification.required = true`. A implementação é pequena e autocontida (generate, store, verify). **Implementar conforme detalhado na seção 5.1** (a documentação completa está lá por razões históricas). `SessionService` é injetado com `@Optional()` — a integração real acontece na Fase 4 (seção 5.8), mas o stub permite compilação limpa.

2. **Implementar `register()`** conforme Apêndice A.1:
   - Resolver `tenantId` via `tenantIdResolver` se fornecido, senão usar do DTO
   - Executar `hooks.beforeRegister()` — se `allowed: false`, lançar exceção com `reason`
   - Aplicar `modifiedData` do hook (role, status, emailVerified)
   - Verificar email existente via `userRepo.findByEmail(email, tenantId)`
   - Se existe, lançar `EMAIL_ALREADY_EXISTS`
   - Hash da senha via `passwordService.hash()`
   - Criar usuário via `userRepo.create()` com status padrão do hook ou `'ACTIVE'`
   - Se `emailVerification.required`: gerar OTP, armazenar, enviar via email provider
   - Emitir tokens via `tokenManager.issueTokens()`
   - Executar `hooks.afterRegister()` (erros logados, não propagados)
   - Retornar `AuthResult`

3. **Implementar `login()`** conforme Apêndice A.2:
   - Resolver `tenantId`
   - Computar identificador de brute-force: `sha256(tenantId + ':' + email)`
   - Verificar lockout via `bruteForce.isLockedOut()`
   - Se locked, obter TTL restante e lançar `ACCOUNT_LOCKED` com header `Retry-After`
   - Executar `hooks.beforeLogin()` (erros propagados)
   - Buscar usuário via `userRepo.findByEmail()`
   - Se não encontrado, registrar falha de brute-force e lançar `INVALID_CREDENTIALS`
   - Verificar status contra `blockedStatuses` — lançar erro específico
   - Se `emailVerification.required` e `!emailVerified`, lançar `EMAIL_NOT_VERIFIED`
   - Comparar senha via `passwordService.compare()`
   - Se falhar, registrar falha e lançar `INVALID_CREDENTIALS`
   - Se `user.mfaEnabled`:
     - Emitir `mfaTempToken` via `tokenManager.issueMfaTempToken(userId, 'dashboard')`
     - Retornar `MfaChallengeResult`
   - Se não MFA:
     - Resetar brute-force
     - Emitir tokens
     - Atualizar `lastLoginAt`
     - Executar `hooks.afterLogin()`
     - Retornar `AuthResult`

4. **Implementar `logout()`** conforme Apêndice A.5:
   - Decodificar access token para extrair `jti` e tempo restante
   - Adicionar `jti` na blacklist: `rv:{jti}` com TTL = tempo restante do JWT
   - Deletar refresh token: `rt:{sha256(refreshToken)}`
   - Se sessions habilitado, remover do SET
   - Executar `hooks.afterLogout()`

5. **Implementar `refresh()`:**
   - Delegar para `tokenManager.reissueTokens()`
   - Retornar `AuthResult`

6. **Implementar `getMe()`:**
   - Buscar usuário via `userRepo.findById(userId)`
   - Se não encontrado, lançar `TOKEN_INVALID`
   - Retornar `AuthUser`

7. **Implementar `verifyEmail()`:**
   - Computar identifier: `sha256(tenantId + ':' + email)`
   - Verificar OTP via `otpService.verify('email_verification', identifier, otp)`
   - Atualizar `emailVerified` via `userRepo.updateEmailVerified(userId, true)`
   - Executar `hooks.afterEmailVerified()`

8. **Implementar `resendVerificationEmail()`:**
   - **Cooldown atômico de reenvio:** Usar `SET resend:email_verification:{sha256(tenantId+':'+email)} 1 NX EX 60` via `AuthRedisService` (prefixo `auth:` adicionado automaticamente). `NX` garante que apenas a primeira requisição concorrente prossegue. Se retornar `nil`, cooldown ativo → retornar sucesso sem gerar novo OTP
   - Buscar usuário, gerar novo OTP, armazenar, enviar via email
   - **Normalização de timing:** aguardar tempo constante independente de usuário existir (previne side-channel de enumeração)

9. Escrever testes unitários abrangentes:
   - Register: sucesso, email duplicado, hook rejeita, verificação de email
   - Login: sucesso, credenciais inválidas, brute-force lockout, MFA redirect, conta bloqueada
   - Logout: blacklist de JWT, remoção de refresh
   - Refresh: rotação com sucesso, token inválido, grace window
   - GetMe: usuário encontrado, não encontrado

### 3.5 AuthController

**Arquivo:** `src/server/controllers/auth.controller.ts`

**Tarefas detalhadas:**

1. Aplicar decorators: `@Controller(routePrefix)` com prefixo dinâmico
2. Implementar 7 endpoints conforme tabela 7.1:

   | Método | Rota                   | Decorators                                   | Implementação                                                                                               |
   | ------ | ---------------------- | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
   | POST   | `/register`            | `@Public()`, `@Throttle(register)`           | Chamar `authService.register()`, entregar via `tokenDeliveryService`                                        |
   | POST   | `/login`               | `@Public()`, `@Throttle(login)`              | Chamar `authService.login()`, entregar via `tokenDeliveryService` (ou retornar `MfaChallengeResult` direto) |
   | POST   | `/logout`              | `@UseGuards(JwtAuthGuard)`                   | Extrair tokens via `tokenDeliveryService`, chamar `authService.logout()`, limpar sessão                     |
   | POST   | `/refresh`             | `@Public()`, `@Throttle(refresh)`            | Extrair refresh via `tokenDeliveryService`, chamar `authService.refresh()`, entregar novos tokens           |
   | GET    | `/me`                  | `@UseGuards(JwtAuthGuard)`                   | Chamar `authService.getMe(user.sub)`                                                                        |
   | POST   | `/verify-email`        | `@Public()`, `@Throttle(verifyEmail)`        | Chamar `authService.verifyEmail()`                                                                          |
   | POST   | `/resend-verification` | `@Public()`, `@Throttle(resendVerification)` | Chamar `authService.resendVerificationEmail()`                                                              |

3. Usar `@Res({ passthrough: true })` para preservar interceptors do NestJS quando manipulando cookies
4. Extrair `req.ip` e `req.headers['user-agent']` para passar aos services
5. Escrever testes unitários do controller (mock de services)

### 3.6 Módulo dinâmico

**Arquivo:** `src/server/bymax-auth.module.ts`

**Tarefas detalhadas:**

1. Implementar `BymaxAuthModule` como `@Module({})` com método estático `registerAsync()`:
   - Aceitar `imports`, `inject`, `useFactory`, `providers`
   - Usar `DynamicModule` com `module: BymaxAuthModule`
   - Seguir o padrão do `@nestjs/jwt` `registerAsync`: (1) `useFactory` resolve apenas configuração, (2) providers do usuário (repositórios, email, hooks, Redis) são registrados diretamente via array `providers`, (3) o módulo merge internamente com seus próprios providers

2. No `useFactory`:
   - Resolver opções via `resolveOptions(userOptions)` — aplica defaults e valida
   - Registrar opções resolvidas como provider com token `BYMAX_AUTH_OPTIONS`

3. Registrar providers obrigatórios:
   - `AuthRedisService`
   - `PasswordService`
   - `TokenManagerService`
   - `TokenDeliveryService`
   - `BruteForceService`
   - `OtpService` (movido da Fase 4 — necessário para email verification no `AuthService`)
   - `AuthService`
   - `JwtStrategy`
   - `JwtAuthGuard`, `RolesGuard`, `UserStatusGuard`

4. Registrar providers condicionais:
   - Se `BYMAX_AUTH_HOOKS` não fornecido → usar `@Optional() @Inject(BYMAX_AUTH_HOOKS)` nos services e registrar `NoOpAuthHooks` como fallback
   - Se `BYMAX_AUTH_EMAIL_PROVIDER` não fornecido → registrar `NoOpEmailProvider`

5. **Registrar controllers condicionais** — mecanismo técnico:
   - Construir o array `controllers` dinamicamente dentro do método `registerAsync` baseado nas opções resolvidas
   - NestJS suporta `controllers` no retorno de `DynamicModule` — construir o array antes de retornar o módulo
   - `AuthController` se `controllers.auth !== false`
   - Demais controllers adicionados em fases posteriores
   - **Alternativa se necessário:** usar `RouterModule.register()` nos imports do `DynamicModule` para prefixo dinâmico de rotas

6. **Estratégia de guards:** NÃO registrar guards como `APP_GUARD` global (efeito colateral no app host). Cada controller do pacote aplica guards explicitamente via `@UseGuards()`. Documentar no README que o app host pode registrar guards globalmente se desejar.

7. **Prefixo de rotas dinâmico:** Usar `RouterModule.register([{ path: routePrefix, module: BymaxAuthModule }])` dentro dos imports do `DynamicModule` para aplicar o prefixo configurável. Isso é mais confiável que `@Controller(dynamicPrefix)` que requer string estática.

8. Importar `JwtModule.registerAsync()` com `secret` e `signOptions` das opções resolvidas

9. Escrever testes de integração do módulo:
    - Módulo compila e inicializa com configuração mínima
    - Validação de secret falha com secret fraco
    - Controllers são registrados condicionalmente (auth: false → AuthController ausente)
    - Prefixo de rotas funciona corretamente

### 3.7 Atualização do barrel export

Adicionar ao `index.ts`:

- `export { BymaxAuthModule }`
- `export { AuthService }` e `export type { AuthResult, MfaChallengeResult }` (já definidos na Fase 1)
- Guards: `export { JwtAuthGuard, RolesGuard, UserStatusGuard }`
- Decorators: `export { CurrentUser, Roles, Public }`
- DTOs: `export { RegisterDto, LoginDto }`

### 3.8 Validação da Fase 2

- [ ] Fluxo completo register → login → refresh → logout funcional
- [ ] Guards funcionam corretamente (público, autenticado, roles)
- [ ] `RolesGuard` respeita hierarquia (OWNER acessa endpoints restritos a ADMIN)
- [ ] TokenDelivery funciona nos 3 modos (cookie, bearer, both)
- [ ] Brute-force bloqueia após N tentativas, com `Retry-After` header
- [ ] Módulo dinâmico compila e inicializa
- [ ] Controllers são registrados condicionalmente (auth: false → sem AuthController)
- [ ] Prefixo de rotas dinâmico funciona via RouterModule
- [ ] `tenantIdResolver` é chamado quando fornecido, e `tenantId` do body é ignorado
- [ ] `pnpm build` sem erros
- [ ] `pnpm test` com cobertura >= 80%

---

## 4. Fase 3 — Autenticação Multi-Fator (MFA)

**Duração:** 1 semana
**Dependência:** Fase 2 completa
**Objetivo:** Implementar MFA completo baseado em TOTP — setup, verificação, desafio durante login, desativação, recovery codes. Ao final, um usuário pode ativar MFA no app autenticador, fazer login com código TOTP e recuperar acesso via recovery codes.

### 4.1 MfaService

**Arquivo:** `src/server/services/mfa.service.ts`

**Tarefas detalhadas:**

1. Injetar: `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, `@Optional() BYMAX_AUTH_PLATFORM_USER_REPOSITORY`, `AuthRedisService`, `TokenManagerService`, `@Optional() SessionService`, `BruteForceService`, `BYMAX_AUTH_EMAIL_PROVIDER`, `BYMAX_AUTH_HOOKS`, `PasswordService`
   - `BYMAX_AUTH_PLATFORM_USER_REPOSITORY` é `@Optional()` pois só existe quando `platformAdmin.enabled`. Se `context === 'platform'` e o repositório não está disponível, lançar erro descritivo
   - `SessionService` é `@Optional()` pois só existe quando `sessions.enabled`

2. **Implementar `setup(userId)`:**
   - Verificar se MFA já está habilitado → lançar `MFA_ALREADY_ENABLED`
   - **Idempotência:** Verificar se já existe setup em andamento (`mfa_setup:{sha256(userId)}`) — se existe e TTL > 0, retornar o resultado existente em vez de gerar novo (previne CPU waste com hash de recovery codes em chamadas concorrentes)
   - Gerar secret TOTP: 20 bytes aleatórios via `crypto.randomBytes(20)`, codificado em Base32
   - Criptografar secret com `aes-gcm.encrypt(secret, encryptionKey)`
   - Gerar recovery codes: 8 códigos aleatórios (formato: `xxxx-xxxx-xxxx` com caracteres alfanuméricos)
   - Fazer hash scrypt de cada recovery code via `PasswordService.hash()`
   - Armazenar no Redis temporariamente: `mfa_setup:{sha256(userId)}` → `{ encryptedSecret, hashedCodes }`, TTL 10 min. **Nota:** usa `sha256(userId)` como chave conforme princípio de hashing de identificadores da spec
   - Gerar URI do QR code via `buildTotpUri(secret, email, issuer)` de `src/server/crypto/totp.ts` — formato padrão `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}`
   - Retornar `MfaSetupResult { secret, qrCodeUri, recoveryCodes }`
   - **Nota sobre `aes-gcm.ts`:** Já implementado na Fase 1 (seção 2.5) — aqui é consumido, não criado. Desvio intencional da spec que o lista na Fase 3.

3. **Implementar `verifyAndEnable(userId, code)`:**
   - Buscar setup temporário no Redis `mfa_setup:{sha256(userId)}`
   - Se não encontrado, lançar `MFA_SETUP_REQUIRED`
   - Descriptografar secret
   - Validar código TOTP com `verifyTotp(secret, code, totpWindow)` de `src/server/crypto/totp.ts`
   - Se inválido, lançar `MFA_INVALID_CODE`
   - Persistir no banco via `userRepo.updateMfa({ mfaEnabled: true, mfaSecret: encrypted, mfaRecoveryCodes: hashed })`
   - Deletar setup temporário do Redis
   - **SEGURANÇA:** Invalidar todas as sessões ativas do usuário via `sess:{userId}` SET — revogar refresh tokens (DEL `rt:{sessionHash}` para cada membro do SET). **Limitação:** access tokens ativos NÃO podem ser blacklisted pois `jti` não é armazenado no `rt:` record. Tokens existentes (sem `mfaVerified: true`) permanecem válidos por até `accessExpiresIn` (padrão 15min). Endpoints sensíveis DEVEM usar `MfaRequiredGuard` para mitigar essa janela
   - Enviar notificação via `emailProvider.sendMfaEnabledNotification()`
   - Executar `hooks.afterMfaEnabled()`

4. **Implementar `challenge(mfaTempToken, code, ip, userAgent)`:**
   - Verificar `mfaTempToken` via `tokenManager.verifyMfaTempToken()` — retorna `{ userId, context }` (não apenas `string`)
   - Usar `context` para determinar repositório e tipo de resultado:
   - Computar identificador de brute-force: `sha256(userId)`
   - Verificar lockout via `bruteForce.isLockedOut()`
   - Buscar usuário no repositório correto conforme `context`:
     - `dashboard` → `userRepo.findById(userId)`
     - `platform` → `platformUserRepo.findById(userId)`
   - Descriptografar `mfaSecret`
   - Tentar validar como código TOTP (6 dígitos)
   - Se código TOTP: verificar com `verifyTotp()` de `src/server/crypto/totp.ts`, verificar anti-replay (`tu:{userId}:{code}`)
   - Se não TOTP (recovery code): verificar contra `mfaRecoveryCodes` via `verifyRecoveryCode()`
   - Se inválido: registrar falha, se 5+ falhas → revogar `mfaTempToken` (forçar re-autenticação), lançar `MFA_INVALID_CODE`
   - Se válido:
     - Se TOTP: marcar código como usado no Redis (`tu:{userId}:{code}`, TTL 90s)
     - Se recovery code: remover da lista via `userRepo.updateMfa()`
     - Resetar brute-force
     - Emitir tokens com `mfaVerified: true` conforme contexto:
       - `dashboard` → `tokenManager.issueTokens(user, ip, userAgent, { mfaVerified: true })` → retornar `AuthResult`
       - `platform` → emitir tokens de plataforma → retornar `PlatformAuthResult`
     - Criar sessão (se habilitado e contexto dashboard)
     - Executar `hooks.afterLogin()`
   - Retornar resultado conforme contexto

5. **Implementar `disable(userId, code)`:**
   - Buscar usuário, verificar MFA habilitado → se não, lançar `MFA_NOT_ENABLED`
   - Verificar brute-force lockout via `bruteForce.isLockedOut(sha256(userId))` (mesmo identificador do `challenge`)
   - Descriptografar secret, validar código TOTP
   - Se inválido, registrar falha via `bruteForce.recordFailure(sha256(userId))`, lançar `MFA_INVALID_CODE`
   - Se válido, resetar brute-force
   - Desabilitar via `userRepo.updateMfa({ mfaEnabled: false, mfaSecret: null, mfaRecoveryCodes: null })`
   - Notificar via `emailProvider.sendMfaDisabledNotification()`
   - Executar `hooks.afterMfaDisabled()`

6. **Implementar `encryptSecret()` e `decryptSecret()`:** delegar para `aes-gcm.ts`

7. **Implementar `hashRecoveryCodes(count)`:**
   - Gerar `count` códigos aleatórios com `crypto.randomBytes`
   - Formatar como `xxxx-xxxx-xxxx`
   - Hash cada código com `PasswordService.hash()` (scrypt via `node:crypto`)
   - Retornar `{ plainCodes, hashedCodes }`

8. **Implementar `verifyRecoveryCode(code, hashedCodes)`:**
   - Iterar sobre `hashedCodes`, comparar com `PasswordService.compare()` (scrypt + `crypto.timingSafeEqual`)
   - Retornar índice se encontrado, -1 se não

9. Escrever testes unitários abrangentes:
   - Setup: gera secret, QR code URI, recovery codes
   - VerifyAndEnable: código correto habilita, código incorreto rejeita
   - Challenge: TOTP correto, recovery code correto, brute-force lockout, anti-replay
   - Challenge com contexto platform: retorna PlatformAuthResult
   - Disable: código correto desabilita, MFA não habilitado rejeita

### 4.2 MfaController

**Arquivo:** `src/server/controllers/mfa.controller.ts`

**Tarefas detalhadas:**

1. Prefixo: `{routePrefix}/mfa`
2. Implementar 4 endpoints conforme tabela 7.2:

   | Método | Rota         | Guards         | Throttle       | Implementação                                                        |
   | ------ | ------------ | -------------- | -------------- | -------------------------------------------------------------------- |
   | POST   | `/setup`     | `JwtAuthGuard` | `mfaSetup`     | Chamar `mfaService.setup(user.sub)`                                  |
   | POST   | `/verify`    | `JwtAuthGuard` | —              | Chamar `mfaService.verifyAndEnable()`                                |
   | POST   | `/challenge` | Público        | `mfaChallenge` | Chamar `mfaService.challenge()`, entregar via `tokenDeliveryService` |
   | POST   | `/disable`   | `JwtAuthGuard` | `mfaDisable`   | Chamar `mfaService.disable()`                                        |

3. O endpoint `/challenge` é público pois o usuário ainda não tem JWT de sessão — usa `mfaTempToken` no body
4. Escrever testes unitários do controller

### 4.3 DTOs de MFA

**Arquivos a criar:**

| Arquivo                        | Campos                                                                                                                                                                                                                                         |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/dto/mfa-verify.dto.ts`    | `@IsString() @IsNotEmpty() @Length(6, 6) code`                                                                                                                                                                                                 |
| `src/server/dto/mfa-challenge.dto.ts` | `@IsString() @IsNotEmpty() mfaTempToken`, `@IsString() @IsNotEmpty() @MaxLength(128) code`                                                                                                                                                     |
| `src/server/dto/mfa-disable.dto.ts`   | `@IsString() @IsNotEmpty() @Length(6, 6) code`. **Nota:** Aceita apenas TOTP — recovery codes não são aceitos para desativar MFA (decisão de design da spec). Documentar no README que recuperação sem TOTP requer intervenção administrativa. |

### 4.4 Guard e Decorator de MFA

**Arquivos a criar:**

| Arquivo                                | Conteúdo                                                                                                                       |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `src/server/guards/mfa-required.guard.ts`     | Verifica `request.user.mfaVerified === true`. Se MFA habilitado e não verificado, lança `MFA_REQUIRED`. Respeita `@SkipMfa()`. |
| `src/server/decorators/skip-mfa.decorator.ts` | `@SkipMfa()` — `SetMetadata(SKIP_MFA_KEY, true)`                                                                               |

### 4.5 Integração no módulo dinâmico

- Registrar `MfaService` condicionalmente (quando `mfa` configurado)
- Registrar `MfaController` condicionalmente (quando `mfa` configurado e `controllers.mfa !== false`)
- Registrar `MfaRequiredGuard`

### 4.6 Atualização do barrel export

Adicionar ao `index.ts`:

- `export { MfaRequiredGuard }`
- `export { SkipMfa }`
- `export type { MfaSetupResult }`
- DTOs: `export { MfaVerifyDto, MfaChallengeDto, MfaDisableDto }`

### 4.7 Validação da Fase 3

- [ ] Fluxo setup → verify → challenge funcional
- [ ] Setup é idempotente (chamada concorrente retorna mesmo resultado)
- [ ] Recovery codes funcionam para acesso alternativo
- [ ] Todos os recovery codes consumidos → usuário bloqueado sem TOTP (documentar cenário)
- [ ] Anti-replay de código TOTP previne reutilização
- [ ] Brute-force em MFA challenge funciona (lockout + revogação de temp token após 5 falhas)
- [ ] Brute-force identifier é `sha256(userId)` (independente do login brute-force por email)
- [ ] Challenge com `context: 'platform'` retorna `PlatformAuthResult` (compilação ok com interface da Fase 1)
- [ ] Challenge com token `dashboard` no endpoint de plataforma → rejeitado
- [ ] Após habilitar MFA, todas as sessões existentes são invalidadas
- [ ] Disable exige código TOTP correto (recovery codes não aceitos)
- [ ] `@SkipMfa()` bypassa `MfaRequiredGuard`
- [ ] Cobertura >= 80%

---

## 5. Fase 4 — Sessões e Reset de Senha

**Duração:** 1 semana
**Dependência:** Fase 2 completa
**Objetivo:** Implementar gerenciamento de sessões (listagem, revogação, FIFO eviction) e fluxo completo de reset de senha (token e OTP), incluindo verificação de email.

### 5.1 OtpService

**Arquivo:** `src/server/services/otp.service.ts`

> **Nota de fase:** `OtpService` é criado na **Fase 2** (movido da Fase 4 original) pois `AuthService.verifyEmail()` o utiliza. Nesta seção, documenta-se a implementação completa para referência, mas o código já existe quando a Fase 4 inicia.

**Tarefas detalhadas:**

1. **Implementar `generate(length = 6)`:**
   - Usar `crypto.randomInt(0, 10 ** length)` — NUNCA `Math.random()`
   - Pad com zeros à esquerda: `String(num).padStart(length, '0')`

2. **Implementar `store(purpose, identifier, code, ttlSeconds)`:**
   - Chave Redis: `otp:{purpose}:{identifier}`
   - Valor: JSON `{ code, attempts: 0 }`
   - TTL: `ttlSeconds`

3. **Implementar `verify(purpose, identifier, code)`:**
   - Buscar no Redis por `otp:{purpose}:{identifier}`
   - Se não encontrado → lançar `OTP_EXPIRED`
   - Verificar `attempts >= 5` → lançar `OTP_MAX_ATTEMPTS`
   - **Comparação constant-time:** Converter ambos os valores para `Buffer.from(code, 'utf8')` antes de chamar `crypto.timingSafeEqual()`. Se os buffers têm comprimento diferente → retornar `OTP_INVALID` sem chamar `timingSafeEqual` (diferença de comprimento já é suficiente para rejeitar; `timingSafeEqual` lança `RangeError` com buffers de tamanhos diferentes)
   - Se inválido → incrementar attempts, lançar `OTP_INVALID`
   - Se válido → deletar do Redis
   - **Normalização de timing interna:** Todas as branches (expired, max attempts, invalid, valid) devem ter tempo de resposta similar. Usar `const start = Date.now()` + `sleep(Math.max(0, 100 - elapsed))` antes de retornar/lançar
   - **Retorna `void`** — o caller já conhece o identifier/purpose (diferente de `verifyMfaTempToken` que retorna userId pois o caller não sabe a quem pertence o token)

4. **Implementar `incrementAttempts()`:** incrementar campo `attempts` no Redis

5. Escrever testes: geração de comprimento correto, armazenamento, verificação, expiração, max attempts, comparação com comprimento diferente

### 5.2 SessionService

**Arquivo:** `src/server/services/session.service.ts`

**Tarefas detalhadas:**

1. **Implementar `createSession(userId, refreshToken, ip, userAgent)`:**
   - Computar `sessionHash = sha256(refreshToken)`
   - Armazenar detalhes: `sd:{sessionHash}` → JSON `{ device: parseUserAgent(userAgent), ip, createdAt, lastActivityAt }`
   - Adicionar ao SET: `SADD sess:{userId} sessionHash`
   - TTL do `sd:` e do SET = `refreshExpiresInDays * 86400`
   - Chamar `enforceSessionLimit(userId, user)`
   - Executar `hooks.onNewSession()`
   - Se configurado, enviar alerta de novo login via `emailProvider.sendNewSessionAlert()`

2. **Implementar `listSessions(userId, currentSessionHash?)`:**
   - Buscar SET: `SMEMBERS sess:{userId}`
   - Para cada hash, buscar detalhes: `GET sd:{hash}`
   - Marcar `isCurrent: hash === currentSessionHash`
   - Ordenar por `createdAt` descendente
   - Retornar `SessionInfo[]`

3. **Implementar `revokeSession(userId, sessionHash)`:**
   - **Validação de propriedade:** `SISMEMBER sess:{userId} sessionHash`
   - Se não pertence ao usuário → lançar `SESSION_NOT_FOUND` (previne BOLA/IDOR)
   - Remover refresh token: `DEL rt:{sessionHash}` (nota: sessionHash = sha256 do refresh token)
   - Remover do SET: `SREM sess:{userId} sessionHash`
   - Deletar detalhes: `DEL sd:{sessionHash}`

4. **Implementar `revokeAllExceptCurrent(userId, currentSessionHash)`:**
   - Buscar todas as sessões do SET
   - Filtrar excluindo `currentSessionHash`
   - Revogar cada uma individualmente

5. **Implementar `enforceSessionLimit(userId, user)`:**
   - Resolver limite: `maxSessionsResolver(user)` → `defaultMaxSessions` → 5
   - Contar sessões ativas: `SCARD sess:{userId}`
   - Se exceder: aplicar FIFO — ordenar por `createdAt`, revogar a mais antiga

6. Implementar `parseUserAgent(ua)`: extrair dispositivo/browser do user-agent string

7. **Implementar `rotateSession(userId, oldRefreshToken, newRefreshToken)`:**
   - Chamado durante refresh token rotation para manter `sess:{userId}` e `sd:` sincronizados
   - Remover `sha256(oldRefreshToken)` do SET `sess:{userId}`
   - Adicionar `sha256(newRefreshToken)` ao SET
   - Atualizar `sd:{sha256(newRefreshToken)}` com `lastActivityAt` atualizado
   - Deletar `sd:{sha256(oldRefreshToken)}`
   - Renovar TTL do SET `sess:{userId}` com `EXPIRE`
   - **Atomicidade:** Estender o script Lua de rotação de refresh (spec seção 12.4) para aceitar chaves `sess:` e `sd:` como KEYS adicionais e executar SREM/SADD/SET/DEL atomicamente. O script deve ser parametrizável com prefixos (`rt/rp/sess/sd` para dashboard, `prt/prp/psess/psd` para plataforma) em vez de hardcodar prefixos. Isso previne inconsistências se o processo crashar entre a rotação do token e a atualização das sessões
   - **Desvio da spec:** `rotateSession()` não existe na API de `SessionService` da spec seção 6.4. É uma adição necessária para manter consistência do SET de sessões durante refresh

8. Escrever testes: criar sessão, listar, revogar (própria e de outro usuário), FIFO eviction, isCurrent, rotação de sessão no refresh

### 5.3 SessionController

**Arquivo:** `src/server/controllers/session.controller.ts`

**Tarefas detalhadas:**

1. Prefixo: `{routePrefix}/sessions`
2. Implementar 3 endpoints conforme tabela 7.4:

   | Método | Rota   | Guards         | Implementação                                  |
   | ------ | ------ | -------------- | ---------------------------------------------- |
   | GET    | `/`    | `JwtAuthGuard` | Listar sessões com `currentSessionHash` do JWT |
   | DELETE | `/:id` | `JwtAuthGuard` | Revogar sessão por `sessionHash`               |
   | DELETE | `/all` | `JwtAuthGuard` | Revogar todas exceto atual                     |

3. Extrair `currentSessionHash` do JWT ou calcular do refresh token do cookie
4. Escrever testes do controller

### 5.4 PasswordResetService

**Arquivo:** `src/server/services/password-reset.service.ts`

**Dependências injetadas:** `BYMAX_AUTH_OPTIONS`, `BYMAX_AUTH_USER_REPOSITORY`, `BYMAX_AUTH_EMAIL_PROVIDER`, `BYMAX_AUTH_HOOKS`, `OtpService`, `PasswordService`, `AuthRedisService`, `@Optional() SessionService` (para revogar todas as sessões após reset de senha)

**Tarefas detalhadas:**

1. **Implementar `initiateReset(email, tenantId)`:**
   - Buscar usuário por email — NÃO revelar se existe (sempre retornar sucesso)
   - Se método = `token`:
     - Gerar token seguro via `generateSecureToken(32)`
     - Armazenar no Redis: `pr:{sha256(token)}` → userId, TTL = `tokenTtlSeconds`
     - Enviar via `emailProvider.sendPasswordResetToken()`
   - Se método = `otp`:
     - Gerar OTP via `otpService.generate()`
     - Armazenar via `otpService.store('password_reset', sha256(tenantId + ':' + email), otp, otpTtlSeconds)`
     - Enviar via `emailProvider.sendPasswordResetOtp()`
   - **Normalização de timing:** aguardar tempo constante para prevenir side-channel

2. **Implementar `resetPassword(dto)`:**
   - Se `verifiedToken` presente: validar via Redis (`prv:{sha256(verifiedToken)}` → `{ email, tenantId }`)
     - Verificar que `tenantId` da requisição corresponde ao armazenado (previne cross-tenant)
   - Se `token` presente: validar via Redis (`pr:{sha256(token)}` → userId)
   - Se `otp` presente: validar via `otpService.verify()`
   - Hash da nova senha
   - Atualizar via `userRepo.updatePassword()`
   - Consumir token/OTP do Redis
   - Invalidar todas as sessões do usuário
   - Invalidar cache de status: `DEL us:{userId}`
   - Executar `hooks.afterPasswordReset()`

3. **Implementar `verifyOtp(email, otp, tenantId)`:**
   - Computar identifier: `sha256(tenantId + ':' + email)`
   - Validar OTP via `otpService.verify('password_reset', identifier, otp)` — CONSOME o OTP
   - Gerar token temporário de verificação (UUID)
   - Armazenar: `prv:{sha256(token)}` → `{ email, tenantId }`, TTL 5 minutos
   - Retornar `{ verifiedToken }`

4. **Implementar `resendOtp(email, tenantId)`:**
   - **Cooldown atômico de reenvio:** Usar `SET resend:password_reset:{sha256(tenantId+':'+email)} 1 NX EX 60` — `NX` garante que apenas a primeira requisição concorrente prossegue (previne TOCTOU race). Se retornar `nil`, cooldown já ativo → retornar sucesso sem gerar novo OTP
   - Buscar usuário — sempre retornar sucesso (anti-enumeração)
   - Se existe: gerar novo OTP, armazenar, enviar
   - Normalização de timing

5. Escrever testes: reset por token, reset por OTP, reset por verifiedToken, cross-tenant rejected, usuário inexistente (sem leak), cooldown de reenvio respeitado

### 5.5 PasswordResetController

**Arquivo:** `src/server/controllers/password-reset.controller.ts`

**Tarefas detalhadas:**

1. Prefixo: `{routePrefix}/password`
2. Implementar 4 endpoints conforme tabela 7.3:

   | Método | Rota               | Throttle            | Implementação            |
   | ------ | ------------------ | ------------------- | ------------------------ |
   | POST   | `/forgot-password` | `forgotPassword`    | Chamar `initiateReset()` |
   | POST   | `/reset-password`  | `resetPassword`     | Chamar `resetPassword()` |
   | POST   | `/verify-otp`      | `verifyOtp`         | Chamar `verifyOtp()`     |
   | POST   | `/resend-otp`      | `resendPasswordOtp` | Chamar `resendOtp()`     |

3. Todos os endpoints são públicos
4. Escrever testes do controller

### 5.6 DTOs de Password Reset e Verificação

**Arquivos a criar:**

| Arquivo                              | Campos conforme seção 7.3                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/dto/forgot-password.dto.ts`     | `@IsEmail() email`, `@IsString() @IsNotEmpty() tenantId`                                                                                                                                                                                                                                                                                                                                                                      |
| `src/server/dto/reset-password.dto.ts`      | `@IsEmail() email`, `@IsString() @MinLength(8) @MaxLength(128) newPassword`, `@IsOptional() @IsString() @IsNotEmpty() token?`, `@IsOptional() @IsString() @IsNotEmpty() otp?`, `@IsOptional() @IsString() @IsNotEmpty() verifiedToken?`, `@IsString() @IsNotEmpty() tenantId`. **Nota:** `@IsNotEmpty()` nos campos opcionais garante que se presentes, não sejam empty string (que geraria `sha256("")` válido mas incorreto) |
| `src/server/dto/verify-otp.dto.ts`          | `@IsEmail() email`, `@IsString() @IsNotEmpty() @Length(6, 8) otp` (mín 6 = padrão, máx 8 = otpLength máximo), `@IsString() @IsNotEmpty() tenantId`                                                                                                                                                                                                                                                                            |
| `src/server/dto/resend-otp.dto.ts`          | `@IsEmail() email`, `@IsString() @IsNotEmpty() tenantId`                                                                                                                                                                                                                                                                                                                                                                      |
| `src/server/dto/verify-email.dto.ts`        | `@IsEmail() email`, `@IsString() @IsNotEmpty() otp`, `@IsString() @IsNotEmpty() tenantId`                                                                                                                                                                                                                                                                                                                                     |
| `src/server/dto/resend-verification.dto.ts` | `@IsEmail() email`, `@IsString() @IsNotEmpty() tenantId`                                                                                                                                                                                                                                                                                                                                                                      |

### 5.7 Integração no módulo dinâmico

- `OtpService` já registrado na Fase 2 — nenhum registro adicional necessário
- Registrar `SessionService` condicionalmente (quando `sessions.enabled`)
- Registrar `PasswordResetService` sempre
- Registrar controllers condicionalmente
- Adicionar ao barrel export:
  - `export { ForgotPasswordDto, ResetPasswordDto, VerifyOtpDto, ResendOtpDto, VerifyEmailDto, ResendVerificationDto }`
  - `export type { SessionInfo }` de `./services/session.service`

### 5.8 Integração com AuthService (modificação retroativa da Fase 2)

**Arquivos modificados:** `src/server/services/auth.service.ts`, `src/server/services/token-manager.service.ts`

- Integrar `SessionService` no fluxo de login/logout do `AuthService`:
  - `login()`: após emitir tokens, chamar `sessionService.createSession()` se `sessions.enabled`
  - `logout()`: chamar `sessionService.revokeSession()` para remover a sessão do SET
  - `refresh()`: chamar `sessionService.rotateSession()` para atualizar `sess:` e `sd:` durante rotação
  - Incluir `sessionHash` no `AuthResult` retornado
- Integrar `SessionService` no `MfaService.challenge()`:
  - Após emitir tokens com `mfaVerified: true`, criar sessão se `sessions.enabled` e `context === 'dashboard'`

> **Nota:** Esta integração modifica código da Fase 2. Os pontos de integração devem ser marcados com comentários `// Phase 4: SessionService integration` durante a Fase 2 para facilitar localização.

### 5.9 Validação da Fase 4

- [ ] Reset de senha por token funcional (email → token → reset)
- [ ] Reset de senha por OTP funcional (email → OTP → verify → verifiedToken → reset)
- [ ] Resend de OTP funciona
- [ ] Cross-tenant reset rejeitado
- [ ] Sessões: criar, listar, revogar, revogar todas
- [ ] FIFO eviction respeita limite configurado
- [ ] Verificação de email funcional
- [ ] Normalização de timing em endpoints anti-enumeração (4 endpoints)
- [ ] DTOs `VerifyOtpDto`, `ResendOtpDto`, `VerifyEmailDto`, `ResendVerificationDto` validam corretamente
- [ ] `logout()` deriva `sessionHash` via `sha256(rawRefreshToken)` para chamar `revokeSession()`
- [ ] Cooldown de reenvio de OTP (60s) funciona via chave Redis
- [ ] Cobertura >= 80%

---

## 6. Fase 5 — Plataforma, OAuth e Convites

**Duração:** 1 semana
**Dependência:** Fases 2, 3 e 4 completas
**Objetivo:** Implementar autenticação de administradores da plataforma, sistema OAuth extensível com plugin Google, e sistema de convites.

### 6.1 Platform Auth

**Arquivos a criar:**

| Arquivo                                       | Conteúdo                                                                                                                                                                                              |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/guards/jwt-platform.guard.ts`            | Guard nativo NestJS (mesmo padrão do `JwtAuthGuard` da Fase 2) que valida `payload.type === 'platform'`. Rejeita `dashboard` com `PLATFORM_AUTH_REQUIRED`. Valida `jti` presente. **OBRIGATÓRIO:** pinar `algorithms: ['HS256']` via `JwtService.verify()`. |
| `src/server/guards/platform-roles.guard.ts`          | Guard de roles usando `platformHierarchy`.                                                                                                                                                            |
| `src/server/decorators/platform-roles.decorator.ts`  | `@PlatformRoles()` para endpoints de plataforma.                                                                                                                                                      |
| `src/server/services/platform-auth.service.ts`       | Login, logout, refresh, getMe, revokeAllPlatformSessions para admins.                                                                                                                                 |
| `src/server/controllers/platform-auth.controller.ts` | 6 endpoints conforme tabela 7.5.                                                                                                                                                                      |
| `src/server/dto/platform-login.dto.ts`               | `email`, `password` (max 72).                                                                                                                                                                         |

**Tarefas detalhadas para PlatformAuthService:**

1. Implementar `login()`: brute-force → buscar admin → comparar senha → MFA redirect ou tokens
   - **Brute-force identifier:** Usar `sha256('platform:' + email)` — o prefixo `platform:` evita colisão com o identifier de dashboard `sha256(tenantId + ':' + email)` para o mesmo email
   - Usar `issueMfaTempToken(userId, 'platform')` se MFA habilitado
   - Emitir JWT com `type: 'platform'` via `tokenManager.issuePlatformTokens()`
   - Refresh tokens com prefixo `prt:` no Redis
   - Manter SET `psess:{userId}` com hashes das sessões de plataforma (análogo ao `sess:{userId}` do dashboard)
   - Manter detalhes em `psd:{sessionHash}` (análogo ao `sd:{sessionHash}`)
2. Implementar `logout()`: blacklist access JWT via `rv:{jti}` + deletar `prt:{sha256(refreshToken)}` + remover do SET `psess:{userId}` + deletar `psd:{sessionHash}`
3. Implementar `refresh()` via `tokenManager.reissuePlatformTokens()`: rotação com `prt:` e ponteiro `prp:`. Atualizar `psess:` e `psd:` durante rotação. **Renovar TTL do SET `psess:{userId}` com `EXPIRE`** a cada rotação (previne expiração do SET enquanto tokens individuais são renovados)
4. Implementar `getMe()`: buscar via `platformUserRepo.findById()`
5. Implementar `revokeAllPlatformSessions(userId)`:
   - Usar `SMEMBERS psess:{userId}` para enumerar todos os session hashes ativos
   - Para cada hash: deletar `prt:{hash}`, deletar `psd:{hash}`
   - Deletar o SET `psess:{userId}`
   - **Nota:** NÃO usar `SCAN prt:*` (O(N) sobre todas as chaves Redis). O SET `psess:` garante O(M) onde M = sessões do admin
   - **Desvio da spec:** A spec seção 6.9 referencia incorretamente `auth:prp:{userId}` como SET de sessões. `prp:` é o prefixo de ponteiro de rotação (análogo a `rp:` do dashboard). O SET correto é `psess:{userId}` conforme definido neste plano
6. Usar `TokenDeliveryService` em todos os endpoints do `PlatformAuthController` para entrega de tokens (mesmo padrão do `AuthController`)
7. Escrever testes unitários completos:
   - Login com e sem MFA
   - `revokeAllPlatformSessions` invalida todos os refresh tokens
   - Token `dashboard` rejeitado pelo `JwtPlatformGuard`

**Tarefas para PlatformAuthController:**

1. Implementar 6 endpoints conforme tabela 7.5:
   - POST `/login` (público, `@Throttle(AUTH_THROTTLE_CONFIGS.platformLogin)`)
   - POST `/mfa/challenge` (público + mfaToken, `@Throttle(AUTH_THROTTLE_CONFIGS.mfaChallenge)`)
   - GET `/me` (JwtPlatformGuard)
   - POST `/logout` (JwtPlatformGuard)
   - POST `/refresh` (público, `@Throttle(AUTH_THROTTLE_CONFIGS.refresh)`)
   - DELETE `/sessions` (JwtPlatformGuard)
2. O endpoint `/mfa/challenge` reutiliza `MfaService.challenge()` — o `context: 'platform'` no temp token direciona o fluxo
3. Todos os endpoints usam `TokenDeliveryService` para entrega e extração de tokens (mesmo padrão do `AuthController`)
4. **Limitação conhecida — status check pós-login:** Não existe `PlatformUserStatusGuard` equivalente ao `UserStatusGuard` do dashboard. Se um admin for banido após login, o JWT existente permanece válido até expirar (`accessExpiresIn`, padrão 15min). **Mitigação:** o app host DEVE chamar `revokeAllPlatformSessions()` ao alterar status de um admin. Documentar no README

### 6.2 OAuth Module

**Arquivos a criar:**

| Arquivo                                   | Conteúdo                                                                                                                                                  |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/oauth/oauth.module.ts`               | Módulo dinâmico que registra providers OAuth com base na configuração. Importado condicionalmente pelo `BymaxAuthModule`.                                                                                                                                                                                           |
| `src/server/oauth/oauth.service.ts`              | Serviço central: `handleCallback(provider, code, state, ip, ua)` — troca código via plugin, executa `onOAuthLogin`, cria/vincula usuário, emite tokens. Gerencia state CSRF via Redis.                                                                                                                             |
| `src/server/oauth/oauth-provider.plugin.ts`      | Interface `OAuthProviderPlugin` com 3 métodos: `authorizeUrl(state, redirectUri): string`, `exchangeCode(code, redirectUri): Promise<OAuthTokens>`, `fetchProfile(accessToken): Promise<OAuthProfile>`. Todas as implementações usam native `fetch` — zero dependências externas. |
| `src/server/oauth/google/google-oauth.plugin.ts` | Plugin Google implementando `OAuthProviderPlugin`. Constrói URLs OAuth2 do Google, troca código via POST `https://oauth2.googleapis.com/token`, busca perfil via GET `https://www.googleapis.com/oauth2/v3/userinfo`. Tudo via native `fetch`.                                                                      |

**Tarefas detalhadas para OAuthService:**

1. **Implementar `initiateOAuth(provider, tenantId)`:**
   - Gerar state aleatório com `crypto.randomBytes(32).toString('hex')` (64 caracteres hex)
   - Armazenar no Redis: `os:{sha256(state)}` → `{ tenantId }`, TTL 10 min (600s)
   - **Validação de `tenantId`:** O pacote NÃO valida que o `tenantId` existe (é database-agnostic). O hook `onOAuthLogin` é o ponto de validação — se `createData.tenantId` é inválido, o `userRepo.createWithOAuth()` falhará no banco. Documentar que sem o hook `onOAuthLogin`, tenant spoofing é possível no fluxo OAuth
   - Construir URL de redirect para o provider com query params: `client_id`, `redirect_uri`, `scope`, `state`
   - Registrar rotas automaticamente para cada provider configurado:
     - `GET /{routePrefix}/{provider}?tenantId=xxx` → inicia fluxo (extrai `tenantId` do query param)
     - `GET /{routePrefix}/{provider}/callback` → processa callback
   - Retornar redirect HTTP 302 para URL do provider

2. **Implementar `handleCallback(provider, code, state, ip, userAgent)`:**
   - Validar state no Redis — se não encontrado, lançar `OAUTH_FAILED`
   - Extrair `tenantId` do state armazenado
   - Consumir state (deletar do Redis)
   - Trocar código via `plugin.exchangeCode(code, redirectUri)` — retorna `accessToken`
   - Buscar perfil via `plugin.fetchProfile(accessToken)` — retorna `OAuthProfile`
   - Buscar usuário existente: `userRepo.findByOAuthId(provider, profile.providerId, tenantId)`
   - Executar `hooks.onOAuthLogin(profile, existingUser, context)`
   - Conforme resultado:
     - `create`: criar usuário via `userRepo.createWithOAuth()` com dados do hook
     - `link`: vincular via `userRepo.linkOAuth()`
     - `reject`: lançar exceção com `rejectReason`
   - Emitir tokens
   - Criar sessão (se habilitado)
   - Retornar `AuthResult`

3. **Rotas OAuth** (registradas pelo módulo):
   - `GET /{routePrefix}/{provider}?tenantId=xxx` → iniciar fluxo
   - `GET /{routePrefix}/{provider}/callback` → processar callback

4. Escrever testes: fluxo completo (create, link, reject), state CSRF, tenantId resolution

### 6.3 Convites

**Arquivos a criar:**

| Arquivo                                    | Conteúdo                                                                                                                                                                                                                             |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `src/server/services/invitation.service.ts`       | `invite()` e `acceptInvitation()`.                                                                                                                                                                                                   |
| `src/server/controllers/invitation.controller.ts` | POST `/` (criar convite) e POST `/accept`.                                                                                                                                                                                           |
| `src/server/dto/create-invitation.dto.ts`         | `@IsEmail() email`, `@IsString() @IsNotEmpty() role`, `@IsOptional() @IsString() tenantName?`. **Nota:** `tenantId` NÃO está no DTO — é extraído do JWT do inviter. Validação de `role` contra `roles.hierarchy` é feita no service. |
| `src/server/dto/accept-invitation.dto.ts`         | `@IsString() @IsNotEmpty() token`, `@IsString() @MinLength(2) name`, `@IsString() @MinLength(8) @MaxLength(128) password`                                                                                                             |

**Tarefas detalhadas para InvitationService:**

1. **Implementar `invite(inviterId, email, role, tenantId)`:**
   - **Validar que o `role` existe na `roles.hierarchy` configurada** — se não existe, lançar `INSUFFICIENT_ROLE` (previne criação de convites com roles inexistentes)
   - **Validação de autorização:** verificar que o role do inviter é >= role solicitado na hierarquia (usa `hasRole` do `RolesGuard`). A validação de role contra a hierarquia é feita no service (não no DTO), pois `class-validator` não tem acesso ao contexto de DI
   - Se não, lançar `INSUFFICIENT_ROLE`
   - Gerar token seguro via `generateSecureToken(32)`
   - Armazenar: `inv:{sha256(token)}` → `{ email, role, tenantId, inviterId }`, TTL = `tokenTtlSeconds`
   - Buscar nome do inviter via `userRepo.findById(inviterId)` para incluir no email
   - **Resolução de `tenantName`:** O `IEmailProvider.sendInvitation()` requer `tenantName`. Como o `IUserRepository` não tem método para buscar nome do tenant, o `tenantName` deve ser passado como parâmetro adicional pelo controller (extraído do hook `beforeRegister` ou configurado pelo app host). **Decisão de design:** adicionar `tenantName?: string` ao parâmetro de `invite()` — se não fornecido, usar `tenantId` como fallback
   - Enviar via `emailProvider.sendInvitation()`
   - O raw token NUNCA é logado pelo service (apenas pelo `NoOpEmailProvider` truncado)

2. **Implementar `acceptInvitation(dto, ip, userAgent)`:**
   - Buscar convite: `inv:{sha256(token)}`
   - Se não encontrado → lançar `INVALID_INVITATION_TOKEN`
   - Verificar se email já existe no tenant
   - Criar usuário com role e tenant do convite, com `emailVerified: true` (o convite enviado ao email implica verificação do endereço)
   - Consumir convite (deletar do Redis)
   - Emitir tokens
   - Executar `hooks.afterInvitationAccepted()`
   - Retornar `AuthResult`

3. No `InvitationController`:
   - POST `/` requer `JwtAuthGuard` + `RolesGuard` — `tenantId` extraído do JWT, NÃO do body. `tenantName` vem do body (`CreateInvitationDto.tenantName?`) ou usa `tenantId` como fallback. **Desvio da spec:** o DTO da spec não inclui `tenantName`, mas `IEmailProvider.sendInvitation()` o requer. Este é um campo opcional adicionado pelo plano
   - POST `/accept` é público, com `@Throttle(AUTH_THROTTLE_CONFIGS.invitationAccept)`

4. Escrever testes: criar convite, aceitar, token inválido, email duplicado, role insuficiente

### 6.4 Integração no módulo dinâmico

- Registrar `PlatformAuthService` e controllers se `platformAdmin.enabled`
- Registrar `OAuthModule` se `oauth` configurado
- Registrar `InvitationService` e controller se `invitations.enabled`
- Atualizar barrel export

### 6.5 Atualização do barrel export

Adicionar ao `index.ts`:

- `export { JwtPlatformGuard, PlatformRolesGuard }`
- `export { PlatformRoles }` decorator
- `export type { PlatformAuthResult }` (já definido na Fase 1, confirmar export)
- DTOs: `export { PlatformLoginDto, AcceptInvitationDto, CreateInvitationDto }`

### 6.6 Validação da Fase 5

- [ ] Login de admin da plataforma funcional (com e sem MFA)
- [ ] JWT de plataforma isolado de JWT de dashboard (type claim)
- [ ] `JwtPlatformGuard` usa `algorithms: ['HS256']` via `JwtService.verify()` (algorithm pinning)
- [ ] Token `dashboard` rejeitado por `JwtPlatformGuard` com `PLATFORM_AUTH_REQUIRED`
- [ ] `revokeAllPlatformSessions` invalida todos os refresh tokens via `psess:{userId}` SET
- [ ] OAuth Google: fluxo completo funcional
- [ ] State CSRF validado e consumido (single-use)
- [ ] Convites: criar, aceitar, expirar
- [ ] Validação de role no convite: role inexistente → `INSUFFICIENT_ROLE`
- [ ] Validação de role no convite: inviter sem autorização → `INSUFFICIENT_ROLE`
- [ ] TenantId no convite vem do JWT, não do body
- [ ] Todos os endpoints de plataforma usam `TokenDeliveryService`
- [ ] Cobertura >= 80%

---

## 7. Fase 6 — Integração, Polimento e Publicação

**Duração:** 1 semana
**Dependência:** Fases 1-5 completas
**Objetivo:** Finalizar guards adicionais, testes de integração E2E, documentação JSDoc, README e publicação no npm.

### 7.1 Guards adicionais

**Arquivos a criar:**

| Arquivo                             | Conteúdo                                                                                                                         |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `src/server/guards/ws-jwt.guard.ts`        | Guard para WebSocket — extrai JWT do handshake via header `Authorization` (NÃO query param). Valida e popula `client.data.user`. |
| `src/server/guards/self-or-admin.guard.ts` | Permite acesso se `:userId === JWT.sub` ou se role é admin na hierarquia. Proteção primária contra IDOR.                         |
| `src/server/guards/optional-auth.guard.ts` | Tenta autenticar via JWT, mas não falha se ausente. Popula `request.user` ou null.                                               |

**Tarefas para cada guard:**

1. **WsJwtGuard:** extrair token de `client.handshake.headers.authorization`, validar JWT, verificar `payload.type === 'dashboard'` (rejeitar tokens `platform` e `mfa_challenge`), popular `client.data.user`. **Peer dependency opcional:** se `@nestjs/websockets` não está instalado, `WsJwtGuard.canActivate()` deve lançar erro descritivo ("WsJwtGuard requires @nestjs/websockets") em vez de crashar silenciosamente. O check deve ser no `canActivate()` (runtime), não apenas no import (compile-time)
2. **SelfOrAdminGuard:** comparar `req.params.userId` com `req.user.sub`, verificar role admin na hierarquia. Para session hashes no `DELETE /sessions/:id`, validar formato SHA-256 hex (64 caracteres, `[a-f0-9]{64}`). **IMPORTANTE — cross-tenant:** Este guard NÃO valida que o recurso alvo pertence ao `tenantId` do JWT. Em contextos multi-tenant, o controller ou service deve adicionalmente verificar ownership. Documentar no README
3. **OptionalAuthGuard:** extends `JwtAuthGuard`, sobrescrever `handleRequest()` para não lançar exceção se token ausente — popular `request.user` como `null`
4. Escrever testes unitários para cada guard:
   - WsJwtGuard: token `platform` rejeitado, token `dashboard` aceito
   - SelfOrAdminGuard: acesso próprio permitido, admin permitido, outro usuário rejeitado
   - OptionalAuthGuard: sem token → `user` é `null`, com token → `user` populado

### 7.2 Testes de integração E2E

**Cenários de teste:**

1. **Fluxo completo de autenticação:**
   - Register → login → refresh → /me → logout
   - Verificar cookies setados (modo cookie)
   - Verificar body response (modo bearer)

2. **Fluxo MFA:**
   - Register → login → setup MFA → verify → logout → login (MFA challenge) → challenge (TOTP) → acesso
   - Challenge com recovery code

3. **Fluxo de sessões:**
   - Login em 3 dispositivos → listar sessões → revogar uma → revogar todas exceto atual

4. **Fluxo de password reset:**
   - Token method: forgot → email com token → reset
   - OTP method: forgot → email com OTP → verify OTP → reset com verifiedToken

5. **Fluxo de convites:**
   - Admin cria convite → email com token → aceitar → login

6. **Fluxo OAuth (mock):**
   - Iniciar → callback com perfil → criar usuário → tokens emitidos

7. **Sessões com FIFO eviction:**
   - Login de 6 dispositivos (limite = 5) → verificar que sessão mais antiga foi removida
   - Listar sessões retorna 5, com `isCurrent` correto

8. **Concorrência de refresh:**
   - Duas requisições de refresh simultâneas com o mesmo token → primeira sucede, segunda usa grace window e retorna o mesmo novo token

9. **Segurança:**
   - Brute-force: 10 tentativas falhas → lockout → verificar `Retry-After`
   - Token na blacklist: logout → reutilizar token → 401
   - Cross-tenant: login em tenant A → acessar recurso de tenant B → 403
   - Role insuficiente: MEMBER tenta acessar endpoint ADMIN → 403
   - Token sem `jti` → 401 `TOKEN_INVALID`
   - MFA temp token `dashboard` no endpoint de plataforma → rejeitado
   - Cooldown de reenvio de OTP respeitado (< 60s → sucesso sem novo OTP)

### 7.3 Revisão de segurança

Verificar cada item do Apêndice B da especificação:

- [ ] Senhas hasheadas com scrypt (N=2^15, r=8, p=1)
- [ ] Comparação constant-time via `crypto.timingSafeEqual()` em senhas, OTPs, recovery codes
- [ ] Secrets TOTP criptografados com AES-256-GCM
- [ ] Recovery codes hasheados com scrypt (mesmos parâmetros das senhas)
- [ ] Refresh tokens opacos (UUID v4, não JWT)
- [ ] Rotação de refresh com grace window
- [ ] Blacklist de access tokens via `jti`
- [ ] HttpOnly cookies em modo cookie/both
- [ ] SameSite Strict no refresh cookie
- [ ] Path restrito `/auth` no refresh cookie
- [ ] Brute-force por email (scopado por tenant)
- [ ] Rate limiting por IP em todos os endpoints sensíveis
- [ ] Não revelação de existência de usuário
- [ ] PII mascarado em logs
- [ ] SHA-256 em todas as chaves Redis
- [ ] Anti-replay de código TOTP
- [ ] OTP com limite de 5 tentativas
- [ ] Algorithm pinning no JWT Strategy (HS256)
- [ ] Sanitização de headers no HookContext

### 7.4 Documentação

1. **JSDoc:** Adicionar documentação em todos os métodos públicos de serviços, guards e decorators
2. **README.md:** Guia de início rápido com:
   - Instalação
   - Configuração mínima
   - Exemplo de `registerAsync()`
   - Exemplo de implementação de `IUserRepository`
   - Exemplo de implementação de `IEmailProvider` com nota de segurança: todos os valores de usuário interpolados em HTML devem ser escapados (`escapeHtml(name)`) para prevenir XSS nas notificações
   - Tabela de endpoints
   - Tabela de guards e decorators
   - Seção de segurança: allowlist de domínios em `resolveDomains`, recovery sem TOTP requer intervenção admin, `@MaxLength(128)` em senhas
   - Nota sobre `@nestjs/throttler` >= 6.0.0 como requisito para `AUTH_THROTTLE_CONFIGS`
3. **CHANGELOG.md:** Entrada v1.0.0 (arquivo criado na Fase 1, populado aqui)

### 7.5 Atualização do barrel export (Fase 6)

Adicionar ao `index.ts`:

- `export { WsJwtGuard, SelfOrAdminGuard, OptionalAuthGuard }`

### 7.6 Polimento final

1. Revisar barrel export (`index.ts`) — verificar que tudo que é público está exportado
2. Validação de opções na inicialização do módulo — mensagens de erro claras
3. Logs estruturados com `Logger` do NestJS em todos os serviços
4. Garantir que o build produz `dist/` limpo com types e sourcemaps
5. Verificar `files` no `package.json` — apenas `dist/` publicado
6. Testar instalação local em um projeto NestJS de teste

### 7.7 Publicação

1. Executar `pnpm build`
2. Executar `pnpm test:cov` — verificar cobertura >= 80%
3. Executar `pnpm pack` para verificar conteúdo do pacote
4. Publicar com `pnpm publish --access public`

### 7.8 Validação da Fase 6

- [ ] Todos os testes E2E passando (incluindo concorrência de refresh e FIFO eviction)
- [ ] Cobertura total >= 80%
- [ ] Build sem erros ou warnings
- [ ] README completo e funcional com seções de segurança
- [ ] JSDoc em todos os exports públicos
- [ ] Todos os 14 endpoints têm `@Throttle()` com configs de `AUTH_THROTTLE_CONFIGS`
- [ ] Checklist de segurança 100% verificado (Apêndice B da spec)
- [ ] `WsJwtGuard` verifica `payload.type === 'dashboard'`
- [ ] Barrel export distingue `export type` de `export` corretamente
- [ ] Pacote publicado no npm

---

## 8. Fase 7 — Shared + Client Subpath

**Duração:** 1-2 semanas (Semana 6-7)
**Dependência:** Fase 6 completa (server testado e publicado)
**Objetivo:** Extrair tipos e constantes compartilhados para o subpath `shared`, e implementar o cliente de autenticação framework-agnostic no subpath `client`.

### 8.1 Shared Subpath (`src/shared/`)

**Arquivos a criar:**

| Arquivo                           | Conteúdo                                                                                                  |
| --------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `src/shared/types/auth-user.types.ts`       | `AuthUserClient` — representação do usuário autenticado no client-side                                    |
| `src/shared/types/auth-result.types.ts`     | `AuthClientResponse`, `MfaChallengeResult`, `AuthErrorResponse` — tipos de resultado da API              |
| `src/shared/types/jwt-payload.types.ts`     | `DashboardJwtPayload`, `PlatformJwtPayload`, `MfaTempPayload` — tipos de payload JWT                     |
| `src/shared/constants/cookie-defaults.ts`   | `AUTH_ACCESS_COOKIE_NAME`, `AUTH_REFRESH_COOKIE_NAME`, `AUTH_HAS_SESSION_COOKIE_NAME`, `AUTH_REFRESH_COOKIE_PATH` |
| `src/shared/constants/error-codes.ts`       | `AUTH_ERROR_CODES` — códigos de erro usados pelo client para tratar respostas                             |
| `src/shared/constants/routes.ts`            | `AUTH_ROUTES` — mapa de rotas padrão da API de auth                                                      |
| `src/shared/index.ts`                       | Barrel export de todos os tipos e constantes do subpath shared                                            |

**Tarefas detalhadas:**

1. **Extrair tipos do server para shared (estrutura por subdiretório `types/`):**
   - `types/jwt-payload.types.ts`: Mover interfaces de payload JWT (`DashboardJwtPayload`, `PlatformJwtPayload`, `MfaTempPayload`) que são usadas tanto pelo server quanto pelo client
   - `types/auth-result.types.ts`: Mover tipos de resultado (`AuthClientResponse`, `MfaChallengeResult`, `AuthErrorResponse`) — o client precisa tipar as respostas
   - `types/auth-user.types.ts`: Mover `AuthUserClient` — representação do usuário autenticado no client-side
   - Atualizar imports no server para referenciar `../shared/types/` em vez das definições locais

2. **Extrair constantes (estrutura por subdiretório `constants/`):**
   - `constants/error-codes.ts`: `AUTH_ERROR_CODES` — códigos de erro usados pelo client para tratar respostas
   - `constants/cookie-defaults.ts`: Nomes de cookies (`AUTH_ACCESS_COOKIE_NAME`, `AUTH_REFRESH_COOKIE_NAME`, `AUTH_HAS_SESSION_COOKIE_NAME`) + `AUTH_REFRESH_COOKIE_PATH` — usados pelo proxy Next.js
   - `constants/routes.ts`: `AUTH_ROUTES` — mapa de rotas padrão da API de auth

3. **Barrel export** em `src/shared/index.ts`

4. **Testes:**
   - Verificar que todos os tipos compilam sem erros
   - Verificar que as constantes do shared correspondem aos valores usados pelo server (teste de sincronização)

### 8.2 Client Subpath (`src/client/`)

**Arquivos a criar:**

| Arquivo                           | Conteúdo                                                                                                  |
| --------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `src/client/createAuthClient.ts`  | Factory `createAuthClient(config: AuthClientConfig)` que retorna métodos tipados de autenticação           |
| `src/client/createAuthFetch.ts`   | Wrapper de `fetch` com interceptação de 401, refresh automático e dedup de refresh                        |
| `src/client/types.ts`             | `AuthClientConfig`, `AuthFetchConfig` e tipos internos do client                                          |
| `src/client/index.ts`             | Barrel export do subpath client                                                                           |

**Tarefas detalhadas:**

1. **Implementar `createAuthClient(config: AuthClientConfig)`:**
   - Factory que retorna objeto com métodos tipados: `login`, `register`, `logout`, `refresh`, `getMe`, `mfaChallenge`, `forgotPassword`, `resetPassword`
   - Cada método encapsula a chamada HTTP correspondente com tipos de entrada e saída corretos
   - Usa `createAuthFetch` internamente para interceptação automática de 401
   - Config aceita: `baseUrl`, `fetchOptions`, `onSessionExpired`

2. **Implementar `createAuthFetch(config: AuthFetchConfig)`:**
   - Wrapper de `fetch` nativo — zero dependências externas
   - **Single-flight refresh dedup:** ao receber 401, inicia refresh. Se múltiplas requisições falham simultaneamente com 401, apenas UMA chamada de refresh é feita (padrão `refreshPromise`)
   - **`shouldSkipRefreshOnUrl(url)`:** lista completa de URLs que NÃO devem triggerar refresh automático (ex: `/auth/login`, `/auth/register`, `/auth/refresh`, `/auth/forgot-password`, `/auth/reset-password`)
   - **Interceptação 401 → refresh → retry:** ao receber 401, tenta refresh, e se suceder, re-executa a requisição original com novos cookies/headers
   - **`onSessionExpired` callback:** chamado quando refresh falha (sessão expirada de verdade) — permite ao app host redirecionar para login
   - Todas as operações via native `fetch`

3. **Barrel export** em `src/client/index.ts`

4. **Testes:**
   - Mock de `fetch` global
   - Testar dedup de refresh (2 requisições 401 simultâneas → 1 refresh)
   - Testar skip list (chamada de login com 401 NÃO tenta refresh)
   - Testar `onSessionExpired` chamado quando refresh falha
   - Testar retry da requisição original após refresh bem-sucedido

### 8.3 Validação da Fase 7

- [ ] Todos os tipos do shared compilam sem erros
- [ ] Constantes do shared correspondem aos valores usados pelo server
- [ ] `createAuthClient` retorna todos os métodos tipados
- [ ] `createAuthFetch` faz dedup de refresh (single-flight)
- [ ] Skip list previne refresh automático em URLs de auth
- [ ] `onSessionExpired` é chamado quando refresh falha
- [ ] Zero dependências externas — apenas native `fetch`
- [ ] Server continua compilando após extração dos tipos para shared
- [ ] Cobertura >= 80%

---

## 9. Fase 8 — React Subpath

**Duração:** ~0.5 semana (Semana 7)
**Dependência:** Fase 7 completa (client subpath funcional)
**Objetivo:** Implementar hooks e context React para gerenciamento de sessão de autenticação.

### 9.1 Arquivos a criar

| Arquivo                           | Conteúdo                                                                                                  |
| --------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `src/react/AuthProvider.tsx`      | Context component que gerencia estado de sessão, auto-revalidação periódica e integração com `createAuthClient` |
| `src/react/useSession.ts`         | Hook que retorna `{ user, status, isLoading, refresh, lastValidation }`                                   |
| `src/react/useAuth.ts`            | Hook que retorna `{ login, register, logout, forgotPassword, resetPassword }`                             |
| `src/react/useAuthStatus.ts`      | Hook de conveniência que retorna `{ isAuthenticated, isLoading }`                                         |
| `src/react/types.ts`              | Tipos internos do React subpath: `AuthProviderProps`, `SessionState`, `AuthContextValue`                  |
| `src/react/index.ts`              | Barrel export do subpath react                                                                            |

### 9.2 Tarefas detalhadas

1. **`AuthProvider` context component:**
   - Aceita `config` (mesma config do `createAuthClient`) e `children`
   - Gerencia estado de sessão: `user`, `status` (`loading` | `authenticated` | `unauthenticated`), `lastValidation` (timestamp)
   - Auto-revalidação: chama `getMe()` na montagem e em intervalo configurável
   - Expõe métodos de auth via context (login, register, logout, etc.)
   - Trata `onSessionExpired` para atualizar estado automaticamente

2. **`useSession()` hook:**
   - Consome o context do `AuthProvider`
   - Retorna `{ user: AuthUserClient | null, status, isLoading, refresh, lastValidation }`
   - `refresh()` força revalidação imediata da sessão
   - Lança erro se usado fora do `AuthProvider`

3. **`useAuth()` hook:**
   - Consome o context do `AuthProvider`
   - Retorna `{ login, register, logout, forgotPassword, resetPassword }`
   - Cada método retorna `Promise` com tipos adequados
   - `login` e `register` atualizam o estado de sessão automaticamente ao suceder

4. **`useAuthStatus()` hook:**
   - Hook de conveniência para checks simples
   - Retorna `{ isAuthenticated: boolean, isLoading: boolean }`
   - Derivado de `useSession()` internamente

5. **Barrel export** em `src/react/index.ts`

6. **Testes:**
   - React Testing Library para testar componentes e hooks
   - Mock do `AuthProvider` com diferentes estados iniciais
   - Verificar transições de estado: `loading` → `authenticated` → `unauthenticated` (após logout)
   - Verificar que hooks lançam erro fora do `AuthProvider`
   - Verificar auto-revalidação (timer mock)

7. **Peer dependency:** `react ^19`

### 9.3 Validação da Fase 8

- [ ] `AuthProvider` gerencia estado de sessão corretamente
- [ ] `useSession()` retorna dados atualizados do usuário
- [ ] `useAuth()` métodos atualizam estado de sessão após login/logout
- [ ] `useAuthStatus()` deriva estado corretamente
- [ ] Hooks lançam erro descritivo fora do `AuthProvider`
- [ ] Auto-revalidação funciona com intervalo configurável
- [ ] Testes com React Testing Library passando
- [ ] Peer dependency `react ^19` declarada
- [ ] Cobertura >= 80%

---

## 10. Fase 9 — Next.js Subpath

**Duração:** 1-2 semanas (Semana 7-8)
**Dependência:** Fase 7 completa (shared + client subpaths)
**Objetivo:** Implementar utilitários Next.js para autenticação no proxy (`proxy.ts`), route handlers de refresh, e helpers JWT/cookie. Esta é a fase frontend mais crítica — todos os padrões vêm do projeto bymax-fitness-ai, onde um bug de redirect loop foi encontrado e corrigido. Documentar TODOS os edge cases.

### 10.1 Arquivos a criar

| Arquivo                                     | Conteúdo                                                                                                  |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `src/nextjs/createAuthProxy.ts`             | Factory `createAuthProxy(config)` que retorna `{ proxy, config }` para uso em `proxy.ts` do Next.js 16   |
| `src/nextjs/createSilentRefreshHandler.ts`      | Factory que retorna GET handler para `/api/auth/silent-refresh`                                           |
| `src/nextjs/createClientRefreshHandler.ts`      | Factory que retorna POST handler para `/api/auth/client-refresh`                                          |
| `src/nextjs/createLogoutHandler.ts`             | Factory que retorna POST handler para `/api/auth/logout` — forward para backend + limpeza de cookies      |
| `src/nextjs/helpers/buildSilentRefreshUrl.ts`   | Constrói URL para `/api/auth/silent-refresh?dest=<dest>&_r=<currentR+1>` com propagação do counter `_r`  |
| `src/nextjs/helpers/isBackgroundRequest.ts`     | Detecta requisições RSC/prefetch via headers (`RSC: 1`, `Next-Router-Prefetch: 1`, `Next-Router-State-Tree`) |
| `src/nextjs/helpers/dedupeSetCookieHeaders.ts`  | `dedupeSetCookieHeaders()`, `parseSetCookieHeader()` — utilitários de deduplicação de cookie              |
| `src/nextjs/helpers/jwt.ts`                     | `decodeJwtToken()` (decode-only) e `verifyJwtToken()` (HS256 via Web Crypto API com algorithm pinning)    |
| `src/nextjs/types.ts`                           | `AuthProxyConfig`, `SilentRefreshConfig`, `ClientRefreshConfig`, `LogoutHandlerConfig` e tipos internos   |
| `src/nextjs/index.ts`                       | Barrel export do subpath nextjs                                                                           |

### 10.2 Tarefas detalhadas

1. **`createAuthProxy(config: AuthProxyConfig)`** — Factory que retorna `{ proxy, config }` para `proxy.ts`:

   - **`isBackgroundRequest(request)`:** Detecta requisições RSC/prefetch via headers (`RSC: 1`, `Next-Router-Prefetch: 1`, `Next-Router-State-Tree`). Requisições de background retornam 401 em vez de redirect — sem isso, o prefetcher do Next.js receberia HTML de redirect em vez de RSC payload, causando erros de hidratação

   - **Counter `_r`:** Limita tentativas de silent-refresh a `maxRefreshAttempts` (default 2). Previne redirect loop quando o browser não processa o Set-Cookie entre redirects consecutivos. A cada tentativa de refresh, o proxy incrementa `_r` na query string. Se `_r >= maxRefreshAttempts`, redireciona para login com `reason=expired` em vez de tentar novamente

   - **Guard `reason=expired`:** Em rotas públicas (ex: `/login`), se `reason=expired` já está presente na query string, o proxy NÃO tenta silent-refresh — o usuário já foi redirecionado após falha, evitando loop infinito

   - **Check do signal cookie `has_session`:** O cookie `has_session` (não-HttpOnly) indica se existe sessão ativa. Se ausente, o proxy NÃO tenta silent-refresh em rotas protegidas — redireciona diretamente para login. Isso evita uma ida-e-volta desnecessária ao backend

   - **Bloqueio por status do usuário:** Decodifica o access token JWT e verifica `status`. Usuários BANNED, INACTIVE ou EXPIRED são redirecionados para uma página de bloqueio (configurável), mesmo com token válido

   - **RBAC no proxy:** Verifica `role` do JWT contra roles permitidas para a rota. Redireciona para página de acesso negado se role insuficiente. Suporta redirects por role (ex: admin → `/admin/dashboard`, user → `/dashboard`)

   - **Propagação de headers:** Injeta `x-user-id`, `x-user-role`, `x-tenant-id`, `x-tenant-domain` nos headers da requisição para consumo pelos server components e API routes

   - **`buildSilentRefreshUrl(destination, currentR)`:** Constrói URL para `/api/auth/silent-refresh?dest=<destination>&_r=<currentR+1>` com propagação do counter `_r`

2. **`createSilentRefreshHandler(config?)`** — GET handler para `/api/auth/silent-refresh`:

   - Recebe `dest` (destino pós-refresh) e `_r` (counter) da query string
   - Forward cookies da requisição para backend POST `/auth/refresh`
   - **Sucesso:** Redirect 302 para `dest` com propagação de Set-Cookie (novos tokens)
   - **Falha:** Redirect 302 para login com `reason=expired`, limpar todos os cookies de auth (access, refresh, has_session)
   - **Defesa contra open redirect:** Validar que `dest` é um path relativo (começa com `/`), verificar origin da requisição. Rejeitar URLs absolutas ou paths que apontem para domínios externos. **Rejeitar explicitamente prefixo `//`** (protocol-relative URL attack — ex: `//evil.com` seria interpretado como `https://evil.com`)
   - **`dedupeSetCookieHeaders()`:** Ao propagar Set-Cookie do backend, deduplicar por (nome + domínio) — last writer wins. Necessário porque o backend pode enviar múltiplos Set-Cookie para o mesmo cookie em cenários de rotação
   - **`getSetCookie()` fallback:** Para runtimes pré-Node 18.14 que não suportam `Headers.getSetCookie()`, implementar fallback parseando o header `set-cookie` manualmente

3. **`createClientRefreshHandler(config?)`** — POST handler para `/api/auth/client-refresh`:

   - Bridge same-origin para evitar problemas de CORS/credential cookies
   - O client-side `createAuthFetch` chama este endpoint em vez de ir diretamente ao backend
   - Forward cookies da requisição para backend POST `/auth/refresh`
   - Retorna 200 com Set-Cookie propagado (sucesso) ou 401 (falha)
   - Sem redirect — é uma API JSON pura

4. **JWT helpers:**
   - **`decodeJwtToken(token)`:** Decode-only (sem verificação de assinatura) — usado pelo proxy para ler claims sem precisar do secret. Parsing de base64url do payload
   - **`verifyJwtToken(token, secret)`:** Verificação completa com HS256 via Web Crypto API. **Algorithm pinning obrigatório** — rejeitar tokens com `alg !== 'HS256'` no header ANTES de verificar assinatura (previne `alg: 'none'` attack)

5. **Cookie utilities:**
   - **`dedupeSetCookieHeaders(headers)`:** Recebe array de strings Set-Cookie, agrupa por nome+domínio, mantém o último (last writer wins)
   - **`parseSetCookieHeader(header)`:** Parse de uma string Set-Cookie individual em objeto com `name`, `value`, `domain`, `path`, `expires`, `httpOnly`, `secure`, `sameSite`

6. **Barrel export** em `src/nextjs/index.ts`

7. **Testes:**
   - **Proxy:** testar `isBackgroundRequest` com headers RSC/prefetch, testar counter `_r` (incremento, limite, redirect para login), testar guard `reason=expired`, testar `has_session` cookie check
   - **Silent refresh handler:** mock de fetch para backend, testar sucesso com Set-Cookie propagation, testar falha com limpeza de cookies, testar defesa open redirect
   - **Client refresh handler:** testar bridge same-origin, testar 200 vs 401
   - **JWT:** testar decode de payload válido, testar verificação HS256, testar rejeição de `alg: 'none'`
   - **Cookies:** testar dedup com múltiplos Set-Cookie, testar parse de header complexo

8. **Peer dependencies:** `next ^16`, `react ^19`

### 10.3 Validação da Fase 9

- [ ] `createAuthProxy` integra com `proxy.ts` do Next.js 16
- [ ] `isBackgroundRequest` detecta RSC e prefetch corretamente
- [ ] Counter `_r` previne redirect loop (testado com 3+ tentativas)
- [ ] Guard `reason=expired` evita re-tentativa em rotas públicas
- [ ] `has_session` cookie check evita refresh desnecessário
- [ ] Bloqueio por status do usuário funcional (BANNED, INACTIVE, EXPIRED)
- [ ] RBAC no proxy com redirects por role
- [ ] Headers `x-user-id`, `x-user-role`, `x-tenant-id`, `x-tenant-domain` propagados
- [ ] Silent refresh handler com Set-Cookie propagation funcional
- [ ] Defesa contra open redirect testada (inclui rejeição de prefixo `//` — protocol-relative URL attack)
- [ ] `dedupeSetCookieHeaders` deduplicação por nome+domínio
- [ ] Client refresh handler retorna 200/401 corretamente
- [ ] `verifyJwtToken` rejeita `alg: 'none'` (algorithm pinning)
- [ ] Peer dependencies `next ^16` e `react ^19` declaradas
- [ ] Cobertura do proxy >= 90% (caminho crítico)
- [ ] Cobertura geral >= 80%

---

## 11. Critérios de Qualidade por Fase

| Critério                | Exigência                                                                                                                                                                                 |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Compilação**          | `pnpm build` sem erros em cada fase                                                                                                                                                    |
| **Cobertura de testes** | >= 80% (branches, functions, lines) por fase                                                                                                                                              |
| **Linting**             | Zero erros de ESLint                                                                                                                                                                      |
| **Tipagem**             | Zero uso de `any` em código de produção. Preferir tipos discriminados a `Record<string, unknown>`. Para dados externos não tipados, usar narrowing documentado via JSDoc                   |
| **Segurança**           | Revisão dos itens do Apêndice B aplicáveis à fase                                                                                                                                         |
| **Performance Redis**   | Todas as operações O(1) exceto listagem de sessões                                                                                                                                        |
| **DI sem ciclos**       | `TokenManagerService` NUNCA injeta `SessionService`. Rotação de sessão é chamada por `AuthService`. `InvitationService` usa `hasRole()` de `utils/roles.util.ts`, não injeta `RolesGuard` |
| **Barrel export**       | Atualizado a cada fase com novos exports. DTOs sempre `export` (nunca `export type`) para preservar metadata de `class-validator` em runtime                                              |
| **Documentação inline** | JSDoc em todos os métodos públicos (mínimo na fase, completo na 6)                                                                                                                        |
| **Fase 7**              | 80% cobertura, zero dependências externas verificado, tipos compatíveis com exports do server                                                                                             |
| **Fase 8**              | Testes de componentes com React Testing Library, hooks testados em isolamento                                                                                                             |
| **Fase 9**              | Lógica do proxy com 90%+ de cobertura (caminho crítico), cenários de redirect loop testados                                                                                               |

---

## 12. Riscos e Mitigações

| Risco                                                                         | Probabilidade | Impacto | Mitigação                                                                                                                                                                                                                                                                                                       |
| ----------------------------------------------------------------------------- | ------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Complexidade do módulo dinâmico NestJS                                        | Alta          | Alto    | Implementar scaffold básico na Fase 1, iterar na Fase 2. Usar `DynamicModule` com array `controllers` dinâmico + `RouterModule` para prefixo                                                                                                                                                                    |
| Registro condicional de controllers                                           | Alta          | Alto    | Construir array `controllers` dinamicamente no `registerAsync`. Testar com cada controller habilitado/desabilitado                                                                                                                                                                                              |
| Script Lua de refresh token com race condition                                | Média         | Alto    | Testes com concorrência simulada, revisão do script Lua                                                                                                                                                                                                                                                         |
| Incompatibilidade de versões de peer deps                                     | Média         | Médio   | Usar ranges flexíveis (`^11.0.0`), testar com versões mínima e máxima                                                                                                                                                                                                                                           |
| Criptografia AES-256-GCM com erros sutis                                      | Média         | Alto    | Testes extensivos de round-trip, usar Node.js crypto nativo (não polyfill)                                                                                                                                                                                                                                      |
| `resolveOptions` strip de funções em deep merge                               | Média         | Alto    | Usar shallow merge por grupo (spread), nunca `JSON.parse/stringify`. Testar que funções sobrevivem ao merge                                                                                                                                                                                                     |
| Peer dependencies opcionais (`@nestjs/websockets`)                            | Média         | Médio   | Usar `require.resolve()` com try/catch. Erro descritivo se ausente e funcionalidade configurada                                                                                                                                                                                                                 |
| OAuth state CSRF com múltiplas instâncias                                     | Baixa         | Alto    | Testar com Redis compartilhado entre instâncias                                                                                                                                                                                                                                                                 |
| DoS via recovery codes longos em scrypt                                       | Baixa         | Médio   | `@MaxLength(128)` no DTO do MFA challenge                                                                                                                                                                                                                                                                       |
| Timing side-channel em OTP verification                                       | Baixa         | Médio   | Usar `timingSafeEqual` com buffers de mesmo comprimento; rejeitar antes se comprimento diferir                                                                                                                                                                                                                  |
| Cookie domain injection via Host header                                       | Baixa         | Alto    | Validar hostname em `extractDomain()`, documentar allowlist em `resolveDomains`                                                                                                                                                                                                                                 |
| Normalização de timing em endpoints anti-enumeração                           | Média         | Médio   | Padrão concreto: `const start = Date.now()` no início, `await sleep(Math.max(0, MIN_RESPONSE_MS - (Date.now() - start)))` antes de retornar (MIN_RESPONSE_MS = 300ms). Aplicar nos 4 endpoints: `initiateReset`, `resendOtp`, `resendVerificationEmail`, `verifyEmail`. Best-effort, não garantia criptográfica |
| Recovery codes esgotados sem TOTP                                             | Baixa         | Alto    | Documentar que recuperação requer intervenção admin. Sem endpoint de regeneração na v1                                                                                                                                                                                                                          |
| Set-Cookie não processado entre redirects (browser behavior)                  | Média         | Alto    | Mitigado pelo counter `_r` que limita tentativas de silent-refresh e pelo guard `reason=expired` que interrompe o loop                                                                                                                                                                                          |
| Race condition entre proxy e interceptor client-side                          | Média         | Médio   | Mitigado pelo delay de 500ms no redirect do interceptor client-side, permitindo que o proxy processe primeiro                                                                                                                                                                                                   |

---

## 13. Dependências entre Fases

```
Fase 1 (Fundação)
  │
  ├──→ Fase 2 (Auth Core)
  │      │
  │      ├──→ Fase 3 (MFA) ──────────┐
  │      │                            │
  │      └──→ Fase 4 (Sessões) ──────┤
  │                                   │
  │                                   └──→ Fase 5 (Plataforma + OAuth + Convites)
  │                                          │
  └──────────────────────────────────────────┴──→ Fase 6 (Integração + Polimento)
                                                    │
                                                    ├──→ Fase 7 (Shared + Client)
                                                    │      │
                                                    │      ├──→ Fase 8 (React)
                                                    │      │
                                                    │      └──→ Fase 9 (Next.js)
```

**Fases 3 e 4 podem ser iniciadas em paralelo** (ambas dependem apenas da Fase 2), com ressalvas:

- `MfaService.challenge()` (Fase 3) injeta `@Optional() SessionService` — compila sem ele, mas a integração de sessão no MFA challenge requer a Fase 4 completa
- Ambas as fases modificam `AuthService` da Fase 2 (Fase 3 para MFA redirect, Fase 4 para sessions) — atenção a merge conflicts
- `OtpService` foi movido para Fase 2, eliminando a dependência circular original

**Fase 5 depende das Fases 3 e 4** porque:

- `PlatformAuthService` reutiliza `MfaService.challenge()` com `context: 'platform'` (Fase 3)
- `OAuthService` pode criar sessões (Fase 4)
- `InvitationService` pode integrar com sessões (Fase 4)

**Fases 7-9 dependem da Fase 6** (server completo e testado). Fase 8 e 9 podem ser parcialmente paralelizadas, pois ambas dependem da Fase 7 (shared + client) mas não dependem uma da outra.

---

## 14. Registro de Auditoria

| Versão | Data       | Descrição                                                                                                                                                                                                                 |
| ------ | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| v1.0.0 | 2026-04-10 | Versão inicial do plano — Fases 1-6 (server completo)                                                                                                                                                                    |
| v1.1.0 | 2026-04-10 | Versão inicial pós-auditoria de 4 agentes especialistas. Correções de segurança, tipagem e consistência                                                                                                                  |
| v1.2.0 | 2026-04-13 | Adição de Fases 7-9 (frontend subpaths: shared, client, react, nextjs). Remoção de Passport/bcrypt/otpauth — guards JWT nativos via `@nestjs/jwt`, criptografia via `node:crypto`. Build tool alterado para `tsup ^8.0.0` |

---

_Fim do plano de desenvolvimento._
