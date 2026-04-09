# @bymax-one/nest-auth - Especificação Técnica Completa

> **Versão:** 1.0.0
> **Última atualização:** 2026-04-09
> **Status:** Rascunho para implementação
> **Tipo:** Pacote npm público (`@bymax-one/nest-auth`)

---

## Sumário

1. [Visão Geral e Proposta de Valor](#1-visao-geral-e-proposta-de-valor)
2. [Arquitetura](#2-arquitetura)
3. [Estrutura do Pacote](#3-estrutura-do-pacote)
4. [API de Configuração](#4-api-de-configuração)
5. [Contratos de Repositório](#5-contratos-de-repositório)
6. [Serviços](#6-serviços)
7. [Controllers](#7-controllers)
8. [Guards e Decorators](#8-guards-e-decorators)
9. [Sistema de Hooks](#9-sistema-de-hooks)
10. [Interface de Email Provider](#10-interface-de-email-provider)
11. [Sistema de OAuth](#11-sistema-de-oauth)
12. [Estratégia de Redis](#12-estratégia-de-redis)
13. [Estrutura de JWT Claims](#13-estrutura-de-jwt-claims)
14. [Gerenciamento de Cookies](#14-gerenciamento-de-cookies)
15. [Catálogo de Error Codes](#15-catalogo-de-error-codes)
16. [Rate Limiting](#16-rate-limiting)
17. [O que NÃO está no Pacote](#17-o-que-não-está-no-pacote)
18. [Dependências](#18-dependências)
19. [Fases de Implementação](#19-fases-de-implementação)
20. [Limitações Conhecidas](#20-limitações-conhecidas)

---

## 1. Visão Geral e Proposta de Valor

### 1.1 O que é o `@bymax-one/nest-auth`

O `@bymax-one/nest-auth` é um **pacote npm público** que fornece um módulo NestJS reutilizável e completo de autenticação e autorização para o ecossistema Bymax SaaS. Ele encapsula toda a lógica de autenticação — registro, login, JWT, refresh tokens, MFA, sessões, OAuth, password reset, convites e administração de plataforma — em um único módulo dinâmico configurável.

### 1.2 Por que existe

Em uma arquitetura SaaS multi-tenant, cada aplicação do ecossistema Bymax precisa de autenticação robusta. Em vez de reimplementar a mesma lógica em cada serviço, o `@bymax-one/nest-auth` centraliza essa responsabilidade em um pacote compartilhado que:

- **Elimina duplicação de código** entre os serviços do ecossistema
- **Garante consistência** no comportamento de autenticação
- **Reduz tempo de desenvolvimento** de novos serviços para minutos
- **Mantém padrões de segurança** uniformes (hashing, tokens, MFA, brute-force)
- **Facilita manutenção** — correções de segurança são propagadas com um `npm update`

### 1.3 Quem utiliza

- **Aplicações SaaS do ecossistema Bymax** (dashboards de tenant, APIs internas)
- **Painel de administração da plataforma** (super-admins que gerenciam tenants)
- **Qualquer aplicação NestJS** que precise de autenticação completa e configurável

### 1.4 Modelo de distribuição

| Aspecto   | Detalhe                              |
| --------- | ------------------------------------ |
| Registro  | npm público (`@bymax-one/nest-auth`) |
| Custo     | Zero — pacote open source            |
| Licença   | MIT                                  |
| Runtime   | Node.js 24+                          |
| Framework | NestJS 11+                           |

### 1.5 Princípios de design

1. **Configuração sobre convenção**: Tudo é configurável, mas defaults sensatos estão presentes
2. **Inversão de dependência**: O pacote define interfaces; a aplicação host fornece implementações
3. **Separação de responsabilidades**: Autenticação no pacote, persistência e email na aplicação
4. **Segurança por padrão**: Bcrypt, AES-256-GCM, HttpOnly cookies, blacklist de tokens, brute-force protection
5. **Zero opinião sobre persistência**: O pacote define contratos (interfaces TypeScript) e nunca importa nenhum ORM. O app consumidor implementa os repositórios com a tecnologia de sua escolha. Desenvolvido e testado com Prisma — compatível com TypeORM, Drizzle e outros ORMs SQL por design. ORMs de documento (Mongoose) requerem mapeamento extra para o contrato `AuthUser`

### 1.6 Categorização de módulos

O pacote organiza suas funcionalidades em quatro camadas com níveis de ativação distintos:

#### Core (sempre ativo)

Funcionalidades que são registradas automaticamente e não podem ser desabilitadas:

| Módulo                   | Responsabilidade                              |
| ------------------------ | --------------------------------------------- |
| **AuthService**          | Registro, login, logout, refresh, me          |
| **PasswordService**      | Hash e comparação de senhas (bcrypt)          |
| **TokenManagerService**  | Emissão e verificação de JWT                  |
| **TokenDeliveryService** | Entrega de tokens (cookies, body ou ambos) conforme `tokenDelivery` |
| **BruteForceService**    | Proteção contra força bruta por email         |
| **AuthRedisService**     | Operações Redis (blacklist, refresh sessions) |
| **JwtAuthGuard**         | Validação de JWT em cookie ou header `Authorization: Bearer` |
| **RolesGuard**           | Controle de acesso baseado em roles           |
| **UserStatusGuard**      | Bloqueio de usuários inativos/banidos         |
| **PasswordResetService** | Fluxo de redefinição de senha                 |

#### Security Extensions (opt-in via configuração)

Habilitadas quando a configuração correspondente é fornecida:

| Módulo             | Ativação                                                                      | Responsabilidade                       |
| ------------------ | ----------------------------------------------------------------------------- | -------------------------------------- |
| **MfaService**     | `mfa: { ... }`                                                                | TOTP, recovery codes, MFA challenge    |
| **SessionService** | `sessions: { enabled: true }`                                                 | Rastreamento de sessões, FIFO eviction |
| **OtpService**     | `passwordReset: { method: 'otp' }` ou `emailVerification: { required: true }` | Códigos OTP por email                  |

#### Platform Extensions (opt-in via configuração)

Funcionalidades para administração da plataforma:

| Módulo                  | Ativação                           | Responsabilidade                      |
| ----------------------- | ---------------------------------- | ------------------------------------- |
| **PlatformAuthService** | `platformAdmin: { enabled: true }` | Login e JWT para admins da plataforma |
| **InvitationService**   | `invitations: { enabled: true }`   | Convites de usuários por email        |

#### Integrations (opt-in via configuração)

Provedores externos de autenticação:

| Módulo               | Ativação                     | Responsabilidade      |
| -------------------- | ---------------------------- | --------------------- |
| **Google OAuth**     | `oauth: { google: { ... } }` | Login via Google      |
| _Futuros provedores_ | `oauth: { github: { ... } }` | Extensível via plugin |

> **Princípio:** Quando um módulo opt-in não é configurado, seus controllers, guards e services **não são registrados** no container NestJS. Isso garante zero overhead e nenhuma dependência desnecessária.

---

## 2. Arquitetura

### 2.1 Padrão de módulo dinâmico NestJS

O `@bymax-one/nest-auth` utiliza o padrão **Dynamic Module** do NestJS. Isso significa que ele **não é um serviço separado** — ele roda **dentro de cada aplicação SaaS** como um módulo importado. A aplicação host controla:

- A conexão com o banco de dados (via repositórios injetados)
- O envio de emails (via email provider injetado)
- A instância Redis (via cliente Redis injetado)
- Os hooks de ciclo de vida (via hooks injetados)

```
┌──────────────────────────────────────────────┐
│              Aplicação Host (SaaS)            │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │           @bymax-one/nest-auth module           │  │
│  │                                        │  │
│  │  Controllers ←→ Services ←→ Redis      │  │
│  │       ↕              ↕                 │  │
│  │   Guards          Strategies           │  │
│  │       ↕              ↕                 │  │
│  │  Decorators      Token Manager         │  │
│  └────────┬───────────┬──────────────────┘  │
│           │           │                      │
│    ┌──────▼──┐  ┌─────▼──────┐              │
│    │ IUser   │  │ IEmail     │              │
│    │ Repo    │  │ Provider   │              │
│    │(Prisma) │  │ (Resend)   │              │
│    └─────────┘  └────────────┘              │
│                                              │
│    ┌──────────┐  ┌───────────┐              │
│    │ Redis    │  │ IAuth     │              │
│    │ Client   │  │ Hooks     │              │
│    │(ioredis) │  │ (custom)  │              │
│    └──────────┘  └───────────┘              │
└──────────────────────────────────────────────┘
```

### 2.2 Fluxo de inicialização

1. A aplicação host chama `BymaxAuthModule.registerAsync({ ... })`
2. O módulo resolve as opções de configuração via `ConfigService` ou factory
3. Os providers injetados (repositórios, email, Redis, hooks) são validados
4. Controllers são registrados condicionalmente com base nas opções `controllers.*`
5. Strategies e guards são configurados automaticamente
6. O módulo está pronto para processar requisições

### 2.3 Fluxo de uma requisição autenticada

```
Requisição HTTP
    │
    ▼
JwtAuthGuard (extrai JWT do cookie/header)
    │
    ▼
UserStatusGuard (verifica cache Redis → status do usuário)
    │
    ▼
MfaRequiredGuard (verifica se MFA foi completado, se exigido)
    │
    ▼
RolesGuard (verifica hierarquia de roles)
    │
    ▼
Controller → Service → Repositório (via interface)
    │
    ▼
Resposta HTTP
```

---

## 3. Estrutura do Pacote

### 3.1 Árvore de diretórios completa

```
@bymax-one/nest-auth/
├── package.json
├── tsconfig.json
├── tsconfig.build.json
├── src/
│   ├── index.ts                              # Public API barrel export
│   ├── bymax-one-nest-auth.module.ts                  # Root dynamic module
│   ├── bymax-one-nest-auth.constants.ts               # Injection tokens
│   │
│   ├── interfaces/
│   │   ├── auth-module-options.interface.ts   # Opções de configuração
│   │   ├── user-repository.interface.ts       # Contrato do repositório de usuários
│   │   ├── platform-user-repository.interface.ts  # Contrato do repo de admins
│   │   ├── email-provider.interface.ts        # Contrato do provider de email
│   │   ├── auth-hooks.interface.ts            # Hooks de ciclo de vida
│   │   ├── oauth-provider.interface.ts        # Plugin de OAuth
│   │   ├── jwt-payload.interface.ts           # Tipagem dos claims JWT
│   │   └── authenticated-request.interface.ts # Request com usuário autenticado
│   │
│   ├── config/
│   │   ├── default-options.ts                 # Valores padrão para todas as opções
│   │   └── resolved-options.ts                # Opções resolvidas (merge de defaults + user)
│   │
│   ├── services/
│   │   ├── auth.service.ts                    # Registro, login, logout, refresh, me
│   │   ├── password.service.ts                # Hash e comparação bcrypt
│   │   ├── token-manager.service.ts           # Emissão e verificação de JWTs
│   │   ├── session.service.ts                 # Gerenciamento de sessões
│   │   ├── mfa.service.ts                     # Autenticação multi-fator (TOTP)
│   │   ├── password-reset.service.ts          # Reset de senha (token/OTP)
│   │   ├── otp.service.ts                     # Geração e verificação de OTPs
│   │   ├── brute-force.service.ts             # Proteção contra brute-force
│   │   ├── platform-auth.service.ts           # Autenticação de admins da plataforma
│   │   ├── invitation.service.ts              # Sistema de convites
│   │   └── token-delivery.service.ts           # Entrega de tokens (cookie, bearer ou ambos)
│   │
│   ├── constants/
│   │   ├── index.ts
│   │   ├── throttle-configs.ts              # Configurações de rate limiting recomendadas
│   │   └── error-codes.ts                   # Re-export dos error codes
│   │
│   ├── redis/
│   │   ├── auth-redis.service.ts              # Wrapper sobre ioredis
│   │   └── auth-redis.module.ts               # Módulo Redis interno
│   │
│   ├── controllers/
│   │   ├── auth.controller.ts                 # Endpoints principais de auth
│   │   ├── mfa.controller.ts                  # Endpoints de MFA
│   │   ├── password-reset.controller.ts       # Endpoints de reset de senha
│   │   ├── session.controller.ts              # Endpoints de sessões
│   │   ├── platform-auth.controller.ts        # Endpoints de admin da plataforma
│   │   └── invitation.controller.ts           # Endpoints de convites
│   │
│   ├── strategies/
│   │   ├── jwt.strategy.ts                    # Passport JWT para dashboard
│   │   └── jwt-platform.strategy.ts           # Passport JWT para plataforma
│   │
│   ├── guards/
│   │   ├── jwt-auth.guard.ts                  # Guard JWT padrão
│   │   ├── jwt-platform.guard.ts              # Guard JWT para admins
│   │   ├── roles.guard.ts                     # Guard de roles com hierarquia
│   │   ├── platform-roles.guard.ts            # Guard de roles da plataforma
│   │   ├── user-status.guard.ts               # Verificação de status do usuário
│   │   ├── mfa-required.guard.ts              # Exige MFA completado
│   │   ├── ws-jwt.guard.ts                    # Guard JWT para WebSockets
│   │   ├── self-or-admin.guard.ts             # Acesso próprio ou admin
│   │   └── optional-auth.guard.ts             # Autenticação opcional
│   │
│   ├── decorators/
│   │   ├── current-user.decorator.ts          # @CurrentUser()
│   │   ├── roles.decorator.ts                 # @Roles()
│   │   ├── platform-roles.decorator.ts        # @PlatformRoles()
│   │   ├── public.decorator.ts                # @Public()
│   │   └── skip-mfa.decorator.ts              # @SkipMfa()
│   │
│   ├── oauth/
│   │   ├── oauth.module.ts                    # Módulo OAuth dinâmico
│   │   ├── oauth.service.ts                   # Serviço central de OAuth
│   │   └── google/
│   │       ├── google-oauth.plugin.ts         # Plugin Google OAuth
│   │       ├── google.strategy.ts             # Passport Google Strategy
│   │       └── google-auth.guard.ts           # Guard para rota Google
│   │
│   ├── providers/
│   │   └── no-op-email.provider.ts          # Email provider para desenvolvimento (logs only)
│   │
│   ├── hooks/
│   │   └── no-op-auth.hooks.ts              # Hooks padrão (no-op)
│   │
│   ├── dto/
│   │   ├── register.dto.ts                    # DTO de registro
│   │   ├── login.dto.ts                       # DTO de login
│   │   ├── forgot-password.dto.ts             # DTO de esqueci minha senha
│   │   ├── reset-password.dto.ts              # DTO de reset de senha
│   │   ├── mfa-verify.dto.ts                  # DTO de verificação MFA
│   │   ├── mfa-challenge.dto.ts               # DTO de desafio MFA
│   │   ├── mfa-disable.dto.ts                 # DTO de desativação MFA
│   │   ├── platform-login.dto.ts              # DTO de login da plataforma
│   │   ├── accept-invitation.dto.ts           # DTO de aceite de convite
│   │   └── create-invitation.dto.ts           # DTO de criação de convite
│   │
│   ├── crypto/
│   │   ├── aes-gcm.ts                         # Criptografia AES-256-GCM
│   │   └── secure-token.ts                    # Geração de tokens seguros
│   │
│   └── errors/
│       ├── auth-error-codes.ts                # Constantes de códigos de erro
│       └── auth-exception.ts                  # Classe AuthException
```

### 3.2 Barrel export (`src/index.ts`)

O arquivo `index.ts` exporta toda a API publica do pacote:

```typescript
// Módulo principal
export { BymaxAuthModule } from "./bymax-one-nest-auth.module";

// Constantes de injeção
export {
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_REDIS_CLIENT,
} from "./bymax-one-nest-auth.constants";

// Interfaces
export type { BymaxAuthModuleOptions } from "./interfaces/auth-module-options.interface";
export type {
  IUserRepository,
  AuthUser,
} from "./interfaces/user-repository.interface";
export type {
  IPlatformUserRepository,
  AuthPlatformUser,
} from "./interfaces/platform-user-repository.interface";
export type { IEmailProvider } from "./interfaces/email-provider.interface";
export type {
  IAuthHooks,
  HookContext,
  BeforeRegisterResult,
  OAuthLoginResult,
} from "./interfaces/auth-hooks.interface";
export type { OAuthProviderPlugin } from "./interfaces/oauth-provider.interface";
export type {
  OAuthProfile,
} from "./interfaces/auth-hooks.interface";
export type {
  DashboardJwtPayload,
  PlatformJwtPayload,
  MfaTempPayload,
} from "./interfaces/jwt-payload.interface";
export type {
  AuthenticatedRequest,
  PlatformAuthenticatedRequest,
} from "./interfaces/authenticated-request.interface";

// Guards
export { JwtAuthGuard } from "./guards/jwt-auth.guard";
export { JwtPlatformGuard } from "./guards/jwt-platform.guard";
export { RolesGuard } from "./guards/roles.guard";
export { PlatformRolesGuard } from "./guards/platform-roles.guard";
export { UserStatusGuard } from "./guards/user-status.guard";
export { MfaRequiredGuard } from "./guards/mfa-required.guard";
export { WsJwtGuard } from "./guards/ws-jwt.guard";
export { SelfOrAdminGuard } from "./guards/self-or-admin.guard";
export { OptionalAuthGuard } from "./guards/optional-auth.guard";

// Decorators
export { CurrentUser } from "./decorators/current-user.decorator";
export { Roles } from "./decorators/roles.decorator";
export { PlatformRoles } from "./decorators/platform-roles.decorator";
export { Public } from "./decorators/public.decorator";
export { SkipMfa } from "./decorators/skip-mfa.decorator";

// Serviços (apenas API pública)
export { AuthService } from "./services/auth.service";

// Tipos de retorno (para uso em hooks, testes e extensões)
export type { AuthResult, MfaChallengeResult } from "./services/auth.service";
export type { PlatformAuthResult } from "./services/platform-auth.service";
export type { SessionInfo } from "./services/session.service";
export type { MfaSetupResult } from "./services/mfa.service";

// Erros
export { AuthException } from "./errors/auth-exception";
export { AUTH_ERROR_CODES } from "./errors/auth-error-codes";

// Rate limiting configs
export { AUTH_THROTTLE_CONFIGS } from "./constants/throttle-configs";

// DTOs (para uso em testes ou extensões)
export { RegisterDto } from "./dto/register.dto";
export { LoginDto } from "./dto/login.dto";
export { ForgotPasswordDto } from "./dto/forgot-password.dto";
export { ResetPasswordDto } from "./dto/reset-password.dto";
export { MfaVerifyDto } from "./dto/mfa-verify.dto";
export { MfaChallengeDto } from "./dto/mfa-challenge.dto";
export { MfaDisableDto } from "./dto/mfa-disable.dto";
export { PlatformLoginDto } from "./dto/platform-login.dto";
export { AcceptInvitationDto } from "./dto/accept-invitation.dto";
export { CreateInvitationDto } from "./dto/create-invitation.dto";

// Providers para desenvolvimento
export { NoOpEmailProvider } from "./providers/no-op-email.provider";
export { NoOpAuthHooks } from "./hooks/no-op-auth.hooks";
```

> **API publica vs interna:** Apenas os services abaixo sao exportados para uso direto pela aplicacao host. Os demais services sao internos e nao devem ser acessados diretamente.
>
> **Services publicos:** `AuthService` (para operacoes programaticas de auth)
> **Services protegidos:** Todos os demais services sao internos ao modulo. Use os controllers e hooks para interagir com o pacote.

---

## 4. API de Configuração

### 4.1 Interface `BymaxAuthModuleOptions`

Esta é a interface principal que controla todo o comportamento do módulo. A aplicação host fornece essas opções ao registrar o módulo.

```typescript
export interface BymaxAuthModuleOptions {
  /**
   * Configuração de JWT.
   * O secret é OBRIGATÓRIO e deve ter no mínimo 32 caracteres.
   */
  jwt: {
    /**
     * Chave secreta para assinatura JWT. OBRIGATÓRIO.
     * Requisitos:
     * - Mínimo 32 caracteres
     * - Deve ser gerado com entropia criptográfica (ex: crypto.randomBytes(32).toString('base64'))
     * - O módulo valida no startup e rejeita secrets fracos com os seguintes critérios:
     *   1. Comprimento mínimo de 32 caracteres
     *   2. Entropia mínima de Shannon estimada em 3.5 bits/char
     *   3. Rejeita strings com todos os caracteres iguais (ex: 'aaaa...') ou padrões repetitivos
     *   4. Recomendado: crypto.randomBytes(32).toString('base64') — 44 chars, ~5.9 bits/char
     * - O mesmo critério se aplica a `mfa.encryptionKey`
     */
    secret: string;

    /** Tempo de expiração do access token. Padrão: '15m' */
    accessExpiresIn?: string;

    /** Max-age do cookie de access token em milissegundos. Padrão: 900_000 (15 minutos) */
    accessCookieMaxAgeMs?: number;

    /** Tempo de expiração do refresh token em dias. Padrão: 7 */
    refreshExpiresInDays?: number;

    /** Algoritmo de assinatura. Padrão: 'HS256' */
    algorithm?: "HS256";

    /** Janela de tolerância para rotação de refresh token em segundos. Padrão: 30 */
    refreshGraceWindowSeconds?: number;
  };

  /**
   * Configuração de hashing de senha.
   */
  password?: {
    /** Número de salt rounds para bcrypt. Padrão: 12 */
    saltRounds?: number;
  };

  /**
   * Modo de entrega dos tokens JWT.
   *
   * - `'cookie'`  — tokens em cookies HTTP-only (padrão — recomendado para web/SPA com mesmo domínio)
   * - `'bearer'`  — tokens retornados no body do response; guards extraem do header `Authorization: Bearer`
   *                 (recomendado para React Native, apps mobile e clientes que não gerenciam cookies)
   * - `'both'`    — seta cookies E retorna tokens no body; guards aceitam cookie e header `Authorization: Bearer`
   *                 (útil quando o mesmo backend serve web e mobile)
   *
   * Padrão: `'cookie'`
   */
  tokenDelivery?: 'cookie' | 'bearer' | 'both';

  /**
   * Configuração de cookies HTTP.
   * Ignorado quando `tokenDelivery: 'bearer'`.
   */
  cookies?: {
    /** Nome do cookie de access token. Padrão: 'access_token' */
    accessTokenName?: string;

    /** Nome do cookie de refresh token. Padrão: 'refresh_token' */
    refreshTokenName?: string;

    /** Nome do cookie de sinal de sessão. Padrão: 'has_session' */
    sessionSignalName?: string;

    /** Path do cookie de refresh. Padrão: '/auth' */
    refreshCookiePath?: string;

    /**
     * Função para resolver domínios de cookie a partir do domínio da requisição.
     * Útil para suporte multi-domínio (ex: api.example.com e app.example.com).
     * Retorna array de domínios onde os cookies devem ser setados.
     */
    resolveDomains?: (requestDomain: string) => string[];
  };

  /**
   * Configuração de autenticação multi-fator (MFA).
   * Se habilitado, encryptionKey e issuer são OBRIGATÓRIOS.
   */
  mfa?: {
    /**
     * Chave de criptografia AES-256-GCM para secrets TOTP. OBRIGATÓRIO se MFA habilitado.
     * Deve ser exatamente 32 bytes (ex: crypto.randomBytes(32).toString('base64') → 44 caracteres base64).
     * Validado no startup — o módulo rejeita chaves com tamanho incorreto.
     */
    encryptionKey: string;

    /** Nome da aplicação exibido no app autenticador. OBRIGATÓRIO. */
    issuer: string;

    /** Quantidade de recovery codes gerados. Padrão: 8 */
    recoveryCodeCount?: number;

    /** Janela de tolerância TOTP (periodos de 30s). Padrão: 1 */
    totpWindow?: number;
  };

  /**
   * Configuração do sistema de sessões.
   */
  sessions?: {
    /** Habilita gerenciamento de sessões. Padrão: false */
    enabled?: boolean;

    /** Número máximo de sessões simultâneas por usuário. Padrão: 5 */
    defaultMaxSessions?: number;

    /**
     * Função para resolver o limite de sessões por usuário.
     * Permite limites diferentes por plano/role.
     */
    maxSessionsResolver?: (user: AuthUser) => number | Promise<number>;

    /** Estratégia de despejo quando o limite é atingido. Padrão: 'fifo' */
    evictionStrategy?: "fifo";
  };

  /**
   * Configuração de proteção contra brute-force.
   */
  bruteForce?: {
    /** Número máximo de tentativas antes do bloqueio. Padrão: 10 */
    maxAttempts?: number;

    /** Janela de tempo em segundos para contagem de tentativas. Padrão: 900 (15 minutos) */
    windowSeconds?: number;
  };

  /**
   * Configuração de reset de senha.
   */
  passwordReset?: {
    /** Método de reset: token (link por email) ou otp (código numérico). Padrão: 'token' */
    method?: "token" | "otp";

    /** TTL do token de reset em segundos. Padrão: 3600 (1 hora) */
    tokenTtlSeconds?: number;

    /** TTL do OTP de reset em segundos. Padrão: 600 (10 minutos) */
    otpTtlSeconds?: number;

    /** Comprimento do código OTP. Padrão: 6 */
    otpLength?: number;
  };

  /**
   * Configuração de verificação de email.
   */
  emailVerification?: {
    /** Se true, usuários devem verificar email antes de logar. Padrão: false */
    required?: boolean;

    /** TTL do OTP de verificação em segundos. Padrão: 600 (10 minutos) */
    otpTtlSeconds?: number;
  };

  /**
   * Configuração do módulo de administração da plataforma.
   */
  platformAdmin?: {
    /** Habilita endpoints e lógica de admin da plataforma. Padrão: false */
    enabled?: boolean;
  };

  /**
   * Configuração do sistema de convites.
   */
  invitations?: {
    /** Habilita sistema de convites. Padrão: false */
    enabled?: boolean;

    /** TTL do token de convite em segundos. Padrão: 604800 (7 dias) */
    tokenTtlSeconds?: number;
  };

  /**
   * Configuração de roles e hierarquia.
   */
  roles: {
    /**
     * Hierarquia de roles do dashboard/tenant.
     * Cada role herda as permissões dos roles listados.
     * OBRIGATÓRIO.
     *
     * Exemplo:
     * {
     *   OWNER: ['ADMIN', 'MEMBER', 'VIEWER'],
     *   ADMIN: ['MEMBER', 'VIEWER'],
     *   MEMBER: ['VIEWER'],
     *   VIEWER: []
     * }
     */
    hierarchy: Record<string, string[]>;

    /**
     * Hierarquia de roles da plataforma (super-admins).
     * Opcional — necessário apenas se platformAdmin.enabled = true.
     */
    platformHierarchy?: Record<string, string[]>;
  };

  /**
   * Lista de status que bloqueiam acesso.
   * Padrão: ['BANNED', 'INACTIVE', 'SUSPENDED']
   */
  blockedStatuses?: string[];

  /**
   * Namespace para chaves Redis. Padrão: 'auth'
   * Todas as chaves serao prefixadas com este namespace.
   */
  redisNamespace?: string;

  /**
   * Configuração de provedores OAuth.
   */
  oauth?: {
    google?: {
      clientId: string;
      clientSecret: string;
      callbackUrl: string;
    };
  };

  /**
   * Prefixo para todas as rotas do módulo. Padrão: 'auth'
   * Exemplo: com prefixo 'auth', as rotas serao /auth/login, /auth/register, etc.
   */
  routePrefix?: string;

  /**
   * Função para resolver o tenantId a partir da requisição.
   * Se fornecido, o pacote usa o tenantId resolvido e IGNORA o tenantId do body.
   * Isso previne tenant spoofing onde um cliente envia tenantId de outro tenant.
   *
   * Exemplos:
   * - Resolução por subdomínio: (req) => req.hostname.split('.')[0]
   * - Resolução por header: (req) => req.headers['x-tenant-id']
   * - Resolução por path: (req) => req.params.tenantId
   *
   * Se não fornecido, o pacote usa o tenantId do body/DTO da requisição.
   * Neste caso, a aplicação host é responsável por validar o tenantId.
   */
  tenantIdResolver?: (req: any) => string | Promise<string>;

  /**
   * Controle granular de quais controllers são registrados.
   * Permite desabilitar endpoints que não são necessários.
   */
  controllers?: {
    /** Habilita AuthController (register, login, logout, refresh, me). Padrão: true */
    auth?: boolean;

    /** Habilita MfaController. Padrão: true (se mfa configurado) */
    mfa?: boolean;

    /** Habilita PasswordResetController. Padrão: true */
    passwordReset?: boolean;

    /** Habilita SessionController. Padrão: true (se sessions.enabled) */
    sessions?: boolean;

    /** Habilita PlatformAuthController. Padrão: true (se platformAdmin.enabled) */
    platformAuth?: boolean;

    /** Habilita InvitationController. Padrão: true (se invitations.enabled) */
    invitations?: boolean;
  };

  /**
   * TTL do cache de status do usuário em segundos. Padrão: 60
   * O status e cacheado no Redis para evitar consultas ao banco a cada requisição.
   */
  userStatusCacheTtlSeconds?: number;
}
```

### 4.2 Tabela de opções com valores padrão

| Opção                             | Tipo                       | Obrigatório | Padrão                                | Descrição                              |
| --------------------------------- | -------------------------- | ----------- | ------------------------------------- | -------------------------------------- |
| `tokenDelivery`                   | `'cookie' \| 'bearer' \| 'both'` | Não  | `'cookie'`                            | Modo de entrega dos tokens (web, mobile ou ambos) |
| `jwt.secret`                      | `string`                   | Sim         | —                                     | Chave secreta JWT, min 32 caracteres   |
| `jwt.accessExpiresIn`             | `string`                   | Não         | `'15m'`                               | Expiração do access token              |
| `jwt.accessCookieMaxAgeMs`        | `number`                   | Não         | `900_000`                             | Max-age do cookie de access            |
| `jwt.refreshExpiresInDays`        | `number`                   | Não         | `7`                                   | Expiração do refresh token em dias     |
| `jwt.algorithm`                   | `'HS256'`                  | Não         | `'HS256'`                             | Algoritmo de assinatura JWT            |
| `jwt.refreshGraceWindowSeconds`   | `number`                   | Não         | `30`                                  | Grace window da rotação de refresh     |
| `password.saltRounds`             | `number`                   | Não         | `12`                                  | Salt rounds do bcrypt                  |
| `cookies.accessTokenName`         | `string`                   | Não         | `'access_token'`                      | Nome do cookie de access               |
| `cookies.refreshTokenName`        | `string`                   | Não         | `'refresh_token'`                     | Nome do cookie de refresh              |
| `cookies.sessionSignalName`       | `string`                   | Não         | `'has_session'`                       | Nome do cookie sinal                   |
| `cookies.refreshCookiePath`       | `string`                   | Não         | `'/auth'`                             | Path do cookie de refresh              |
| `cookies.resolveDomains`          | `function`                 | Não         | `undefined`                           | Resolver de domínios multi-domínio     |
| `mfa.encryptionKey`               | `string`                   | Condicional | —                                     | Chave AES-256-GCM (obrigatório se MFA) |
| `mfa.issuer`                      | `string`                   | Condicional | —                                     | Nome do app no autenticador            |
| `mfa.recoveryCodeCount`           | `number`                   | Não         | `8`                                   | Quantidade de recovery codes           |
| `mfa.totpWindow`                  | `number`                   | Não         | `1`                                   | Janela de tolerância TOTP              |
| `sessions.enabled`                | `boolean`                  | Não         | `false`                               | Habilita gerenciamento de sessões      |
| `sessions.defaultMaxSessions`     | `number`                   | Não         | `5`                                   | Máximo de sessões simultâneas          |
| `sessions.maxSessionsResolver`    | `function`                 | Não         | `undefined`                           | Resolver personalizado de limite       |
| `sessions.evictionStrategy`       | `'fifo'`                   | Não         | `'fifo'`                              | Estratégia de despejo de sessões       |
| `bruteForce.maxAttempts`          | `number`                   | Não         | `10`                                  | Tentativas antes do bloqueio           |
| `bruteForce.windowSeconds`        | `number`                   | Não         | `900`                                 | Janela de contagem (15 min)            |
| `passwordReset.method`            | `'token' \| 'otp'`         | Não         | `'token'`                             | Método de reset                        |
| `passwordReset.tokenTtlSeconds`   | `number`                   | Não         | `3600`                                | TTL do token de reset                  |
| `passwordReset.otpTtlSeconds`     | `number`                   | Não         | `600`                                 | TTL do OTP de reset                    |
| `passwordReset.otpLength`         | `number`                   | Não         | `6`                                   | Comprimento do OTP                     |
| `emailVerification.required`      | `boolean`                  | Não         | `false`                               | Exige verificação de email             |
| `emailVerification.otpTtlSeconds` | `number`                   | Não         | `600`                                 | TTL do OTP de verificação              |
| `platformAdmin.enabled`           | `boolean`                  | Não         | `false`                               | Habilita admin da plataforma           |
| `invitations.enabled`             | `boolean`                  | Não         | `false`                               | Habilita sistema de convites           |
| `invitations.tokenTtlSeconds`     | `number`                   | Não         | `604800`                              | TTL do token de convite (7 dias)       |
| `roles.hierarchy`                 | `Record<string, string[]>` | Sim         | —                                     | Hierarquia de roles                    |
| `roles.platformHierarchy`         | `Record<string, string[]>` | Não         | `undefined`                           | Hierarquia de roles da plataforma      |
| `blockedStatuses`                 | `string[]`                 | Não         | `['BANNED', 'INACTIVE', 'SUSPENDED']` | Status que bloqueiam acesso            |
| `redisNamespace`                  | `string`                   | Não         | `'auth'`                              | Namespace das chaves Redis             |
| `oauth.google.clientId`           | `string`                   | Condicional | —                                     | Client ID Google OAuth                 |
| `oauth.google.clientSecret`       | `string`                   | Condicional | —                                     | Client Secret Google OAuth             |
| `oauth.google.callbackUrl`        | `string`                   | Condicional | —                                     | URL de callback Google OAuth           |
| `routePrefix`                     | `string`                   | Não         | `'auth'`                              | Prefixo das rotas                      |
| `tenantIdResolver`                | `function`                 | Não         | `undefined`                           | Resolver de tenantId (previne spoofing) |
| `controllers.auth`                | `boolean`                  | Não         | `true`                                | Habilita AuthController                |
| `controllers.mfa`                 | `boolean`                  | Não         | `true`                                | Habilita MfaController                 |
| `controllers.passwordReset`       | `boolean`                  | Não         | `true`                                | Habilita PasswordResetController       |
| `controllers.sessions`            | `boolean`                  | Não         | `true`                                | Habilita SessionController             |
| `controllers.platformAuth`        | `boolean`                  | Não         | `true`                                | Habilita PlatformAuthController        |
| `controllers.invitations`         | `boolean`                  | Não         | `true`                                | Habilita InvitationController          |
| `userStatusCacheTtlSeconds`       | `number`                   | Não         | `60`                                  | TTL do cache de status                 |

### 4.3 Exemplo de registro com `registerAsync`

```typescript
// app.module.ts
import { Module } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { ThrottlerModule } from "@nestjs/throttler";
import {
  BymaxAuthModule,
  BYMAX_AUTH_USER_REPOSITORY,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_REDIS_CLIENT,
} from "@bymax-one/nest-auth";

import { PrismaUserRepository } from "./auth/repositories/prisma-user.repository";
import { PrismaPlatformUserRepository } from "./auth/repositories/prisma-platform-user.repository";
import { ResendEmailProvider } from "./auth/providers/resend-email.provider";
import { AppAuthHooks } from "./auth/hooks/app-auth.hooks";
import { RedisService } from "./redis/redis.service";

@Module({
  imports: [
    ConfigModule.forRoot(),
    ThrottlerModule.forRoot([{ ttl: 60_000, limit: 100 }]),

    BymaxAuthModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        jwt: {
          secret: config.getOrThrow<string>("JWT_SECRET"),
          accessExpiresIn: "15m",
          refreshExpiresInDays: 7,
        },
        password: {
          saltRounds: 12,
        },
        cookies: {
          resolveDomains: (domain: string) => {
            // Suporte multi-domínio: api.example.com → ['.example.com']
            const parts = domain.split(".");
            if (parts.length >= 2) {
              return ["." + parts.slice(-2).join(".")];
            }
            return [domain];
          },
        },
        mfa: {
          encryptionKey: config.getOrThrow<string>("MFA_ENCRYPTION_KEY"),
          issuer: "Bymax Finance",
        },
        sessions: {
          enabled: true,
          defaultMaxSessions: 5,
          maxSessionsResolver: async (user) => {
            // Planos premium permitem mais sessões
            return user.role === "OWNER" ? 10 : 5;
          },
        },
        bruteForce: {
          maxAttempts: 10,
          windowSeconds: 900,
        },
        passwordReset: {
          method: "otp",
          otpLength: 6,
          otpTtlSeconds: 600,
        },
        emailVerification: {
          required: true,
        },
        platformAdmin: {
          enabled: true,
        },
        invitations: {
          enabled: true,
          tokenTtlSeconds: 604800,
        },
        roles: {
          hierarchy: {
            OWNER: ["ADMIN", "MEMBER", "VIEWER"],
            ADMIN: ["MEMBER", "VIEWER"],
            MEMBER: ["VIEWER"],
            VIEWER: [],
          },
          platformHierarchy: {
            SUPER_ADMIN: ["ADMIN", "SUPPORT"],
            ADMIN: ["SUPPORT"],
            SUPPORT: [],
          },
        },
        blockedStatuses: ["BANNED", "INACTIVE", "SUSPENDED"],
        oauth: {
          google: {
            clientId: config.getOrThrow<string>("GOOGLE_CLIENT_ID"),
            clientSecret: config.getOrThrow<string>("GOOGLE_CLIENT_SECRET"),
            callbackUrl: config.getOrThrow<string>("GOOGLE_CALLBACK_URL"),
          },
        },
        routePrefix: "auth",
        // tenantIdResolver: (req) => req.hostname.split('.')[0], // descomente para resolver tenantId por subdomínio
      }),
      providers: [
        {
          provide: BYMAX_AUTH_USER_REPOSITORY,
          useClass: PrismaUserRepository,
        },
        {
          provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
          useClass: PrismaPlatformUserRepository,
        },
        {
          provide: BYMAX_AUTH_EMAIL_PROVIDER,
          useClass: ResendEmailProvider,
        },
        {
          provide: BYMAX_AUTH_HOOKS,
          useClass: AppAuthHooks,
        },
        {
          provide: BYMAX_AUTH_REDIS_CLIENT,
          useFactory: (redisService: RedisService) => redisService.getClient(),
          inject: [RedisService],
        },
      ],
    }),
  ],
})
export class AppModule {}
```

### 4.4 Tokens de injeção

O pacote define constantes de injeção que a aplicação host deve fornecer:

```typescript
// bymax-one-nest-auth.constants.ts

/** Token para as opções resolvidas do módulo */
export const BYMAX_AUTH_OPTIONS = Symbol("BYMAX_AUTH_OPTIONS");

/**
 * Token para o repositório de usuários do dashboard/tenant.
 * A aplicação host DEVE fornecer uma implementação de IUserRepository.
 */
export const BYMAX_AUTH_USER_REPOSITORY = Symbol("BYMAX_AUTH_USER_REPOSITORY");

/**
 * Token para o repositório de usuários da plataforma.
 * Necessário apenas se platformAdmin.enabled = true.
 */
export const BYMAX_AUTH_PLATFORM_USER_REPOSITORY = Symbol(
  "BYMAX_AUTH_PLATFORM_USER_REPOSITORY",
);

/**
 * Token para o provider de email.
 * A aplicação host DEVE fornecer uma implementação de IEmailProvider.
 */
export const BYMAX_AUTH_EMAIL_PROVIDER = Symbol("BYMAX_AUTH_EMAIL_PROVIDER");

/**
 * Token para os hooks de ciclo de vida.
 * Opcional — se não fornecido, um NoOpAuthHooks é usado.
 */
export const BYMAX_AUTH_HOOKS = Symbol("BYMAX_AUTH_HOOKS");

/**
 * Token para a instância do cliente Redis (ioredis).
 * A aplicação host DEVE fornecer uma instância Redis.
 */
export const BYMAX_AUTH_REDIS_CLIENT = Symbol("BYMAX_AUTH_REDIS_CLIENT");
```

**Resumo dos providers obrigatórios e opcionais:**

| Token                                 | Interface                 | Obrigatório | Descrição                                          |
| ------------------------------------- | ------------------------- | ----------- | -------------------------------------------------- |
| `BYMAX_AUTH_USER_REPOSITORY`          | `IUserRepository`         | Sim         | Repositório de usuários                            |
| `BYMAX_AUTH_PLATFORM_USER_REPOSITORY` | `IPlatformUserRepository` | Condicional | Repositório de admins (se `platformAdmin.enabled`) |
| `BYMAX_AUTH_EMAIL_PROVIDER`           | `IEmailProvider`          | Sim         | Provider de envio de emails                        |
| `BYMAX_AUTH_HOOKS`                    | `IAuthHooks`              | Não         | Hooks de ciclo de vida                             |
| `BYMAX_AUTH_REDIS_CLIENT`             | `Redis` (ioredis)         | Sim         | Instância do cliente Redis                         |

---

## 5. Contratos de Repositório

### 5.1 Interface `AuthUser`

Esta interface define a forma mínima de um usuário que o módulo espera. A aplicação host pode ter campos adicionais no seu modelo de banco de dados, mas deve mapear para esta interface ao implementar o repositório.

```typescript
export interface AuthUser {
  /** Identificador único do usuário (UUID ou string) */
  id: string;

  /** Email do usuário (único por tenant) */
  email: string;

  /**
   * Hash bcrypt da senha. Null para usuários que registraram via OAuth.
   * Quando null, login por senha e bloqueado.
   */
  passwordHash: string | null;

  /** Nome completo do usuário */
  name: string;

  /** Role do usuário no tenant (ex: 'OWNER', 'ADMIN', 'MEMBER', 'VIEWER') */
  role: string;

  /** Status da conta (ex: 'ACTIVE', 'PENDING_APPROVAL', 'BANNED', 'INACTIVE', 'SUSPENDED') */
  status: string;

  /** Se o email foi verificado */
  emailVerified: boolean;

  mfaEnabled?: boolean; // Opcional — presente apenas quando MFA está habilitado na configuração

  mfaSecret?: string | null; // Opcional — TOTP secret encriptado (AES-256-GCM)

  mfaRecoveryCodes?: string[] | null; // Opcional — Recovery codes com hash bcrypt

  /** Timestamp do ultimo login */
  lastLoginAt: Date | null;

  /** ID do tenant ao qual o usuário pertence */
  tenantId: string;

  /** Timestamp de soft delete. Null se não deletado. */
  deletedAt: Date | null;

  /** Timestamp de criação */
  createdAt: Date;

  /** Timestamp de última atualização */
  updatedAt: Date;
}
```

> **Nota sobre campos MFA:** Os campos `mfaEnabled`, `mfaSecret` e `mfaRecoveryCodes` são opcionais na interface. Quando a configuração `mfa` não é fornecida ao módulo, o pacote ignora esses campos completamente. A aplicação host só precisa incluí-los no schema do banco de dados se habilitar MFA.

### 5.2 Interface `IUserRepository`

```typescript
export interface IUserRepository {
  /**
   * Busca um usuário por ID.
   * Deve ignorar usuários com deletedAt != null.
   * @returns O usuário ou null se não encontrado
   */
  findById(id: string): Promise<AuthUser | null>;

  /**
   * Busca um usuário por email dentro de um tenant.
   * Deve ignorar usuários com deletedAt != null.
   * @returns O usuário ou null se não encontrado
   */
  findByEmail(email: string, tenantId: string): Promise<AuthUser | null>;

  /**
   * Cria um novo usuário no banco de dados.
   * Null para usuários criados via OAuth ou convite sem senha.
   * @param data Dados do novo usuário
   * @returns O usuário criado
   */
  create(data: {
    email: string;
    passwordHash: string | null;
    name: string;
    role: string;
    status: string;
    emailVerified: boolean;
    tenantId: string;
  }): Promise<AuthUser>;

  /**
   * Atualiza o hash da senha de um usuário.
   * Também deve atualizar updatedAt.
   */
  updatePassword(userId: string, passwordHash: string): Promise<void>;

  /**
   * Atualiza as configurações de MFA de um usuário.
   * Usado para habilitar, desabilitar e atualizar recovery codes.
   */
  updateMfa(
    userId: string,
    data: {
      mfaEnabled: boolean;
      mfaSecret: string | null;
      mfaRecoveryCodes: string[] | null;
    },
  ): Promise<void>;

  /**
   * Atualiza o timestamp de ultimo login.
   */
  updateLastLogin(userId: string): Promise<void>;

  /**
   * Atualiza o status de um usuário.
   */
  updateStatus(userId: string, status: string): Promise<void>;

  /**
   * Marca o email como verificado.
   */
  updateEmailVerified(userId: string, verified: boolean): Promise<void>;

  /**
   * Busca um usuário por ID de provider OAuth (ex: Google ID).
   * @param provider Nome do provider (ex: 'google')
   * @param providerId ID do usuário no provider
   * @param tenantId ID do tenant
   * @returns O usuário ou null se não encontrado
   */
  findByOAuthId(
    provider: string,
    providerId: string,
    tenantId: string,
  ): Promise<AuthUser | null>;

  /**
   * Vincula uma conta OAuth a um usuário existente.
   * Salva o provider e providerId na tabela de OAuth links.
   */
  linkOAuth(
    userId: string,
    provider: string,
    providerId: string,
  ): Promise<void>;

  /**
   * Cria um novo usuário via OAuth (sem senha).
   * @returns O usuário criado
   */
  createWithOAuth(data: {
    email: string;
    name: string;
    role: string;
    status: string;
    emailVerified: boolean;
    tenantId: string;
    provider: string;
    providerId: string;
  }): Promise<AuthUser>;
}
```

> **Nota:** O pacote invalida automaticamente o cache de status do usuario no Redis (`auth:us:{userId}`) apos qualquer chamada a `updateStatus()`. A aplicacao host **nao** precisa gerenciar o cache Redis do pacote.

### 5.3 Interface `AuthPlatformUser`

Usuários da plataforma (super-admins) tem uma estrutura mais simples, pois não pertencem a um tenant específico.

```typescript
export interface AuthPlatformUser {
  /** Identificador único do admin */
  id: string;

  /** Email do admin */
  email: string;

  /** Hash bcrypt da senha */
  passwordHash: string;

  /** Nome completo */
  name: string;

  /** Role na plataforma (ex: 'SUPER_ADMIN', 'ADMIN', 'SUPPORT') */
  role: string;

  /** Status da conta */
  status: string;

  /** Se MFA está habilitado */
  mfaEnabled: boolean;

  /** Secret TOTP criptografado */
  mfaSecret: string | null;

  /** Recovery codes hasheados */
  mfaRecoveryCodes: string[] | null;

  /** Timestamp do ultimo login */
  lastLoginAt: Date | null;

  /** Timestamp de criação */
  createdAt: Date;

  /** Timestamp de última atualização */
  updatedAt: Date;

  /**
   * Timestamp de exclusão lógica (soft-delete).
   * Admins com `deletedAt != null` devem ser tratados como inexistentes:
   * - `IPlatformUserRepository.findById()` e `findByEmail()` DEVEM retornar `null`
   * - O `JwtPlatformGuard` rejeitará o acesso pois o repositório não encontrará o admin
   * - Ao excluir um admin, a aplicação host DEVE chamar `PlatformAuthService.revokeAllPlatformSessions()`
   *   para invalidar todos os tokens ativos imediatamente
   */
  deletedAt: Date | null;
}
```

### 5.4 Interface `IPlatformUserRepository`

```typescript
export interface IPlatformUserRepository {
  /**
   * Busca um admin da plataforma por ID.
   */
  findById(id: string): Promise<AuthPlatformUser | null>;

  /**
   * Busca um admin da plataforma por email.
   */
  findByEmail(email: string): Promise<AuthPlatformUser | null>;

  /**
   * Atualiza o timestamp de ultimo login.
   */
  updateLastLogin(userId: string): Promise<void>;

  /**
   * Atualiza as configurações de MFA.
   */
  updateMfa(
    userId: string,
    data: {
      mfaEnabled: boolean;
      mfaSecret: string | null;
      mfaRecoveryCodes: string[] | null;
    },
  ): Promise<void>;

  /**
   * Atualiza a senha (hash) de um admin da plataforma.
   */
  updatePassword(userId: string, passwordHash: string): Promise<void>;

  /**
   * Atualiza o status de um admin da plataforma.
   */
  updateStatus(userId: string, status: string): Promise<void>;
}
```

### 5.5 Interface `IEmailProvider`

```typescript
export interface IEmailProvider {
  /**
   * Envia email com token de reset de senha (link).
   * Usado quando passwordReset.method = 'token'.
   */
  sendPasswordResetToken(
    email: string,
    token: string,
    name: string,
    locale?: string,
  ): Promise<void>;

  /**
   * Envia email com OTP de reset de senha (código numérico).
   * Usado quando passwordReset.method = 'otp'.
   */
  sendPasswordResetOtp(
    email: string,
    otp: string,
    name: string,
    locale?: string,
  ): Promise<void>;

  /**
   * Envia email com OTP de verificação de email.
   */
  sendEmailVerificationOtp(
    email: string,
    otp: string,
    name: string,
    locale?: string,
  ): Promise<void>;

  /**
   * Notifica o usuário que MFA foi habilitado.
   */
  sendMfaEnabledNotification(
    email: string,
    name: string,
    locale?: string,
  ): Promise<void>;

  /**
   * Notifica o usuário que MFA foi desabilitado.
   */
  sendMfaDisabledNotification(
    email: string,
    name: string,
    locale?: string,
  ): Promise<void>;

  /**
   * Alerta o usuário sobre um novo login/sessão.
   * Inclui informações de dispositivo e IP.
   */
  sendNewSessionAlert(
    email: string,
    name: string,
    sessionInfo: { device: string; ip: string; timestamp: Date },
    locale?: string,
  ): Promise<void>;

  /**
   * Envia email de convite para um novo usuário.
   * Inclui o token de convite e informações do convidador.
   */
  sendInvitation(
    email: string,
    data: {
      inviterName: string;
      tenantName: string;
      role: string;
      token: string;
      expiresAt: Date;
    },
    locale?: string,
  ): Promise<void>;
}
```

**Nota importante:** O `IEmailProvider` é **abstrato e template-agnostic**. Ele define **o que** enviar, não **como** renderizar. A aplicação host decide o template, o serviço de email (Resend, SendGrid, SES, etc.) e o layout. Isso permite total liberdade na apresentação.

> **Internacionalização:** Todos os métodos aceitam um parâmetro opcional `locale` (ex: `'pt-BR'`, `'en'`, `'es'`). O pacote repassa o locale do usuário (quando disponível no `AuthUser`) para que a aplicação host renderize templates no idioma correto.

---

## 6. Serviços

### 6.1 AuthService

Serviço central que orquestra registro, login, logout, refresh e verificação de email.

```typescript
class AuthService {
  /**
   * Registra um novo usuário.
   *
   * Fluxo:
   * 1. Executa hook beforeRegister (pode modificar dados ou rejeitar)
   * 2. Verifica se email já existe no tenant
   * 3. Faz hash da senha com bcrypt
   * 4. Cria usuário via IUserRepository.create()
   * 5. Se emailVerification.required, envia OTP de verificação
   * 6. Gera tokens JWT (access + refresh)
   * 7. Executa hook afterRegister
   * 8. Retorna AuthResult com tokens e dados do usuário
   *
   * @designDecision O registro SEMPRE emite tokens, mesmo quando `emailVerification.required = true`.
   * Isso é intencional para permitir que o usuário veja a tela "Verifique seu email" dentro do app
   * (exige estar autenticado). O próximo login após o access token expirar será bloqueado com
   * `AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED` se o email não for verificado.
   * A aplicação host pode usar o hook `afterRegister` ou o campo `emailVerified` no JWT
   * para redirecionar o usuário para a tela de verificação imediatamente após o registro.
   * Janela máxima de acesso sem verificação: `accessExpiresIn` (padrão: 15 minutos).
   *
   * @throws AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS se email já cadastrado
   */
  register(
    dto: RegisterDto,
    ipAddress: string,
    userAgent: string,
  ): Promise<AuthResult>;

  /**
   * Autentica um usuário com email e senha.
   *
   * Fluxo:
   * 1. Verifica brute-force lockout
   * 2. Busca usuário por email e tenant
   * 3. Compara senha com bcrypt (constant-time)
   * 4. Se falhar, registra tentativa e retorna erro genérico
   * 5. Se usuário tem MFA habilitado:
   *    a. Emite mfaToken (JWT de 5 min)
   *    b. Retorna { mfaRequired: true, mfaToken }
   * 6. Se não tem MFA:
   *    a. Reseta contador de brute-force
   *    b. Gera tokens JWT (access + refresh)
   *    c. Cria sessão (se habilitado)
   *    d. Executa hook afterLogin
   *    e. Atualiza lastLoginAt
   * 7. Retorna AuthResult com tokens e dados do usuário
   *
   * @throws AUTH_ERROR_CODES.INVALID_CREDENTIALS (mensagem genérica, nunca revela se email existe)
   * @throws AUTH_ERROR_CODES.ACCOUNT_LOCKED se brute-force ativo
   * @throws AUTH_ERROR_CODES.ACCOUNT_INACTIVE / SUSPENDED / BANNED
   * @throws AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED se verificação exigida e email não verificado
   */
  login(
    dto: LoginDto,
    ipAddress: string,
    userAgent: string,
  ): Promise<AuthResult | MfaChallengeResult>;

  /**
   * Desloga o usuário.
   *
   * Fluxo:
   * 1. Adiciona access JWT na blacklist (Redis, TTL = tempo restante do JWT)
   * 2. Revoga refresh token no Redis
   * 3. Remove sessão (se habilitado)
   * 4. Executa hook afterLogout
   * 5. Retorna void — controller entrega resposta via TokenDeliveryService
   */
  logout(accessToken: string, refreshToken: string): Promise<void>;

  /**
   * Renova o access token usando o refresh token do cookie.
   *
   * Fluxo:
   * 1. Extrai refresh token do cookie
   * 2. Busca sessão no Redis via sha256(refreshToken)
   * 3. Se não encontrado, verifica ponteiro de rotação (grace window de 30s)
   * 4. Gera novo refresh token (rotação)
   * 5. Cria ponteiro de rotação: oldToken → newToken (30s TTL)
   * 6. Armazena novo refresh token no Redis
   * 7. Remove refresh token antigo
   * 8. Retorna AuthResult com novos tokens — controller entrega via TokenDeliveryService
   *
   * @throws AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID se token inválido ou expirado
   */
  refresh(
    rawRefreshToken: string,
    ipAddress: string,
    userAgent: string,
  ): Promise<AuthResult>;

  /**
   * Retorna os dados do usuário autenticado.
   * Busca no repositório por ID (extraido do JWT).
   *
   * @throws AUTH_ERROR_CODES.TOKEN_INVALID se usuário não encontrado
   */
  getMe(userId: string): Promise<AuthUser>;

  /**
   * Verifica o email do usuário com um OTP.
   *
   * Fluxo:
   * 1. Valida OTP no Redis (tenantId necessário para scoped lookup)
   * 2. Marca email como verificado via repositório
   * 3. Executa hook afterEmailVerified
   *
   * @param email Email do usuário
   * @param otp Código OTP
   * @param tenantId ID do tenant (necessário para scoped lookup)
   * @throws AUTH_ERROR_CODES.OTP_INVALID / OTP_EXPIRED / OTP_MAX_ATTEMPTS
   */
  verifyEmail(email: string, otp: string, tenantId: string): Promise<void>;

  /**
   * Reenvia o OTP de verificação de email.
   * Gera novo OTP e armazena no Redis.
   * Envia via IEmailProvider.sendEmailVerificationOtp().
   */
  resendVerificationEmail(email: string, tenantId: string): Promise<void>;
}
```

**Tipos de retorno:**

```typescript
interface AuthResult {
  user: AuthUser;
  accessToken: string;
  rawRefreshToken: string;
  /** Hash da sessão (sha256 do refresh token). Presente quando sessions.enabled = true. */
  sessionHash?: string;
}

interface MfaChallengeResult {
  mfaRequired: true;
  mfaToken: string;
}
```

> **Separação de responsabilidades:** Os services **nunca** manipulam `Response` do Express. Eles retornam objetos com tokens e dados via `AuthResult`. Os **controllers** são responsáveis por chamar `TokenDeliveryService` que, com base no `tokenDelivery` configurado, seta cookies no response (`'cookie'`), retorna tokens no body (`'bearer'`), ou faz ambos (`'both'`). Isso garante que os services são independentes do transporte HTTP e podem ser reutilizados em contextos como WebSocket, CLI ou testes unitários.

### 6.2 PasswordService

Serviço responsável por hashing e comparação de senhas.

```typescript
class PasswordService {
  /**
   * Gera hash bcrypt da senha.
   * Usa o número de salt rounds configurado (padrão: 12).
   *
   * @param plainPassword Senha em texto plano
   * @returns Hash bcrypt
   */
  hash(plainPassword: string): Promise<string>;

  /**
   * Compara senha em texto plano com hash bcrypt.
   * Usa comparação constant-time para prevenir timing attacks.
   *
   * @param plainPassword Senha em texto plano
   * @param hash Hash bcrypt armazenado
   * @returns true se correspondem
   */
  compare(plainPassword: string, hash: string): Promise<boolean>;
}
```

### 6.3 TokenManagerService

Serviço central para emissão, verificação e gerenciamento de todos os tokens JWT e opacos.

```typescript
class TokenManagerService {
  /**
   * Emite um access token JWT.
   *
   * @param payload Claims do JWT (sub, tenantId, role, type, status, mfaVerified)
   * @returns JWT string assinado
   */
  issueAccess(payload: DashboardJwtPayload): string;

  /**
   * Emite access + refresh tokens.
   *
   * Fluxo:
   * 1. Gera access JWT com claims completos
   * 2. Gera refresh token opaco (UUID v4)
   * 3. Armazena refresh token no Redis com dados da sessão
   *
   * NÃO manipula Response — o controller usa TokenDeliveryService para entregar.
   *
   * @returns AuthResult com tokens e dados do usuário
   */
  issueTokens(
    user: AuthUser,
    ipAddress: string,
    userAgent: string,
    options?: { mfaVerified?: boolean },
  ): Promise<AuthResult>;

  /**
   * Reemite tokens usando refresh token existente.
   * Implementa rotação de refresh token com grace window.
   *
   * NÃO manipula Response — o controller usa TokenDeliveryService para entregar.
   *
   * @param refreshToken Token opaco (extraído pelo controller via TokenDeliveryService)
   * @returns AuthResult com novos tokens
   */
  reissueTokens(
    refreshToken: string,
    ipAddress: string,
    userAgent: string,
  ): Promise<AuthResult>;

  /**
   * Decodifica e verifica um JWT sem validar expiração.
   * Útil para extrair claims de tokens expirados (ex: blacklist).
   */
  decodeToken(token: string): DashboardJwtPayload | PlatformJwtPayload | null;

  /**
   * Emite um token temporário para fluxo de MFA.
   * JWT com type: 'mfa_challenge' e expiração de 5 minutos.
   *
   * @param userId ID do usuário/admin que precisa completar MFA
   * @param context Contexto de origem: 'dashboard' para usuários de tenant, 'platform' para admins
   * @returns JWT string do MFA temp token (inclui claim `context` no payload)
   */
  issueMfaTempToken(userId: string, context: 'dashboard' | 'platform'): string;

  /**
   * Verifica e extrai userId de um MFA temp token.
   * Valida no Redis que o token não foi usado.
   *
   * @throws AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID se inválido ou expirado
   */
  verifyMfaTempToken(token: string): Promise<string>;
}
```

### 6.4 SessionService

Gerenciamento de sessões de usuário com suporte a limites configuravies e estratégia FIFO.

```typescript
class SessionService {
  /**
   * Cria uma nova sessão para o usuário.
   *
   * Fluxo:
   * 1. Gera session hash a partir do refresh token
   * 2. Armazena detalhes da sessão no Redis (device, IP, timestamps)
   * 3. Adiciona hash ao SET de sessões do usuário
   * 4. Verifica limite de sessões
   * 5. Se excedeu, aplica estratégia de despejo (FIFO)
   * 6. Notifica via email (se configurado) sobre nova sessão
   * 7. Executa hook onNewSession
   *
   * @param userId ID do usuário
   * @param refreshToken Token opaco da sessão
   * @param ipAddress IP da requisição
   * @param userAgent User-Agent da requisição
   */
  createSession(
    userId: string,
    refreshToken: string,
    ipAddress: string,
    userAgent: string,
  ): Promise<void>;

  /**
   * Lista todas as sessões ativas do usuário.
   *
   * @returns Array de sessões com device, IP, timestamps e indicador de sessão atual
   */
  listSessions(
    userId: string,
    currentSessionHash?: string,
  ): Promise<SessionInfo[]>;

  /**
   * Revoga uma sessão específica.
   *
   * Fluxo:
   * 1. Verifica que sessionHash pertence ao usuário via SISMEMBER auth:sess:{userId}
   * 2. Se não pertence, lança SESSION_NOT_FOUND (previne BOLA/IDOR)
   * 3. Remove refresh token, sessão do SET e detalhes da sessão
   *
   * @throws AUTH_ERROR_CODES.SESSION_NOT_FOUND se sessão não encontrada
   */
  revokeSession(userId: string, sessionHash: string): Promise<void>;

  /**
   * Revoga todas as sessões exceto a atual.
   * Útil para "deslogar de todos os outros dispositivos".
   */
  revokeAllExceptCurrent(
    userId: string,
    currentSessionHash: string,
  ): Promise<void>;

  /**
   * Aplica limite de sessões usando estratégia FIFO.
   * Remove a sessão mais antiga quando o limite e excedido.
   *
   * A resolução do limite segue esta ordem:
   * 1. maxSessionsResolver(user) se fornecido — requer o objeto AuthUser completo
   * 2. defaultMaxSessions da configuração
   * 3. Padrão: 5
   *
   * @param userId ID do usuário
   * @param user Objeto AuthUser completo (necessário para `maxSessionsResolver`)
   *             Se `maxSessionsResolver` não está configurado, pode ser omitido (null)
   */
  enforceSessionLimit(userId: string, user: AuthUser | null): Promise<void>;
}
```

**Interface `SessionInfo`:**

```typescript
interface SessionInfo {
  sessionHash: string;
  device: string;
  ip: string;
  createdAt: Date;
  lastActivityAt: Date;
  isCurrent: boolean;
}
```

### 6.5 MfaService

Serviço de autenticação multi-fator baseado em TOTP (Time-based One-Time Password).

```typescript
class MfaService {
  /**
   * Inicia a configuração de MFA para um usuário.
   *
   * Fluxo:
   * 1. Verifica se MFA já está habilitado
   * 2. Gera secret TOTP aleatorio
   * 3. Criptografa secret com AES-256-GCM
   * 4. Gera recovery codes
   * 5. Armazena secret criptografado e recovery codes hasheados temporariamente
   * 6. Retorna secret, QR code URI e recovery codes em texto plano
   *
   * @throws AUTH_ERROR_CODES.MFA_ALREADY_ENABLED se já habilitado
   * @returns MfaSetupResult com secret, QR code e recovery codes
   */
  setup(userId: string): Promise<MfaSetupResult>;

  /**
   * Verifica o código TOTP e habilita MFA.
   *
   * Fluxo:
   * 1. Descriptografa o secret temporário
   * 2. Valida o código TOTP contra o secret
   * 3. Se válido, persiste MFA no banco (via updateMfa)
   * 4. Envia notificação por email
   * 5. Executa hook afterMfaEnabled
   *
   * @throws AUTH_ERROR_CODES.MFA_INVALID_CODE se código incorreto
   * @throws AUTH_ERROR_CODES.MFA_SETUP_REQUIRED se setup não foi feito
   */
  verifyAndEnable(userId: string, code: string): Promise<void>;

  /**
   * Processa desafio MFA durante login.
   *
   * Fluxo:
   * 1. Verifica mfaTempToken
   * 2. Verifica brute-force lockout via BruteForceService.isLockedOut(sha256(userId))
   * 3. Busca usuário e descriptografa secret
   * 4. Valida código TOTP ou recovery code
   * 5. Se inválido, registra falha via BruteForceService.recordFailure(sha256(userId))
   * 6. Após 5 falhas consecutivas, revoga o mfaTempToken do Redis (força re-autenticação)
   * 7. Se recovery code usado, remove-o da lista
   * 8. Reseta contador de brute-force via BruteForceService.resetFailures()
   * 9. Emite tokens (access JWT com mfaVerified: true + refresh)
   * 10. Cria sessão (se habilitado)
   *
   * NÃO manipula Response — o controller usa TokenDeliveryService para entregar.
   *
   * O método lê o claim `context` do `MfaTempPayload` para determinar o tipo de retorno:
   * - `context === 'dashboard'` → retorna `AuthResult` (tokens de usuário de tenant)
   * - `context === 'platform'`  → retorna `PlatformAuthResult` (tokens de admin de plataforma)
   *
   * @param mfaTempToken Token temporário emitido no login (contém `context` no payload)
   * @param code Código TOTP de 6 digitos ou recovery code
   * @param ipAddress IP da requisição
   * @param userAgent User-Agent da requisição
   * @throws AUTH_ERROR_CODES.MFA_INVALID_CODE / RECOVERY_CODE_INVALID
   */
  challenge(
    mfaTempToken: string,
    code: string,
    ipAddress: string,
    userAgent: string,
  ): Promise<AuthResult | PlatformAuthResult>;

  /**
   * Desabilita MFA para um usuário.
   *
   * Fluxo:
   * 1. Verifica código TOTP atual para confirmar identidade
   * 2. Remove secret e recovery codes do banco
   * 3. Envia notificação por email
   * 4. Executa hook afterMfaDisabled
   *
   * @throws AUTH_ERROR_CODES.MFA_NOT_ENABLED se não habilitado
   * @throws AUTH_ERROR_CODES.MFA_INVALID_CODE se código incorreto
   */
  disable(userId: string, code: string): Promise<void>;

  /**
   * Criptografa um secret TOTP com AES-256-GCM.
   * Usa a encryptionKey da configuração.
   *
   * IV: crypto.randomBytes(12) gerado fresh por operação (NUNCA reutilizar).
   * Formato: base64(iv) + ':' + base64(authTag) + ':' + base64(ciphertext)
   *
   * @returns String no formato "iv:authTag:ciphertext" (base64)
   */
  encryptSecret(secret: string): string;

  /**
   * Descriptografa um secret TOTP.
   * @returns Secret TOTP em texto plano
   */
  decryptSecret(encrypted: string): string;

  /**
   * Gera e faz hash dos recovery codes.
   * @returns { plainCodes: string[], hashedCodes: string[] }
   */
  hashRecoveryCodes(count: number): {
    plainCodes: string[];
    hashedCodes: string[];
  };

  /**
   * Verifica um recovery code contra a lista de hashes.
   * Usa comparação constant-time.
   * @returns Indice do code se válido, -1 se inválido
   */
  verifyRecoveryCode(code: string, hashedCodes: string[]): Promise<number>;
}

// Dependências injetadas pelo MfaService:
// - BYMAX_AUTH_OPTIONS (configuração do módulo)
// - IUserRepository (buscar usuário para desafio dashboard)
// - IPlatformUserRepository (buscar admin para desafio platform, quando platformAdmin.enabled)
// - AuthRedisService (armazenar/recuperar secrets temporários, marcar recovery codes usados)
// - TokenManagerService (emitir tokens após MFA completado)
// - SessionService (criar sessão após MFA, quando sessions.enabled)
// - BruteForceService (lockout por userId em caso de falhas consecutivas)
// - IEmailProvider (notificações de MFA habilitado/desabilitado)
// - IAuthHooks (afterMfaEnabled, afterMfaDisabled)
```

**Tipo `MfaSetupResult`:**

```typescript
interface MfaSetupResult {
  /** Secret TOTP em texto plano (exibir apenas uma vez ao usuário) */
  secret: string;

  /** URI para geração de QR code (otpauth://totp/...) */
  qrCodeUri: string;

  /** Recovery codes em texto plano (exibir apenas uma vez — usuário deve guardar) */
  recoveryCodes: string[];
}
```

### 6.6 PasswordResetService

Serviço de reset de senha com suporte a dois métodos: token (link por email) e OTP (código numérico).

```typescript
class PasswordResetService {
  /**
   * Inicia o processo de reset de senha.
   *
   * Fluxo:
   * 1. Busca usuário por email (NÃO revela se existe ou não)
   * 2. Se method = 'token':
   *    a. Gera token seguro (crypto.randomBytes)
   *    b. Armazena sha256(token) → userId no Redis
   *    c. Envia email com link contendo o token
   * 3. Se method = 'otp':
   *    a. Gera OTP numérico via OtpService
   *    b. Armazena no Redis
   *    c. Envia email com OTP
   * 4. Retorna sucesso (sempre, independente de usuário existir)
   *
   * Segurança: Nunca retorna erro se email não existe (previne enumeração).
   */
  initiateReset(email: string, tenantId: string): Promise<void>;

  /**
   * Reseta a senha usando token ou OTP.
   *
   * Fluxo (token):
   * 1. Busca userId via sha256(token) no Redis
   * 2. Faz hash da nova senha
   * 3. Atualiza senha via repositório
   * 4. Remove token do Redis
   * 5. Revoga todas as sessões do usuário
   * 6. Executa hook afterPasswordReset
   *
   * Fluxo (OTP):
   * 1. Verifica OTP via OtpService
   * 2. Mesmos passos 2-6 acima
   *
   * @throws AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID / EXPIRED
   * @throws AUTH_ERROR_CODES.OTP_INVALID / EXPIRED / MAX_ATTEMPTS
   */
  resetPassword(dto: ResetPasswordDto): Promise<void>;

  /**
   * Verifica um OTP e emite um token temporário de verificação.
   * Usado no fluxo de 2 etapas: primeiro verifica OTP, depois mostra form de nova senha.
   *
   * Fluxo:
   * 1. Valida OTP via OtpService.verify() (CONSOME o OTP)
   * 2. Gera token temporário de verificação (UUID)
   * 3. Armazena no Redis: auth:prv:{sha256(token)} → { email, tenantId }, TTL 5 minutos
   * 4. Retorna o token de verificação
   *
   * O resetPassword valida que o tenantId da requisição corresponde ao
   * tenantId armazenado no token, prevenindo reset cross-tenant.
   *
   * O endpoint resetPassword aceita este token em vez do OTP original,
   * eliminando a janela de race condition entre verificação e reset.
   *
   * @throws AUTH_ERROR_CODES.OTP_INVALID / EXPIRED / MAX_ATTEMPTS
   * @returns Token temporário de verificação (5 minutos de validade)
   */
  verifyOtp(email: string, otp: string, tenantId: string): Promise<{ verifiedToken: string }>;

  /**
   * Reenvia OTP de reset de senha.
   * Gera novo OTP, armazena no Redis e envia via IEmailProvider.
   * Segurança: Retorna sucesso mesmo se email não existe (previne enumeração).
   *
   * @param email Email do usuário
   * @param tenantId ID do tenant
   */
  resendOtp(email: string, tenantId: string): Promise<void>;
}
```

### 6.7 OtpService

Serviço genérico de geração e verificação de OTPs (One-Time Passwords).

```typescript
class OtpService {
  /**
   * Gera um OTP numérico criptograficamente seguro.
   *
   * Implementação OBRIGATÓRIA: usar `crypto.randomInt(0, 10 ** length)` (Node.js built-in).
   * NUNCA usar `Math.random()` — não é criptograficamente seguro e produz OTPs previsíveis.
   *
   * @param length Comprimento do OTP (padrão: 6). Máximo recomendado: 8
   * @returns String numerica com zeros à esquerda se necessário (ex: '048291' para length=6)
   */
  generate(length?: number): string;

  /**
   * Armazena um OTP no Redis.
   * @param purpose Propósito do OTP (ex: 'password_reset', 'email_verification')
   * @param identifier sha256(tenantId + ":" + email) — scopado por tenant
   * @param code Código OTP
   * @param ttlSeconds TTL em segundos
   */
  store(
    purpose: string,
    identifier: string,
    code: string,
    ttlSeconds: number,
  ): Promise<void>;

  /**
   * Verifica um OTP.
   *
   * Fluxo:
   * 1. Busca OTP no Redis por purpose + identifier (já contém hash de tenantId + email)
   * 2. Se não encontrado, lanca OTP_EXPIRED
   * 3. Verifica contador de tentativas
   * 4. Se excedeu máximo (5), lanca OTP_MAX_ATTEMPTS
   * 5. Compara código (constant-time)
   * 6. Se válido, remove do Redis
   * 7. Se inválido, incrementa tentativas
   *
   * @throws AUTH_ERROR_CODES.OTP_INVALID / OTP_EXPIRED / OTP_MAX_ATTEMPTS
   */
  verify(purpose: string, identifier: string, code: string): Promise<void>;

  /**
   * Incrementa o contador de tentativas falhadas de um OTP.
   * Chamado internamente por verify() em caso de falha.
   */
  incrementAttempts(purpose: string, identifier: string): Promise<void>;
}
```

### 6.8 BruteForceService

Proteção contra ataques de forca bruta usando contadores no Redis.

```typescript
class BruteForceService {
  /**
   * Verifica se um identificador está bloqueado.
   *
   * @param identifier sha256(tenantId + ":" + email) — scopado por tenant para evitar lockout cross-tenant
   * @returns true se o número de tentativas excedeu maxAttempts
   */
  isLockedOut(identifier: string): Promise<boolean>;

  /**
   * Registra uma tentativa falhada.
   * Incrementa o contador no Redis e define TTL = windowSeconds.
   *
   * @param identifier sha256(tenantId + ":" + email) — scopado por tenant para evitar lockout cross-tenant
   */
  recordFailure(identifier: string): Promise<void>;

  /**
   * Reseta o contador de tentativas falhadas.
   * Chamado após login bem-sucedido.
   *
   * @param identifier sha256(tenantId + ":" + email) — scopado por tenant para evitar lockout cross-tenant
   */
  resetFailures(identifier: string): Promise<void>;

  /**
   * Retorna o tempo restante de lockout em segundos.
   * Usa o comando Redis TTL na chave `lf`.
   * Retorna 0 se não está bloqueado.
   *
   * @param identifier sha256(tenantId + ":" + email)
   * @returns Segundos restantes de lockout
   */
  getRemainingLockoutSeconds(identifier: string): Promise<number>;
}
```

### 6.9 PlatformAuthService

Serviço de autenticação para administradores da plataforma (super-admins).

```typescript
class PlatformAuthService {
  /**
   * Autentica um admin da plataforma.
   *
   * Fluxo:
   * 1. Verifica brute-force lockout
   * 2. Busca admin por email via IPlatformUserRepository
   * 3. Compara senha
   * 4. Se MFA habilitado, emite mfaTempToken
   * 5. Se não, emite JWT de plataforma (type: 'platform')
   * 6. Atualiza lastLoginAt
   *
   * @throws AUTH_ERROR_CODES.INVALID_CREDENTIALS
   * @throws AUTH_ERROR_CODES.ACCOUNT_LOCKED
   * @throws AUTH_ERROR_CODES.ACCOUNT_BANNED / ACCOUNT_INACTIVE / ACCOUNT_SUSPENDED
   */
  login(
    dto: PlatformLoginDto,
    ipAddress: string,
    userAgent: string,
  ): Promise<PlatformAuthResult | MfaChallengeResult>;

  /**
   * Retorna dados do admin autenticado.
   */
  getMe(userId: string): Promise<AuthPlatformUser>;

  /**
   * Desloga o admin da plataforma.
   *
   * Fluxo:
   * 1. Adiciona access JWT na blacklist (Redis, TTL = tempo restante do JWT)
   * 2. Revoga refresh token no Redis (prefixo `prt`)
   * 3. Executa hook afterLogout
   *
   * @throws AUTH_ERROR_CODES.TOKEN_INVALID se token inválido
   */
  logout(accessToken: string, refreshToken: string): Promise<void>;

  /**
   * Renova tokens do admin da plataforma.
   *
   * Fluxo:
   * 1. Extrai refresh token (cookie ou body conforme tokenDelivery)
   * 2. Busca sessão no Redis via sha256(refreshToken) com prefixo `prt`
   * 3. Rotação de refresh token com grace window
   * 4. Retorna PlatformAuthResult com novos tokens
   *
   * @throws AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID
   */
  refresh(
    rawRefreshToken: string,
    ipAddress: string,
    userAgent: string,
  ): Promise<PlatformAuthResult>;

  /**
   * Revoga TODOS os refresh tokens ativos de um admin da plataforma.
   *
   * Deve ser chamado pela aplicação host ao:
   * - Excluir/desativar um admin da plataforma
   * - Forçar re-autenticação por motivos de segurança
   * - Detecção de comprometimento de conta
   *
   * Fluxo:
   * 1. Busca todos os tokens `prt` associados ao userId no Redis
   * 2. Revoga cada token individualmente
   * 3. Remove o SET de sessões da plataforma (`auth:prp:{userId}`)
   *
   * Nota: Não invalida access tokens ativos (JWT são stateless com TTL de 15min).
   * Para invalidação imediata do access token, adicione o `jti` à blacklist (`rv`).
   *
   * @param userId ID do admin da plataforma
   */
  revokeAllPlatformSessions(userId: string): Promise<void>;
}
```

**Tipos de retorno:**

```typescript
interface PlatformAuthResult {
  admin: AuthPlatformUser;
  accessToken: string;
  rawRefreshToken: string;
}
```

### 6.10 InvitationService

Sistema de convites para adicionar usuários a um tenant.

```typescript
class InvitationService {
  /**
   * Cria e envia um convite.
   *
   * Fluxo:
   * 1. Gera token seguro
   * 2. Valida que o inviter tem autorização para conceder o role solicitado
   *    (inviter.role deve ser igual ou superior ao role no hierarchy)
   * 3. Armazena no Redis: sha256(token) → { email, role, tenantId, inviterId }
   * 4. Envia email de convite via IEmailProvider.sendInvitation()
   *
   * Segurança: O tenantId é extraído do JWT do inviter pelo controller,
   * NÃO do body da requisição, prevenindo cross-tenant invitation injection.
   *
   * @param inviterId ID do usuário que está convidando
   * @param email Email do convidado
   * @param role Role que o convidado tera no tenant
   * @param tenantId ID do tenant
   * @throws AUTH_ERROR_CODES.INSUFFICIENT_ROLE se inviter não pode conceder o role
   */
  invite(
    inviterId: string,
    email: string,
    role: string,
    tenantId: string,
  ): Promise<void>;

  /**
   * Aceita um convite e cria o usuário.
   *
   * Fluxo:
   * 1. Busca convite no Redis via sha256(token)
   * 2. Se não encontrado, lanca INVALID_INVITATION_TOKEN
   * 3. Verifica se email já existe no tenant
   * 4. Cria usuário com role e tenant do convite
   * 5. Remove convite do Redis
   * 6. Emite tokens (access + refresh)
   * 7. Executa hook afterInvitationAccepted
   *
   * NÃO manipula Response — o controller usa TokenDeliveryService para entregar.
   *
   * @throws AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN
   * @throws AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS
   */
  acceptInvitation(
    dto: AcceptInvitationDto,
    ipAddress: string,
    userAgent: string,
  ): Promise<AuthResult>;
}
```

### 6.11 TokenDeliveryService

Serviço responsável por entregar tokens ao cliente conforme o `tokenDelivery` configurado. Encapsula toda a lógica de cookies e body response — controllers e guards delegam para ele sem conhecer o modo ativo.

```typescript
class TokenDeliveryService {
  /**
   * Entrega os tokens de autenticação ao cliente.
   *
   * Comportamento por modo:
   * - 'cookie': seta cookies HttpOnly no response, retorna apenas `{ user }`
   * - 'bearer': não seta cookies, retorna `{ user, accessToken, refreshToken }`
   * - 'both': seta cookies E retorna tokens no body
   *
   * @param res Response do Express
   * @param req Request do Express (para resolver domínios de cookie)
   * @param authResult Resultado da autenticação (tokens + user/admin)
   * @returns Objeto para enviar no body do response
   *
   * Aceita tanto `AuthResult` (dashboard) quanto `PlatformAuthResult` (plataforma)
   * via tipo genérico `{ accessToken, rawRefreshToken, [user|admin] }`.
   */
  deliverAuthResponse(
    res: Response,
    req: Request,
    authResult: AuthResult | PlatformAuthResult,
  ): Record<string, unknown>;

  /**
   * Entrega novos tokens após refresh.
   *
   * Comportamento por modo:
   * - 'cookie': seta novos cookies, limpa antigos, retorna `{}`
   * - 'bearer': retorna `{ accessToken, refreshToken }`
   * - 'both': seta cookies E retorna tokens
   *
   * Aceita tanto `AuthResult` (dashboard) quanto `PlatformAuthResult` (plataforma).
   */
  deliverRefreshResponse(
    res: Response,
    req: Request,
    authResult: AuthResult | PlatformAuthResult,
  ): Record<string, unknown>;

  /**
   * Extrai o access token da requisição.
   *
   * Comportamento por modo:
   * - 'cookie': lê de `req.cookies[accessTokenName]`
   * - 'bearer': lê de `Authorization: Bearer <token>`
   * - 'both': tenta cookie primeiro, depois header
   *
   * @returns JWT string ou null se não encontrado
   */
  extractAccessToken(req: Request): string | null;

  /**
   * Extrai o refresh token da requisição.
   *
   * Comportamento por modo:
   * - 'cookie': lê de `req.cookies[refreshTokenName]`
   * - 'bearer': lê de `req.body.refreshToken`
   * - 'both': tenta cookie primeiro, depois body
   *
   * @returns Refresh token string ou null se não encontrado
   */
  extractRefreshToken(req: Request): string | null;

  /**
   * Limpa a sessão de autenticação do cliente.
   *
   * Comportamento por modo:
   * - 'cookie': limpa todos os cookies de autenticação
   * - 'bearer': no-op (cliente é responsável por descartar tokens)
   * - 'both': limpa cookies (cliente descarta tokens do body)
   */
  clearAuthSession(res: Response, req: Request): void;

  /**
   * Seta o cookie de access token (uso interno).
   * Ignorado quando `tokenDelivery: 'bearer'`.
   */
  private setAccessCookie(res: Response, token: string): void;

  /**
   * Seta o cookie de refresh token (uso interno).
   * Ignorado quando `tokenDelivery: 'bearer'`.
   */
  private setRefreshCookie(res: Response, token: string): void;

  /**
   * Resolve todos os domínios onde cookies devem ser setados.
   * Usa resolveDomains da configuração ou extractDomain como fallback.
   */
  resolveCookieDomains(req: Request): string[];

  /**
   * Extrai o domínio base a partir do hostname da requisição.
   * Ex: 'api.example.com' → '.example.com'
   */
  extractDomain(hostname: string): string;
}
```

---

## 7. Controllers

### 7.1 AuthController

**Prefixo:** `/{routePrefix}` (padrão: `/auth`)

| Método | Rota                   | Auth   | Guards         | Body             | Descrição                              |
| ------ | ---------------------- | ------ | -------------- | ---------------- | -------------------------------------- |
| `POST` | `/register`            | Public | —              | `RegisterDto`    | Registra um novo usuário               |
| `POST` | `/login`               | Public | —              | `LoginDto`       | Autentica usuário com email/senha      |
| `POST` | `/logout`              | JWT    | `JwtAuthGuard` | —                | Desloga usuário, revoga tokens (cookie ou header)          |
| `POST` | `/refresh`             | Cookie/Bearer | —       | `{ refreshToken? }` | Renova tokens; aceita cookie ou body conforme `tokenDelivery` |
| `GET`  | `/me`                  | JWT    | `JwtAuthGuard` | —                | Retorna dados do usuário autenticado   |
| `POST` | `/verify-email`        | Public | —              | `{ email, otp, tenantId }` | Verifica email com OTP                 |
| `POST` | `/resend-verification` | Public | —              | `{ email, tenantId }`      | Reenvia OTP de verificação             |

**DTOs:**

```typescript
// register.dto.ts
export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  @MaxLength(72) // bcrypt trunca silenciosamente acima de 72 bytes
  password: string;

  @IsString()
  @MinLength(2)
  name: string;

  @IsString()
  tenantId: string;
}

// login.dto.ts
export class LoginDto {
  @IsEmail()
  email: string;

  @IsString()
  @MaxLength(72) // bcrypt trunca silenciosamente acima de 72 bytes
  password: string;

  @IsString()
  tenantId: string;
}
```

### 7.2 MfaController

**Prefixo:** `/{routePrefix}/mfa` (padrão: `/auth/mfa`)

| Método | Rota         | Auth              | Guards         | Body              | Descrição                                |
| ------ | ------------ | ----------------- | -------------- | ----------------- | ---------------------------------------- |
| `POST` | `/setup`     | JWT               | `JwtAuthGuard` | —                 | Inicia configuração MFA, retorna QR code |
| `POST` | `/verify`    | JWT               | `JwtAuthGuard` | `MfaVerifyDto`    | Verifica código e habilita MFA           |
| `POST` | `/challenge` | Public + mfaToken | —              | `MfaChallengeDto` | Completa desafio MFA durante login       |
| `POST` | `/disable`   | JWT               | `JwtAuthGuard` | `MfaDisableDto`   | Desabilita MFA                           |

**DTOs:**

```typescript
// mfa-verify.dto.ts
export class MfaVerifyDto {
  @IsString()
  @Length(6, 6)
  code: string;
}

// mfa-challenge.dto.ts
export class MfaChallengeDto {
  @IsString()
  mfaTempToken: string;

  @IsString()
  @MaxLength(128) // TOTP tem 6 chars; recovery codes têm ~32 chars; limite previne bcrypt bombing
  code: string; // TOTP de 6 digitos ou recovery code
}

// mfa-disable.dto.ts
export class MfaDisableDto {
  @IsString()
  @Length(6, 6)
  code: string;
}
```

### 7.3 PasswordResetController

**Prefixo:** `/{routePrefix}/password` (padrão: `/auth/password`)

| Método | Rota               | Auth   | Guards | Body                | Descrição                     |
| ------ | ------------------ | ------ | ------ | ------------------- | ----------------------------- |
| `POST` | `/forgot-password` | Public | —      | `ForgotPasswordDto` | Inicia reset de senha         |
| `POST` | `/reset-password`  | Public | —      | `ResetPasswordDto`  | Reseta senha com token ou OTP |
| `POST` | `/verify-otp`      | Public | —      | `{ email, otp, tenantId }`    | Verifica OTP e retorna token temporário de verificação     |
| `POST` | `/resend-otp`      | Public | —      | `{ email, tenantId }`         | Reenvia OTP de reset          |

**DTOs:**

```typescript
// forgot-password.dto.ts
export class ForgotPasswordDto {
  @IsEmail()
  email: string;

  @IsString()
  tenantId: string;
}

// reset-password.dto.ts
export class ResetPasswordDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  @MaxLength(72) // bcrypt trunca silenciosamente acima de 72 bytes
  newPassword: string;

  @IsOptional()
  @IsString()
  token?: string; // Para method = 'token'

  @IsOptional()
  @IsString()
  otp?: string; // Para method = 'otp'

  @IsOptional()
  @IsString()
  verifiedToken?: string; // Para fluxo de 2 etapas (OTP → verifiedToken → reset)

  @IsString()
  tenantId: string;
}
```

### 7.4 SessionController

**Prefixo:** `/{routePrefix}/sessions` (padrão: `/auth/sessions`)

| Método   | Rota   | Auth | Guards         | Body | Descrição                     |
| -------- | ------ | ---- | -------------- | ---- | ----------------------------- |
| `GET`    | `/`    | JWT  | `JwtAuthGuard` | —    | Lista todas as sessões ativas |
| `DELETE` | `/:id` | JWT  | `JwtAuthGuard` | —    | Revoga uma sessão específica  |
| `DELETE` | `/all` | JWT  | `JwtAuthGuard` | —    | Revoga todas exceto a atual   |

**Respostas:**

```typescript
// GET /auth/sessions
// Resposta: 200 OK
{
  "sessions": [
    {
      "sessionHash": "abc123...",
      "device": "Chrome 120 on macOS",
      "ip": "189.40.xx.xx",
      "createdAt": "2026-04-01T10:30:00Z",
      "lastActivityAt": "2026-04-09T14:22:00Z",
      "isCurrent": true
    },
    {
      "sessionHash": "def456...",
      "device": "Safari on iPhone",
      "ip": "201.17.xx.xx",
      "createdAt": "2026-04-05T08:15:00Z",
      "lastActivityAt": "2026-04-08T19:45:00Z",
      "isCurrent": false
    }
  ]
}
```

### 7.5 PlatformAuthController

**Prefixo:** `/{routePrefix}/platform` (padrão: `/auth/platform`)

| Método   | Rota            | Auth              | Guards             | Body                 | Descrição                                                  |
| -------- | --------------- | ----------------- | ------------------ | -------------------- | ---------------------------------------------------------- |
| `POST`   | `/login`        | Public            | —                  | `PlatformLoginDto`   | Autentica admin da plataforma                              |
| `POST`   | `/mfa/challenge`| Public + mfaToken | —                  | `MfaChallengeDto`    | Completa desafio MFA para admins de plataforma             |
| `GET`    | `/me`           | Platform JWT      | `JwtPlatformGuard` | —                    | Retorna dados do admin                                     |
| `POST`   | `/logout`       | Platform JWT      | `JwtPlatformGuard` | —                    | Desloga admin, revoga tokens                               |
| `POST`   | `/refresh`      | Cookie/Bearer     | —                  | `{ refreshToken? }`  | Renova tokens do admin da plataforma                       |
| `DELETE` | `/sessions`     | Platform JWT      | `JwtPlatformGuard` | —                    | Revoga todas as sessões do admin (útil em casos de comprometimento) |

> **Fluxo MFA platform:** `POST /auth/platform/login` → se MFA habilitado, retorna `{ mfaRequired: true, mfaTempToken }` → `POST /auth/platform/mfa/challenge` com `MfaChallengeDto` → `MfaService.challenge()` lê `context: 'platform'` do `MfaTempPayload` → retorna `PlatformAuthResult` com tokens de plataforma.

**DTO:**

```typescript
// platform-login.dto.ts
export class PlatformLoginDto {
  @IsEmail()
  email: string;

  @IsString()
  @MaxLength(72) // bcrypt trunca silenciosamente acima de 72 bytes
  password: string;
}
```

### 7.6 InvitationController

**Prefixo:** `/{routePrefix}/invitations` (padrão: `/auth/invitations`)

| Método | Rota      | Auth           | Guards                       | Body                    | Descrição                                            |
| ------ | --------- | -------------- | ---------------------------- | ----------------------- | ---------------------------------------------------- |
| `POST` | `/`       | JWT            | `JwtAuthGuard`, `RolesGuard` | `CreateInvitationDto`   | Cria e envia convite (tenantId extraído do JWT) (requer role >= role concedido) |
| `POST` | `/accept` | Public + token | —                            | `AcceptInvitationDto`   | Aceita convite e cria conta                          |

**DTO:**

```typescript
// accept-invitation.dto.ts
export class AcceptInvitationDto {
  @IsString()
  token: string;

  @IsString()
  @MinLength(2)
  name: string;

  @IsString()
  @MinLength(8)
  @MaxLength(72) // bcrypt trunca silenciosamente acima de 72 bytes
  password: string;
}

// create-invitation.dto.ts
// Nota: tenantId NÃO está no DTO — é extraído automaticamente do JWT do inviter
// para prevenir cross-tenant invitation injection.
export class CreateInvitationDto {
  @IsEmail()
  email: string;

  @IsString()
  // Validado dinamicamente contra roles.hierarchy na inicialização do módulo
  // Rejeita roles que não existem na hierarquia configurada
  role: string;
}
```

---

## 8. Guards e Decorators

### 8.1 Guards

| Guard                | Descrição                                                                                                                                                                                    | Aplicação                                                  |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `JwtAuthGuard`       | Valida JWT de dashboard/tenant no cookie ou header `Authorization: Bearer`. Verifica `payload.type === 'dashboard'` — rejeita tokens `platform` e `mfa_challenge` com `auth.token_invalid`. Extrai payload e popula `request.user`. Respeita o decorator `@Public()` para pular validação. | Guard global ou por rota para endpoints autenticados       |
| `JwtPlatformGuard`   | Valida JWT de plataforma. Verifica `payload.type === 'platform'` — rejeita tokens `dashboard` com `auth.platform_auth_required`. Compartilha `jwt.secret` com `JwtAuthGuard` (isolamento via claim `type`, não via chave). | Endpoints de admin da plataforma                           |
| `RolesGuard`         | Verifica se o role do usuário satisfaz a hierarquia definida. Usa metadata setado por `@Roles()`. Um role pai herda todos os roles filhos.                                                   | Endpoints com restrição de role                            |
| `PlatformRolesGuard` | Mesmo que `RolesGuard` mas para a hierarquia de plataforma. Usa metadata setado por `@PlatformRoles()`.                                                                                      | Endpoints de admin com restrição de role                   |
| `UserStatusGuard`    | Verifica se o status do usuário não está na lista de `blockedStatuses`. Consulta cache Redis (TTL configurável) antes de ir ao banco. Se status está bloqueado, rejeita com erro específico. | Guard global, aplicado automaticamente após `JwtAuthGuard` |
| `MfaRequiredGuard`   | Verifica se o claim `mfaVerified` e `true` no JWT. Se o usuário tem MFA habilitado mas o JWT não tem `mfaVerified: true`, rejeita com `auth.mfa_required`. Respeita `@SkipMfa()`.            | Endpoints sensíveis que exigem MFA completado              |
| `WsJwtGuard`         | Guard para conexões WebSocket. Extrai JWT do handshake via header `Authorization`. **Não usa query param** (tokens em query params são logados em plaintext por proxies/CDNs). Valida e popula `client.data.user`. | Gateways WebSocket                                         |
| `SelfOrAdminGuard`   | Permite acesso se o usuário está acessando seus próprios recursos (`:userId` == JWT sub) ou se tem role de admin na hierarquia. A comparação `params.userId === user.sub` é a proteção primária contra IDOR — o `ParseUUIDPipe` é uma defesa em profundidade para aplicações que usam UUIDs. Se a aplicação host usa IDs de outro formato (numérico, slug, etc.), substituir `ParseUUIDPipe` pela validação apropriada ao formato. | Endpoints como `GET /users/:userId`                        |
| `OptionalAuthGuard`  | Tenta autenticar via JWT, mas não falha se token ausente. Popula `request.user` se presente, ou null se ausente.                                                                             | Endpoints públicos que mostram conteúdo extra para logados |

### 8.2 Detalhamento do RolesGuard com hierarquia

O `RolesGuard` implementa verificação hierarquica de roles:

```typescript
// Configuração de hierarquia
const hierarchy = {
  OWNER: ['ADMIN', 'MEMBER', 'VIEWER'],
  ADMIN: ['MEMBER', 'VIEWER'],
  MEMBER: ['VIEWER'],
  VIEWER: [],
};

// Lógica de verificação
function hasRole(userRole: string, requiredRole: string): boolean {
  if (userRole === requiredRole) return true;
  const inherited = hierarchy[userRole] || [];
  return inherited.includes(requiredRole);
}

// Exemplo de uso
@Roles('ADMIN') // OWNER e ADMIN passam; MEMBER e VIEWER não
@Get('reports')
getReports() { ... }
```

### 8.3 Detalhamento do UserStatusGuard

```typescript
// Fluxo do UserStatusGuard
async canActivate(context: ExecutionContext): Promise<boolean> {
  const user = context.switchToHttp().getRequest().user;
  if (!user) return true; // Rota publica

  // 1. Busca status no cache Redis
  let status = await this.redis.get(`auth:us:${user.sub}`);

  // 2. Se não encontrou, busca no banco e cacheia
  if (!status) {
    const dbUser = await this.userRepo.findById(user.sub);
    status = dbUser?.status ?? 'UNKNOWN';
    await this.redis.set(
      `auth:us:${user.sub}`,
      status,
      'EX',
      this.options.userStatusCacheTtlSeconds,
    );
  }

  // 3. Verifica contra lista de bloqueados
  if (this.options.blockedStatuses.includes(status)) {
    const errorMap: Record<string, string> = {
      BANNED: AUTH_ERROR_CODES.ACCOUNT_BANNED,
      INACTIVE: AUTH_ERROR_CODES.ACCOUNT_INACTIVE,
      SUSPENDED: AUTH_ERROR_CODES.ACCOUNT_SUSPENDED,
    };
    throw new AuthException(
      errorMap[status] || AUTH_ERROR_CODES.ACCOUNT_INACTIVE,
      HttpStatus.FORBIDDEN,
    );
  }

  return true;
}
```

### 8.4 Decorators

| Decorator                  | Aplicação           | Descrição                                                                                                                       |
| -------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `@CurrentUser()`           | Parâmetro de método | Extrai o usuário autenticado do `request.user`. Pode receber propriedade específica: `@CurrentUser('sub')` retorna apenas o ID. |
| `@Roles(...roles)`         | Método ou classe    | Define quais roles podem acessar o endpoint. Usado em conjunto com `RolesGuard`.                                                |
| `@PlatformRoles(...roles)` | Método ou classe    | Define quais roles de plataforma podem acessar o endpoint. Usado com `PlatformRolesGuard`.                                      |
| `@Public()`                | Método ou classe    | Marca endpoint como público, fazendo `JwtAuthGuard` pular autenticação.                                                         |
| `@SkipMfa()`               | Método ou classe    | Permite acesso mesmo sem MFA verificado. Útil para endpoints que precisam de JWT mas não são sensíveis (ex: setup de MFA).      |

### 8.5 Exemplos de uso

```typescript
// Controller com guards globais e decorators
@Controller('users')
@UseGuards(JwtAuthGuard, UserStatusGuard, RolesGuard)
export class UsersController {

  // Qualquer usuário autenticado
  @Get('me')
  getMe(@CurrentUser() user: DashboardJwtPayload) {
    return this.userService.findById(user.sub);
  }

  // Apenas ADMIN ou superior (OWNER)
  @Roles('ADMIN')
  @Get()
  listUsers(@CurrentUser('tenantId') tenantId: string) {
    return this.userService.findByTenant(tenantId);
  }

  // Acesso próprio ou admin
  @UseGuards(SelfOrAdminGuard)
  @Get(':userId')
  getUser(@Param('userId') userId: string) {
    return this.userService.findById(userId);
  }

  // Endpoint público (ignora JwtAuthGuard)
  @Public()
  @Get('public-profiles')
  getPublicProfiles() { ... }

  // Requer MFA verificado para ações sensíveis
  @UseGuards(MfaRequiredGuard)
  @Roles('OWNER')
  @Delete(':userId')
  deleteUser(@Param('userId') userId: string) { ... }
}

// Platform admin controller
@Controller('admin/tenants')
@UseGuards(JwtPlatformGuard, PlatformRolesGuard)
export class AdminTenantsController {

  @PlatformRoles('ADMIN')
  @Get()
  listTenants() { ... }

  @PlatformRoles('SUPER_ADMIN')
  @Delete(':tenantId')
  deleteTenant() { ... }
}
```

---

## 9. Sistema de Hooks

### 9.1 Interface `IAuthHooks`

Os hooks permitem que a aplicação host execute lógica personalizada em pontos específicos do ciclo de vida da autenticação. Todos os hooks são **opcionais** — a implementação padrão (`NoOpAuthHooks`) não faz nada.

```typescript
export interface IAuthHooks {
  /**
   * Executado ANTES do registro de um novo usuário.
   * Permite:
   * - Modificar os dados de registro (ex: normalizar email, definir role padrão)
   * - Rejeitar o registro (retornando { allowed: false, reason: '...' })
   * - Adicionar lógica de negócio (ex: verificar limite de usuários no plano)
   *
   * @param context Dados da requisição e do registro
   * @returns Resultado indicando se o registro e permitido
   */
  beforeRegister?(
    context: HookContext & {
      dto: { email: string; name: string; tenantId: string };
    },
  ): Promise<BeforeRegisterResult>;

  /**
   * Executado ANTES do login de um usuário.
   * Permite:
   * - Rejeitar o login com base em regras de negócio (ex: IP geofencing, device trust)
   * - Aplicar políticas de segurança customizadas (ex: bloquear login fora do horário comercial)
   * - Registrar tentativas de login em audit log
   *
   * Para rejeitar o login, lance uma exceção (ex: throw new ForbiddenException()).
   *
   * @param dto Dados de login (email, password, tenantId)
   * @param context Dados da requisição (IP, user-agent, etc.)
   */
  beforeLogin?(dto: LoginDto, context: HookContext): Promise<void>;

  /**
   * Executado APÓS o registro bem-sucedido de um usuário.
   * Permite:
   * - Criar recursos iniciais para o usuário
   * - Enviar notificações personalizadas
   * - Registrar analytics
   *
   * @param user Usuário recem-criado
   * @param context Dados da requisição
   */
  afterRegister?(user: AuthUser, context: HookContext): Promise<void>;

  /**
   * Executado APÓS login bem-sucedido (incluindo após MFA, se aplicável).
   * Permite:
   * - Registrar login em audit log
   * - Atualizar metricas
   * - Executar verificações adicionais
   */
  afterLogin?(user: AuthUser, context: HookContext): Promise<void>;

  /**
   * Executado APÓS logout.
   * Permite:
   * - Limpar cache específico do usuário
   * - Registrar em audit log
   */
  afterLogout?(userId: string, context: HookContext): Promise<void>;

  /**
   * Executado APÓS reset de senha bem-sucedido.
   * Permite:
   * - Enviar notificação de confirmação
   * - Registrar em audit log
   */
  afterPasswordReset?(userId: string, context: HookContext): Promise<void>;

  /**
   * Executado APÓS verificação de email bem-sucedida.
   * Permite:
   * - Ativar funcionalidades bloqueadas por verificação
   * - Enviar email de boas-vindas
   */
  afterEmailVerified?(userId: string, context: HookContext): Promise<void>;

  /**
   * Executado APÓS MFA ser habilitado com sucesso.
   * Permite:
   * - Registrar em audit log
   * - Conceder beneficios por usar MFA
   */
  afterMfaEnabled?(userId: string, context: HookContext): Promise<void>;

  /**
   * Executado APÓS MFA ser desabilitado.
   * Permite:
   * - Registrar em audit log
   * - Aplicar restrições de segurança
   */
  afterMfaDisabled?(userId: string, context: HookContext): Promise<void>;

  /**
   * Executado APÓS um convite ser aceito e o usuário criado.
   * Permite:
   * - Notificar o convidador
   * - Configurar permissões iniciais
   */
  afterInvitationAccepted?(
    user: AuthUser,
    context: HookContext & {
      inviterId: string;
      tenantId: string;
    },
  ): Promise<void>;

  /**
   * Executado quando uma nova sessão e criada.
   * Permite:
   * - Alertar sobre login de novo dispositivo
   * - Registrar em audit log
   */
  onNewSession?(
    userId: string,
    sessionInfo: {
      device: string;
      ip: string;
      sessionHash: string;
    },
    context: HookContext,
  ): Promise<void>;

  /**
   * Executado quando um usuário faz login via OAuth.
   * Permite:
   * - Sincronizar dados do perfil OAuth
   * - Definir role/status com base no provider
   * - Decidir se vincula a conta existente
   *
   * @returns Instruções para o fluxo de OAuth
   */
  onOAuthLogin?(
    profile: OAuthProfile,
    existingUser: AuthUser | null,
    context: HookContext,
  ): Promise<OAuthLoginResult>;
}
```

### 9.2 Interfaces auxiliares

```typescript
/**
 * Contexto passado para todos os hooks.
 * Contém informações da requisição HTTP.
 */
export interface HookContext {
  /** Endereco IP da requisição */
  ip: string;

  /** User-Agent da requisição */
  userAgent: string;

  /** Headers da requisição (sanitizados) */
  headers: Record<string, string>;

  /** Timestamp da operação */
  timestamp: Date;
}
```

> **Sanitização de headers:** O pacote remove automaticamente os seguintes headers antes de passar ao `HookContext`: `authorization`, `cookie`, `x-api-key`, e qualquer header customizado que contenha tokens. Apenas headers seguros para logging são repassados (ex: `user-agent`, `accept-language`, `x-forwarded-for`, `x-request-id`).

```typescript
/**
 * Resultado do hook beforeRegister.
 */
export interface BeforeRegisterResult {
  /** Se o registro e permitido */
  allowed: boolean;

  /** Motivo da rejeição (se allowed = false) */
  reason?: string;

  /** Dados de registro modificados (merge parcial) */
  modifiedData?: Partial<{
    role: string;
    status: string;
    emailVerified: boolean;
  }>;
}

/**
 * Resultado do hook onOAuthLogin.
 */
export interface OAuthLoginResult {
  /**
   * Ação a tomar:
   * - 'create': Cria novo usuário com dados do OAuth
   * - 'link': Vincula OAuth a usuário existente
   * - 'reject': Rejeita o login OAuth
   */
  action: "create" | "link" | "reject";

  /** Motivo da rejeição (se action = 'reject') */
  rejectReason?: string;

  /** Dados extras para criação (se action = 'create') */
  createData?: Partial<{
    role: string;
    status: string;
    tenantId: string;
  }>;
}

/**
 * Perfil retornado pelo provider OAuth.
 */
export interface OAuthProfile {
  provider: string;
  providerId: string;
  email: string;
  name: string;
  picture?: string;
  raw: Record<string, unknown>;
}
```

### 9.3 Implementação padrão (NoOp)

```typescript
/**
 * Implementação padrão que não faz nada.
 * Usada quando a aplicação host não fornece BYMAX_AUTH_HOOKS.
 */
export class NoOpAuthHooks implements IAuthHooks {
  async beforeRegister(): Promise<BeforeRegisterResult> {
    return { allowed: true };
  }

  async beforeLogin(_dto: LoginDto, _context: HookContext): Promise<void> {}
  async afterRegister(_user: AuthUser, _context: HookContext): Promise<void> {}
  async afterLogin(_user: AuthUser, _context: HookContext): Promise<void> {}
  async afterLogout(_userId: string, _context: HookContext): Promise<void> {}
  async afterPasswordReset(
    _userId: string,
    _context: HookContext,
  ): Promise<void> {}
  async afterEmailVerified(
    _userId: string,
    _context: HookContext,
  ): Promise<void> {}
  async afterMfaEnabled(
    _userId: string,
    _context: HookContext,
  ): Promise<void> {}
  async afterMfaDisabled(
    _userId: string,
    _context: HookContext,
  ): Promise<void> {}
  async afterInvitationAccepted(
    _user: AuthUser,
    _context: HookContext & { inviterId: string; tenantId: string },
  ): Promise<void> {}
  async onNewSession(
    _userId: string,
    _sessionInfo: any,
    _context: HookContext,
  ): Promise<void> {}

  async onOAuthLogin(
    profile: OAuthProfile,
    existingUser: AuthUser | null,
    _context: HookContext,
  ): Promise<OAuthLoginResult> {
    if (existingUser) {
      // SEGURANÇA: só faz link se o email do perfil OAuth bate com o email da conta existente.
      // Sem essa verificação, um atacante poderia vincular uma conta OAuth arbitrária a
      // uma conta existente se o provedor OAuth não validar emails adequadamente.
      if (existingUser.email !== profile.email) {
        return { action: "reject", reason: "OAuth email does not match existing account email" };
      }
      return { action: "link" };
    }
    return { action: "create" };
  }
}
```

### 9.4 Comportamento de erro em hooks

Os hooks devem ser **resilientes** — um erro em um hook não deve impedir a operação principal. O comportamento padrão e:

- **Hooks "before" (beforeRegister, beforeLogin):** Erros são **propagados** (throw), pois afetam a decisao de prosseguir
- **Hooks "after" (afterLogin, afterRegister, etc.):** Erros são **logados** mas não propagados, para não afetar a resposta ao usuário

A aplicação host pode personalizar esse comportamento se necessário.

### 9.5 Exemplo de implementação

```typescript
// app-auth.hooks.ts
import { Injectable, Logger } from "@nestjs/common";
import {
  IAuthHooks,
  HookContext,
  BeforeRegisterResult,
  OAuthLoginResult,
  OAuthProfile,
  AuthUser,
} from "@bymax-one/nest-auth";
import { PrismaService } from "../prisma/prisma.service";
import { AnalyticsService } from "../analytics/analytics.service";

@Injectable()
export class AppAuthHooks implements IAuthHooks {
  private readonly logger = new Logger(AppAuthHooks.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly analytics: AnalyticsService,
  ) {}

  async beforeRegister(
    context: HookContext & {
      dto: { email: string; name: string; tenantId: string };
    },
  ): Promise<BeforeRegisterResult> {
    // Verifica limite de usuários no plano do tenant
    const tenant = await this.prisma.tenant.findUnique({
      where: { id: context.dto.tenantId },
      include: { plan: true, _count: { select: { users: true } } },
    });

    if (!tenant) {
      return { allowed: false, reason: "Tenant não encontrado" };
    }

    if (tenant._count.users >= tenant.plan.maxUsers) {
      return {
        allowed: false,
        reason: "Limite de usuários atingido no plano atual",
      };
    }

    // Define role padrão como MEMBER
    return {
      allowed: true,
      modifiedData: { role: "MEMBER", status: "ACTIVE" },
    };
  }

  async afterRegister(user: AuthUser, context: HookContext): Promise<void> {
    this.analytics.track("user.registered", {
      userId: user.id,
      tenantId: user.tenantId,
      ip: context.ip,
    });
  }

  async afterLogin(user: AuthUser, context: HookContext): Promise<void> {
    this.analytics.track("user.logged_in", {
      userId: user.id,
      ip: context.ip,
      userAgent: context.userAgent,
    });
  }

  async onOAuthLogin(
    profile: OAuthProfile,
    existingUser: AuthUser | null,
  ): Promise<OAuthLoginResult> {
    if (existingUser) {
      // Verifica que o email do OAuth corresponde ao email da conta existente
      if (existingUser.email !== profile.email) {
        return { action: "reject", reason: "OAuth email does not match existing account" };
      }
      return { action: "link" };
    }

    // Auto-criar usuário OAuth com tenant padrão
    return {
      action: "create",
      createData: {
        role: "MEMBER",
        status: "ACTIVE",
        tenantId: "default-tenant-id",
      },
    };
  }
}
```

---

## 10. Interface de Email Provider

### 10.1 Princípios de design

O `IEmailProvider` segue os seguintes princípios:

1. **Abstrato**: Define **o que** enviar, não **como** renderizar
2. **Template-agnostic**: A aplicação host decide templates, layouts e estilos
3. **Assíncrono**: Todos os métodos retornam `Promise<void>`
4. **Falha silenciosa**: Erros de envio são logados mas não propagados para o usuário (exceto em registro/verificação)

### 10.2 Métodos do IEmailProvider

Veja a interface completa na seção [5.5](#55-interface-iemailprovider).

### 10.3 NoOpEmailProvider para desenvolvimento

Para facilitar desenvolvimento local, o pacote fornece uma implementação que apenas loga os emails no console:

```typescript
/**
 * Email provider que não envia emails.
 * Útil para desenvolvimento local e testes.
 * Loga o conteúdo no console para depuração.
 */
export class NoOpEmailProvider implements IEmailProvider {
  private readonly logger = new Logger(NoOpEmailProvider.name);

  async sendPasswordResetToken(
    email: string,
    token: string,
    name: string,
    locale?: string,
  ): Promise<void> {
    this.logger.debug(
      `[Password Reset Token] To: ${email}, Name: ${name}, Token: ${token.substring(0, 8)}..., Locale: ${locale}`,
    );
  }

  async sendPasswordResetOtp(
    email: string,
    otp: string,
    name: string,
    locale?: string,
  ): Promise<void> {
    this.logger.debug(
      `[Password Reset OTP] To: ${email}, Name: ${name}, OTP: [REDACTED], Locale: ${locale}`,
    );
  }

  async sendEmailVerificationOtp(
    email: string,
    otp: string,
    name: string,
    locale?: string,
  ): Promise<void> {
    this.logger.debug(
      `[Email Verification OTP] To: ${email}, Name: ${name}, OTP: [REDACTED], Locale: ${locale}`,
    );
  }

  async sendMfaEnabledNotification(
    email: string,
    name: string,
    locale?: string,
  ): Promise<void> {
    this.logger.debug(
      `[MFA Enabled] To: ${email}, Name: ${name}, Locale: ${locale}`,
    );
  }

  async sendMfaDisabledNotification(
    email: string,
    name: string,
    locale?: string,
  ): Promise<void> {
    this.logger.debug(
      `[MFA Disabled] To: ${email}, Name: ${name}, Locale: ${locale}`,
    );
  }

  async sendNewSessionAlert(
    email: string,
    name: string,
    sessionInfo: { device: string; ip: string; timestamp: Date },
    locale?: string,
  ): Promise<void> {
    this.logger.debug(
      `[New Session] To: ${email}, Name: ${name}, Device: ${sessionInfo.device}, IP: ${sessionInfo.ip}, Locale: ${locale}`,
    );
  }

  async sendInvitation(
    email: string,
    data: {
      inviterName: string;
      tenantName: string;
      role: string;
      token: string;
      expiresAt: Date;
    },
    locale?: string,
  ): Promise<void> {
    this.logger.debug(
      `[Invitation] To: ${email}, From: ${data.inviterName}, Tenant: ${data.tenantName}, Role: ${data.role}, Token: ${data.token.substring(0, 8)}..., Locale: ${locale}`,
    );
  }
}
```

### 10.4 Exemplo de implementação com Resend

```typescript
// resend-email.provider.ts
import { Injectable } from "@nestjs/common";
import { IEmailProvider } from "@bymax-one/nest-auth";
import { Resend } from "resend";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class ResendEmailProvider implements IEmailProvider {
  private readonly resend: Resend;
  private readonly fromEmail: string;
  private readonly appUrl: string;

  constructor(private readonly config: ConfigService) {
    this.resend = new Resend(config.getOrThrow("RESEND_API_KEY"));
    this.fromEmail = config.getOrThrow("EMAIL_FROM");
    this.appUrl = config.getOrThrow("APP_URL");
  }

  // ⚠️ SEGURANÇA: Todos os valores dinâmicos (name, role, etc.) DEVEM ser escapados antes de
  // interpolação em HTML para prevenir XSS. Use uma função helper como:
  //   const escapeHtml = (s: string) => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  // Exemplo: `<p>Ola ${escapeHtml(name)},</p>`
  // Este exemplo foi simplificado para fins de documentação — em produção, use um engine
  // de templates (ex: Handlebars, mjml) que faz escaping automaticamente.

  async sendPasswordResetToken(
    email: string,
    token: string,
    name: string,
    locale?: string,
  ): Promise<void> {
    await this.resend.emails.send({
      from: this.fromEmail,
      to: email,
      subject: "Redefinir sua senha",
      html: `
        <p>Ola ${name},</p>
        <p>Clique no link para redefinir sua senha:</p>
        <a href="${this.appUrl}/reset-password?token=${token}">Redefinir Senha</a>
        <p>Este link expira em 1 hora.</p>
      `,
    });
  }

  async sendPasswordResetOtp(
    email: string,
    otp: string,
    name: string,
    locale?: string,
  ): Promise<void> {
    await this.resend.emails.send({
      from: this.fromEmail,
      to: email,
      subject: "Código de redefinição de senha",
      html: `
        <p>Ola ${name},</p>
        <p>Seu código de redefinição de senha e: <strong>${otp}</strong></p>
        <p>Este código expira em 10 minutos.</p>
      `,
    });
  }

  async sendEmailVerificationOtp(
    email: string,
    otp: string,
    name: string,
    locale?: string,
  ): Promise<void> {
    await this.resend.emails.send({
      from: this.fromEmail,
      to: email,
      subject: "Verificar seu email",
      html: `
        <p>Ola ${name},</p>
        <p>Seu código de verificação e: <strong>${otp}</strong></p>
        <p>Este código expira em 10 minutos.</p>
      `,
    });
  }

  async sendMfaEnabledNotification(email: string, name: string): Promise<void> {
    await this.resend.emails.send({
      from: this.fromEmail,
      to: email,
      subject: "Autenticação de dois fatores ativada",
      html: `
        <p>Ola ${name},</p>
        <p>A autenticação de dois fatores foi ativada na sua conta.</p>
        <p>Se voce não fez isso, entre em contato com o suporte imediatamente.</p>
      `,
    });
  }

  async sendMfaDisabledNotification(
    email: string,
    name: string,
  ): Promise<void> {
    await this.resend.emails.send({
      from: this.fromEmail,
      to: email,
      subject: "Autenticação de dois fatores desativada",
      html: `
        <p>Ola ${name},</p>
        <p>A autenticação de dois fatores foi desativada na sua conta.</p>
        <p>Se voce não fez isso, entre em contato com o suporte imediatamente.</p>
      `,
    });
  }

  async sendNewSessionAlert(
    email: string,
    name: string,
    sessionInfo: { device: string; ip: string; timestamp: Date },
  ): Promise<void> {
    await this.resend.emails.send({
      from: this.fromEmail,
      to: email,
      subject: "Novo login detectado",
      html: `
        <p>Ola ${name},</p>
        <p>Um novo login foi detectado na sua conta:</p>
        <ul>
          <li>Dispositivo: ${sessionInfo.device}</li>
          <li>IP: ${sessionInfo.ip}</li>
          <li>Horário: ${sessionInfo.timestamp.toISOString()}</li>
        </ul>
        <p>Se não foi voce, altere sua senha imediatamente.</p>
      `,
    });
  }

  async sendInvitation(
    email: string,
    data: {
      inviterName: string;
      tenantName: string;
      role: string;
      token: string;
      expiresAt: Date;
    },
  ): Promise<void> {
    await this.resend.emails.send({
      from: this.fromEmail,
      to: email,
      subject: `Convite para ${data.tenantName}`,
      html: `
        <p>Ola!</p>
        <p>${data.inviterName} convidou voce para participar de ${data.tenantName} como ${data.role}.</p>
        <a href="${this.appUrl}/invite/accept?token=${data.token}">Aceitar Convite</a>
        <p>Este convite expira em ${data.expiresAt.toLocaleDateString("pt-BR")}.</p>
      `,
    });
  }
}
```

---

## 11. Sistema de OAuth

### 11.1 Interface `OAuthProviderPlugin`

O sistema de OAuth é extensível via plugins. Cada provider implementa esta interface:

```typescript
export interface OAuthProviderPlugin {
  /** Nome único do provider (ex: 'google', 'github') */
  name: string;

  /** Passport Strategy do provider */
  strategy: Type<PassportStrategy>;

  /** Guard do Passport para o provider */
  guard: Type<AuthGuard>;

  /**
   * Função para extrair o perfil padronizado do resultado do Passport.
   * Cada provider retorna dados em formatos diferentes.
   */
  extractProfile(passportUser: any): OAuthProfile;
}
```

### 11.2 Google OAuth (built-in)

O pacote inclui suporte built-in para Google OAuth:

```typescript
// google-oauth.plugin.ts
export class GoogleOAuthPlugin implements OAuthProviderPlugin {
  name = "google";
  strategy = GoogleStrategy;
  guard = GoogleAuthGuard;

  extractProfile(passportUser: any): OAuthProfile {
    return {
      provider: "google",
      providerId: passportUser.id,
      email: passportUser.emails[0].value,
      name: passportUser.displayName,
      picture: passportUser.photos?.[0]?.value,
      raw: passportUser,
    };
  }
}

// google.strategy.ts
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, "google") {
  constructor(@Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions) {
    super({
      clientID: options.oauth.google.clientId,
      clientSecret: options.oauth.google.clientSecret,
      callbackURL: options.oauth.google.callbackUrl,
      scope: ["email", "profile"],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
  ): Promise<any> {
    return profile;
  }
}

// google-auth.guard.ts
@Injectable()
export class GoogleAuthGuard extends AuthGuard("google") {}
```

### 11.3 Fluxo completo de OAuth

```
1. Usuário clica "Entrar com Google"
   │
   ▼
2. GET /auth/google?tenantId=xxx → GoogleAuthGuard → Redireciona para Google
   (tenantId é incluído no state parameter armazenado no Redis)
   │
   ▼
3. Usuário autoriza no Google
   │
   ▼
4. Google redireciona para callback
   │
   ▼
5. GET /auth/google/callback → GoogleAuthGuard → GoogleStrategy.validate()
   │
   ▼
6. OAuthService.handleCallback(profile)
   │
   ├─ 6a. Busca usuário existente: userRepo.findByOAuthId('google', googleId)
   │
   ├─ 6b. Executa hook onOAuthLogin(profile, existingUser)
   │   │
   │   ├─ action: 'link' → userRepo.linkOAuth(userId, 'google', googleId)
   │   │
   │   ├─ action: 'create' → userRepo.createWithOAuth({ ... })
   │   │
   │   └─ action: 'reject' → Retorna erro
   │
   ├─ 6c. Emite JWT cookies (access + refresh)
   │
   └─ 6d. Cria sessão (se habilitado)
   │
   ▼
7. Redireciona para frontend com sessão ativa
```

> **Resolução de tenantId no OAuth:** O `tenantId` deve ser passado como query parameter na URL de início do fluxo OAuth (`GET /auth/{provider}?tenantId=xxx`). O pacote inclui o `tenantId` no state parameter salvo no Redis (`auth:os:{sha256(state)} → { tenantId }`). No callback, o `tenantId` é recuperado do state e passado ao hook `onOAuthLogin`. Se o hook `onOAuthLogin` não for fornecido e `tenantId` não estiver no state, o callback falha com `auth.oauth_failed`. Isso garante que novos usuários OAuth sempre tenham um `tenantId` válido.

### 11.4 Registros de rotas OAuth

Para cada provider OAuth configurado, duas rotas são registradas automaticamente:

| Método | Rota                                 | Descrição                                      |
| ------ | ------------------------------------ | ---------------------------------------------- |
| `GET`  | `/{routePrefix}/{provider}`          | Inicia fluxo OAuth (redireciona para provider) |
| `GET`  | `/{routePrefix}/{provider}/callback` | Callback do provider (processa retorno)        |

**Exemplo para Google:**

- `GET /auth/google` — Inicia fluxo, redireciona para Google
- `GET /auth/google/callback` — Processa retorno do Google

### 11.5 Proteção CSRF no fluxo OAuth

Em uma arquitetura stateless (sem sessions do Passport), o parâmetro `state` do OAuth não é verificado automaticamente. O pacote implementa proteção CSRF da seguinte forma:

1. **Início do fluxo:** Ao redirecionar para o provedor OAuth, o pacote gera um `state` aleatório (32 bytes hex) e o armazena no Redis com TTL de 10 minutos: `auth:os:{sha256(state)} → { tenantId }`
2. **Callback:** Ao receber o callback, o pacote verifica que o `state` retornado existe no Redis e o remove (single-use)
3. **Rejeição:** Se o `state` não for encontrado no Redis, o callback é rejeitado com `auth.oauth_failed`

Essa abordagem não depende de sessions do Passport e funciona corretamente em arquiteturas stateless com múltiplas instâncias, desde que compartilhem o mesmo Redis.

---

## 12. Estratégia de Redis

### 12.1 Visão geral

O Redis é usado extensivamente para armazenamento de tokens, sessões, cache e contadores. Todas as chaves seguem um padrão consistente com namespace configurável.

### 12.2 Padrão de chaves

Todas as chaves seguem o formato: `{namespace}:{prefixo}:{identificador}`

Onde `{namespace}` é o valor de `redisNamespace` (padrão: `auth`).

### 12.3 Tabela completa de chaves Redis

| Prefixo | Padrão da Chave                            | Valor                                                                             | TTL                                                        | Propósito                                                                                                                                                                                                                                            |
| ------- | ------------------------------------------ | --------------------------------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rt`    | `auth:rt:{sha256(token)}`                  | JSON com dados da sessão: `{ userId, tenantId, role, device, ip, createdAt }`     | `refreshExpiresInDays` (em dias, convertido para segundos) | Sessão de refresh token. Armazena dados necessários para reemitir access token sem consultar o banco.                                                                                                                                                |
| `rv`    | `auth:rv:{jti}` ou `auth:rv:{sha256(jwt)}` | `'1'`                                                                             | TTL restante do JWT (calculado a partir do `exp`)          | Blacklist de access JWT. Quando um token é revogado (logout), o `jti` (se presente) ou o hash SHA-256 do JWT é usado como chave. O `JwtAuthGuard` verifica esta chave. Preferir `jti` quando disponível, pois evita o custo de hash do JWT completo. |
| `us`    | `auth:us:{userId}`                         | String do status (ex: `'ACTIVE'`, `'BANNED'`)                                     | `userStatusCacheTtlSeconds` (padrão: 60s)                  | Cache do status do usuário. Evita consulta ao banco a cada requisição. Invalidado quando status muda.                                                                                                                                                |
| `rp`    | `auth:rp:{sha256(oldToken)}`               | `newRawToken` (UUID do novo refresh token)                                        | `refreshGraceWindowSeconds` (padrão: 30s)                  | Ponteiro de rotação (grace window). Quando o refresh token é rotacionado, o token antigo aponta para o novo pelo tempo configurado. Isso previne erros em requisições concorrentes que usam o token antigo.                                           |
| `lf`    | `auth:lf:{sha256(tenantId + ":" + email)}` | Contador numérico (string)                                                        | `windowSeconds` (padrão: 900s = 15 min)                    | Tentativas de login falhadas por tenant. Incrementado a cada falha. Quando atinge `maxAttempts`, o login é bloqueado. Escopo por tenant evita que lockout em um tenant afete outro.                                                                    |
| `pr`    | `auth:pr:{sha256(token)}`                  | `userId` (string)                                                                 | `tokenTtlSeconds` (padrão: 3600s = 1 hora)                 | Token de password reset. Mapeia o hash do token para o userId. Consumido (removido) ao usar.                                                                                                                                                         |
| `otp`   | `auth:otp:{purpose}:{sha256(tenantId + ":" + email)}` | JSON: `{ code: string, attempts: number }`                                        | `otpTtlSeconds` (varia por propósito)                      | Códigos OTP (one-time password) por tenant. O campo `attempts` rastreia tentativas falhadas (máximo 5). Propósitos: `password_reset`, `email_verification`. Escopo por tenant evita colisão de OTPs entre tenants.                                     |
| `mfa`   | `auth:mfa:{sha256(mfaTempToken)}`          | `userId` (string)                                                                 | 300 segundos (5 minutos)                                   | Token temporário de MFA. Emitido após login com senha quando MFA está habilitado. Consumido ao completar o desafio MFA.                                                                                                                              |
| `sess`  | `auth:sess:{userId}`                       | SET (Redis Set) de session hashes                                                 | Igual ao max refresh TTL                                   | Rastreamento de sessões ativas do usuário. Cada membro do SET é o sha256 de um refresh token ativo. Usado para contar e listar sessões.                                                                                                              |
| `sd`    | `auth:sd:{sessionHash}`                    | JSON: `{ device: string, ip: string, createdAt: string, lastActivityAt: string }` | Igual ao max refresh TTL                                   | Detalhes de uma sessão específica. O sessionHash corresponde a um membro do SET `auth:sess:{userId}`.                                                                                                                                                |
| `inv`   | `auth:inv:{sha256(token)}`                 | JSON: `{ email: string, role: string, tenantId: string, inviterId: string }`      | `invitations.tokenTtlSeconds` (padrão: 604800s = 7 dias)          | Convites pendentes. Consumido ao aceitar o convite.                                                                                                                                                                                                  |
| `os`    | `auth:os:{sha256(state)}`                  | JSON: `{ tenantId: string }`                                                      | 600s (10 min)                                              | CSRF state do OAuth                                                                                                                                                                                                                                  |
| `tu`    | `auth:tu:{userId}:{code}`                  | `'1'`                                                                             | 90 segundos (3 × janela TOTP)                              | Prevenção de replay de código TOTP. Após verificação bem-sucedida, o código usado é armazenado para evitar reutilização dentro da mesma janela temporal.                                                                                              |
| `prt`   | `auth:prt:{sha256(token)}`                 | JSON com dados da sessão: `{ userId, role, device, ip, createdAt }`               | `refreshExpiresInDays` (em dias, convertido para segundos) | Sessão de refresh token de admin da plataforma. Mesma estrutura que `rt` mas para tokens de plataforma.                                                                                                                                               |
| `prp`   | `auth:prp:{sha256(oldToken)}`              | `newRawToken` (UUID do novo refresh token de plataforma)                          | `refreshGraceWindowSeconds` (padrão: 30s)                  | Ponteiro de rotação para refresh token de plataforma. Mesma lógica que `rp` mas para o fluxo de admin.                                                                                                                                                |
| `prv`   | `auth:prv:{sha256(token)}`                 | JSON: `{ email: string, tenantId: string }`                                       | 300 segundos (5 minutos)                                   | Token de verificação de OTP de reset de senha. Emitido após validação bem-sucedida do OTP no fluxo de 2 etapas. Consumido ao resetar a senha.                                                                                                         |

### 12.4 Operações Redis por funcionalidade

**Login:**

```
1. GET  auth:lf:{sha256(tid+email)}      → Verificar brute-force (escopo por tenant)
2. INCR auth:lf:{sha256(tid+email)}      → Se falhar, registrar tentativa
3. SET  auth:rt:{sha256(refreshToken)}   → Criar sessão de refresh
4. SADD auth:sess:{userId}               → Adicionar sessão ao SET
5. SET  auth:sd:{sessionHash}            → Armazenar detalhes da sessão
6. DEL  auth:lf:{sha256(tid+email)}      → Se sucesso, resetar brute-force
```

**Refresh (operação atômica via Lua script):**

```lua
-- Script Lua para rotação atômica de refresh token
-- Garante que o token antigo só pode ser usado uma vez (previne race condition)
local old_key = KEYS[1]              -- auth:rt:{sha256(old)}
local new_key = KEYS[2]              -- auth:rt:{sha256(new)}
local pointer_key = KEYS[3]          -- auth:rp:{sha256(old)}
local new_session_data = ARGV[1]     -- JSON da nova sessão
local new_raw_token = ARGV[2]        -- novo token raw (para o ponteiro)
local refresh_ttl = tonumber(ARGV[3])  -- TTL em segundos
local grace_ttl = tonumber(ARGV[4])  -- refreshGraceWindowSeconds da configuração

-- 1. Tenta buscar e deletar atomicamente a sessão antiga
local session_data = redis.call('GET', old_key)
if session_data then
  redis.call('DEL', old_key)
  -- 2. Cria ponteiro de rotação (grace window)
  redis.call('SET', pointer_key, new_raw_token, 'EX', grace_ttl)
  -- 3. Cria nova sessão
  redis.call('SET', new_key, new_session_data, 'EX', refresh_ttl)
  return session_data
end

-- 4. Se não encontrou, tenta grace window (requisição concorrente)
local pointed_token = redis.call('GET', pointer_key)
if pointed_token then
  return 'GRACE:' .. pointed_token  -- retorna token existente do grace window
end

-- 5. Token inválido ou expirado
return nil
```

> **Por que Lua?** Sem atomicidade, duas requisições concorrentes com o mesmo refresh token podem ambas passar no GET (step 1) antes que o DEL aconteça, criando duas sessões válidas. O script Lua executa no Redis como operação atômica, eliminando a race condition.

**Logout:**

```
1. SET  auth:rv:{jti || sha256(accessJwt)} EX {remaining}  → Blacklist do access JWT (usa jti se disponível)
2. DEL  auth:rt:{sha256(refreshToken)}               → Remover sessão
3. SREM auth:sess:{userId} {sessionHash}             → Remover do SET
4. DEL  auth:sd:{sessionHash}                         → Remover detalhes
```

### 12.5 Considerações de performance

- **Todas as operações são O(1)** exceto `SMEMBERS` para listar sessões (O(N) onde N = número de sessões, tipicamente < 10)
- **O namespace** evita colisoes com outras chaves Redis da aplicação
- **Todos os identificadores sensíveis são hasheados com SHA-256** antes de serem usados como chave, prevenindo exposição de tokens no Redis
- **TTLs são sempre definidos** para evitar acumulo de chaves orfas

---

## 13. Estrutura de JWT Claims

### 13.1 Dashboard JWT (Access Token)

O access token JWT para usuários de dashboard/tenant contém os seguintes claims:

```typescript
export interface DashboardJwtPayload {
  /** Subject — ID do usuário */
  sub: string;

  jti: string; // ID único do token (UUID v4) — usado para blacklist

  /** ID do tenant ao qual o usuário pertence */
  tenantId: string;

  /** Role do usuário no tenant (ex: 'OWNER', 'ADMIN', 'MEMBER') */
  role: string;

  /** Tipo do token — sempre 'dashboard' para diferenciar de platform */
  type: "dashboard";

  /** Status atual do usuário (ex: 'ACTIVE', 'PENDING_APPROVAL') */
  status: string;

  /**
   * Se o MFA foi verificado nesta sessão.
   * - true: usuário completou o desafio MFA
   * - false: usuário tem MFA habilitado mas não verificou nesta sessão
   * - undefined/false: usuário não tem MFA habilitado
   */
  mfaVerified: boolean;

  /** Issued At — timestamp de emissão (automático) */
  iat: number;

  /** Expiration — timestamp de expiração (automático, baseado em accessExpiresIn) */
  exp: number;
}
```

**Exemplo de payload decodificado:**

```json
{
  "sub": "clx1abc2def3ghi4jkl",
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "tenantId": "tenant_bymax_finance",
  "role": "OWNER",
  "type": "dashboard",
  "status": "ACTIVE",
  "mfaVerified": true,
  "iat": 1712678400,
  "exp": 1712679300
}
```

> **Pinagem de algoritmo (segurança obrigatória):** O Passport JWT Strategy DEVE ser configurado com `algorithms: ['HS256']` explicitamente. Nunca confiar no header `alg` do token recebido. Isso previne ataques de algorithm confusion (CVE-2015-9235) onde um atacante envia um token com `alg: 'none'` ou `alg: 'RS256'` usando o secret como chave pública. Esta validação é implementada internamente pelo pacote na `jwt.strategy.ts`.

### 13.2 Platform JWT (Admin Token)

Token JWT para administradores da plataforma:

```typescript
export interface PlatformJwtPayload {
  /** Subject — ID do admin */
  sub: string;

  jti: string; // ID único do token (UUID v4) — usado para blacklist

  /** Role na plataforma (ex: 'SUPER_ADMIN', 'ADMIN', 'SUPPORT') */
  role: string;

  /** Tipo do token — sempre 'platform' */
  type: "platform";

  mfaVerified: boolean; // MFA completado (se habilitado para o admin)

  /** Issued At */
  iat: number;

  /** Expiration */
  exp: number;
}
```

**Exemplo:**

```json
{
  "sub": "admin_001",
  "jti": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "role": "SUPER_ADMIN",
  "type": "platform",
  "mfaVerified": true,
  "iat": 1712678400,
  "exp": 1712679300
}
```

### 13.3 MFA Temp Token

Token temporário emitido durante o fluxo de login quando MFA é obrigatório:

```typescript
export interface MfaTempPayload {
  /** Subject — ID do usuário que precisa completar MFA */
  sub: string;

  /** Tipo do token — sempre 'mfa_challenge' */
  type: "mfa_challenge";

  /** Contexto de origem do desafio MFA: 'dashboard' ou 'platform' */
  context: 'dashboard' | 'platform';

  /** Issued At */
  iat: number;

  /** Expiration — 5 minutos após emissão */
  exp: number;
}
```

**Exemplo:**

```json
{
  "sub": "clx1abc2def3ghi4jkl",
  "type": "mfa_challenge",
  "context": "dashboard",
  "iat": 1712678400,
  "exp": 1712678700
}
```

### 13.4 Refresh Token

O refresh token **NÃO é um JWT**. É um **token opaco** (UUID v4) armazenado no Redis.

```
Formato: UUID v4
Exemplo: "f47ac10b-58cc-4372-a567-0e02b2c3d479"
Armazenamento: Redis (auth:rt:{sha256(token)})
Transporte:
  - tokenDelivery 'cookie': Cookie HttpOnly com path restrito (/auth)
  - tokenDelivery 'bearer': Retornado no body, armazenado no SecureStore/Keychain do device
  - tokenDelivery 'both': Cookie + body
```

**Justificativa para token opaco:**

- Não é verificável sem o Redis (mais seguro se interceptado)
- Pode ser revogado instantaneamente (delete no Redis)
- Não carrega claims decodificáveis pelo cliente
- Rotação é mais simples (gerar novo UUID)

---

## 14. Gerenciamento de Cookies

### 14.1 Tabela de cookies

| Cookie         | Nome Padrão     | Path    | HttpOnly | Secure     | SameSite | Max-Age                                      | Propósito                                                                                                                                                                                                   |
| -------------- | --------------- | ------- | -------- | ---------- | -------- | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Access Token   | `access_token`  | `/`     | Sim      | Sim (prod) | `Lax`    | `accessCookieMaxAgeMs` (900.000 ms = 15 min) | Transporta o JWT em toda requisição HTTP. HttpOnly impede acesso via JavaScript.                                                                                                                            |
| Refresh Token  | `refresh_token` | `/auth` | Sim      | Sim (prod) | `Strict` | `refreshExpiresInDays * 86400000` (7 dias)   | Token opaco para renovação. Path restrito a `/auth` limita envio apenas para endpoints de refresh. `Strict` previne CSRF.                                                                                   |
| Session Signal | `has_session`   | `/`     | Não      | Sim (prod) | `Lax`    | Igual ao refresh                             | Cookie não-HttpOnly legível pelo JavaScript/proxy. Indica que existe sessão ativa. **Não contém dados sensíveis** — apenas `"1"`. Útil para middleware de proxy ou frontend decidir se deve tentar refresh. |

> **Nota:** Se `routePrefix` for alterado do padrão `'auth'`, o `cookies.refreshCookiePath` deve ser atualizado para corresponder (ex: `routePrefix: 'api/v1/auth'` → `refreshCookiePath: '/api/v1/auth'`). Caso contrário, o browser não enviará o cookie de refresh para o endpoint correto.

### 14.2 Resolução de domínios

Para suporte multi-domínio (ex: `api.example.com` e `app.example.com`), os cookies precisam ser setados no domínio correto.

**Lógica de resolução:**

```typescript
// Se resolveDomains está configurado, usa a função customizada
if (options.cookies.resolveDomains) {
  const domains = options.cookies.resolveDomains(req.hostname);
  // Seta cookies em cada domínio retornado
  for (const domain of domains) {
    res.cookie(name, value, { ...cookieOptions, domain });
  }
}

// Se não, usa extractDomain como fallback
else {
  const domain = this.extractDomain(req.hostname);
  res.cookie(name, value, { ...cookieOptions, domain });
}
```

**Exemplo de `resolveDomains`:**

```typescript
// Configuração
cookies: {
  resolveDomains: (requestDomain: string) => {
    // Em produção, seta em .example.com para cobrir todos os subdomains
    if (requestDomain.endsWith('.example.com')) {
      return ['.example.com'];
    }
    // Em desenvolvimento local
    if (requestDomain === 'localhost') {
      return ['localhost'];
    }
    return [requestDomain];
  },
}
```

> **⚠️ Segurança em multi-tenant com subdomínios:** Usar `domain='.example.com'` faz com que cookies sejam enviados para TODOS os subdomínios, incluindo subdomínios de outros tenants. Isso pode permitir cross-subdomain token leakage. **Recomendações:**
> 1. Prefira domínios específicos (`tenant-a.example.com`) ao invés do wildcard
> 2. O `JwtAuthGuard` deve sempre validar que o `tenantId` no JWT corresponde ao tenant da requisição atual
> 3. Se o wildcard for necessário, implemente um middleware de validação de tenant na aplicação host

> **⚠️ CRÍTICO — Allowlist de domínios:** A função `resolveDomains` recebe `req.hostname`, que deriva do header `Host` HTTP. Em ambientes onde o `Host` header não é validado pelo proxy/load balancer, um atacante pode manipulá-lo para injetar domínios arbitrários e fazer com que cookies sejam setados para domínios controlados pelo atacante.
>
> **O `resolveDomains` DEVE validar que o domínio retornado está em uma allowlist de domínios configurados:**
> ```typescript
> cookies: {
>   resolveDomains: (requestDomain: string) => {
>     const ALLOWED_DOMAINS = ['.example.com', 'localhost'];
>     // Valida que o requestDomain pertence a um domínio permitido
>     const isAllowed = ALLOWED_DOMAINS.some(d =>
>       requestDomain === d.replace(/^\./, '') || requestDomain.endsWith(d)
>     );
>     if (!isAllowed) {
>       // Retorna domínio padrão seguro em vez de usar requestDomain diretamente
>       return ['.example.com'];
>     }
>     return [`.${requestDomain.split('.').slice(-2).join('.')}`];
>   },
> }
> ```
> **Nunca retornar `requestDomain` diretamente sem validação.**

### 14.3 Ciclo de vida dos cookies

**Login bem-sucedido (sem MFA):**

```
1. setAccessCookie(res, accessJwt)          → access_token = JWT
2. setRefreshCookie(res, refreshToken)      → refresh_token = UUID
3. setSessionSignal(res)                    → has_session = "1"
```

**Login com MFA (fase 1 — senha correta, MFA pendente):**

```
Nenhum cookie e setado.
Retorna { mfaRequired: true, mfaTempToken: "..." } no body.
```

**Login com MFA (fase 2 — MFA completado):**

```
1. setAccessCookie(res, accessJwt)          → access_token = JWT (com mfaVerified: true)
2. setRefreshCookie(res, refreshToken)      → refresh_token = UUID
3. setSessionSignal(res)                    → has_session = "1"
```

**Refresh:**

```
1. clearAccessCookie(res)                   → Remove access_token antigo
2. clearRefreshCookie(res)                  → Remove refresh_token antigo
3. setAccessCookie(res, newAccessJwt)       → access_token = novo JWT
4. setRefreshCookie(res, newRefreshToken)   → refresh_token = novo UUID
```

**Logout:**

```
1. clearAllAuthCookies(res, req)
   → Remove access_token (path: /)
   → Remove refresh_token (path: /auth)
   → Remove has_session (path: /)
   → Em todos os domínios resolvidos
```

### 14.4 Segurança dos cookies

| Medida                        | Justificativa                                                                           |
| ----------------------------- | --------------------------------------------------------------------------------------- |
| `HttpOnly` nos tokens         | Impede acesso via `document.cookie` — protege contra XSS                                |
| `Secure` em produção          | Cookies so são enviados via HTTPS                                                       |
| `SameSite: Strict` no refresh | Impede envio em requisições cross-origin — protege contra CSRF                          |
| `SameSite: Lax` no access     | Permite navegação normal (links) mas bloqueia POST cross-origin                         |
| Path restrito no refresh      | `/auth` limita o envio do refresh token apenas para endpoints de renovação              |
| Session signal não-HttpOnly   | Deliberadamente legível pelo JS para permitir lógica de proxy/frontend sem expor tokens |

### 14.5 Modos de entrega de token (`tokenDelivery`)

O `TokenDeliveryService` encapsula toda a lógica de entrega e leitura de tokens, garantindo que os controllers e guards não precisam conhecer o modo ativo.

#### Comportamento por modo

| Ação              | `'cookie'` (padrão)                       | `'bearer'`                                     | `'both'`                                  |
| ----------------- | ----------------------------------------- | ---------------------------------------------- | ----------------------------------------- |
| **Login/Register** | Seta cookies; body retorna apenas `user`  | Não seta cookies; body retorna `accessToken`, `refreshToken` e `user` | Seta cookies E body retorna tokens        |
| **Refresh**       | Lê refresh do cookie; seta novos cookies  | Lê `refreshToken` do body `{ refreshToken }`; retorna tokens no body | Tenta cookie primeiro, depois body        |
| **Logout**        | Limpa cookies                             | Blacklist via token do header `Authorization`  | Limpa cookies e blacklist do header       |
| **Guards**        | Extrai JWT do cookie `access_token`       | Extrai JWT do header `Authorization: Bearer`   | Tenta cookie primeiro, depois header      |

#### Response em modo `'bearer'`

```typescript
// POST /auth/login — modo 'bearer' ou 'both'
{
  "user": { "id": "...", "email": "...", "role": "..." },
  "accessToken": "eyJhbGci...",
  "refreshToken": "550e8400-e29b-..."
}

// POST /auth/refresh — modo 'bearer' ou 'both'
{
  "accessToken": "eyJhbGci...",
  "refreshToken": "550e8400-e29b-..."
}
```

#### Armazenamento seguro no cliente mobile

Em modo `'bearer'`, o cliente mobile é responsável por armazenar os tokens com segurança:

```typescript
// React Native — armazenamento recomendado
import * as SecureStore from 'expo-secure-store'; // Expo
// ou
import Keychain from 'react-native-keychain';     // React Native bare

// Salvar após login
await SecureStore.setItemAsync('access_token', response.accessToken);
await SecureStore.setItemAsync('refresh_token', response.refreshToken);

// Enviar nas requisições
headers: { Authorization: `Bearer ${accessToken}` }

// Refresh
const body = { refreshToken: await SecureStore.getItemAsync('refresh_token') };
const { accessToken, refreshToken } = await api.post('/auth/refresh', body);
```

> `expo-secure-store` e `react-native-keychain` usam o Keychain (iOS) e Keystore (Android) do sistema operacional — equivalente em segurança ao `HttpOnly` cookie, pois são inacessíveis por outras apps.

#### Configuração para backend que serve web e mobile

```typescript
BymaxAuthModule.registerAsync({
  useFactory: (config: ConfigService) => ({
    tokenDelivery: 'both',   // web recebe cookies; mobile usa tokens do body
    jwt: { secret: config.get('JWT_SECRET') },
    // cookies ainda são configurados normalmente para o modo web
    cookies: {
      resolveDomains: (domain) => [`.${config.get('APP_DOMAIN')}`],
    },
  }),
  inject: [ConfigService],
})
```

---

## 15. Catálogo de Error Codes

### 15.1 Classe `AuthException`

```typescript
import { HttpException, HttpStatus } from "@nestjs/common";

/**
 * Exceção padronizada do módulo de autenticação.
 * Todas as exceções seguem o mesmo formato de resposta.
 */
export class AuthException extends HttpException {
  constructor(
    code: string,
    statusCode: HttpStatus = HttpStatus.UNAUTHORIZED,
    details?: Record<string, unknown>,
  ) {
    super(
      {
        error: {
          code,
          message: AUTH_ERROR_MESSAGES[code] || "Erro de autenticação",
          details: details || null,
        },
      },
      statusCode,
    );
  }
}
```

```typescript
/**
 * Mapeamento de códigos de erro para mensagens legíveis.
 * Usado internamente pelo AuthException.
 */
export const AUTH_ERROR_MESSAGES: Record<string, string> = {
  "auth.invalid_credentials": "Email ou senha inválidos",
  "auth.account_locked": "Conta temporariamente bloqueada. Tente novamente em alguns minutos.",
  "auth.account_inactive": "Conta inativa",
  "auth.account_suspended": "Conta suspensa",
  "auth.account_banned": "Conta banida",
  "auth.token_expired": "Token expirado",
  "auth.token_revoked": "Token revogado",
  "auth.token_invalid": "Token inválido",
  "auth.refresh_token_invalid": "Refresh token inválido ou expirado",
  "auth.session_expired": "Sessão expirada",
  "auth.email_already_exists": "Email já cadastrado",
  "auth.email_not_verified": "Email não verificado",
  "auth.invalid_invitation_token": "Token de convite inválido ou expirado",
  "auth.mfa_required": "Autenticação de dois fatores necessária",
  "auth.mfa_invalid_code": "Código MFA inválido",
  "auth.mfa_already_enabled": "MFA já está habilitado",
  "auth.mfa_not_enabled": "MFA não está habilitado",
  "auth.mfa_setup_required": "Configuração de MFA necessária",
  "auth.mfa_temp_token_invalid": "Token temporário de MFA inválido ou expirado",
  "auth.recovery_code_invalid": "Código de recuperação inválido",
  "auth.password_too_weak": "Senha muito fraca",
  "auth.password_reset_token_invalid": "Token de redefinição de senha inválido",
  "auth.password_reset_token_expired": "Token de redefinição de senha expirado",
  "auth.otp_invalid": "Código OTP inválido",
  "auth.otp_expired": "Código OTP expirado",
  "auth.otp_max_attempts": "Número máximo de tentativas excedido",
  "auth.insufficient_role": "Permissão insuficiente",
  "auth.forbidden": "Acesso negado",
  "auth.pending_approval": "Conta pendente de aprovação",
  "auth.session_limit_reached": "Limite de sessões atingido",
  "auth.session_not_found": "Sessão não encontrada",
  "auth.oauth_failed": "Falha na autenticação OAuth",
  "auth.oauth_email_mismatch": "Email do OAuth não corresponde",
  "auth.platform_auth_required": "Autenticação de plataforma necessária",
};
```

### 15.2 Formato de resposta de erro

Todas as respostas de erro seguem este formato consistente:

```json
{
  "error": {
    "code": "auth.invalid_credentials",
    "message": "Email ou senha inválidos",
    "details": null
  }
}
```

### 15.3 Tabela completa de códigos de erro

| Código                       | HTTP Status | Mensagem                                                            | Contexto                                                                                                                                       |
| ---------------------------- | ----------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `auth.invalid_credentials`   | 401         | Email ou senha inválidos                                            | Login com credenciais incorretas. Mensagem genérica deliberada para não revelar se email existe.                                               |
| `auth.account_locked`        | 429         | Conta temporariamente bloqueada. Tente novamente em alguns minutos. | Brute-force: excedeu `maxAttempts` dentro da `windowSeconds`. O response inclui header `Retry-After` com o número de segundos até desbloqueio. |
| `auth.account_inactive`      | 403         | Conta inativa                                                       | Status do usuário é INACTIVE.                                                                                                                  |
| `auth.account_suspended`     | 403         | Conta suspensa                                                      | Status do usuário e SUSPENDED.                                                                                                                 |
| `auth.account_banned`      | 403         | Conta banida                                                        | Status do usuário é BANNED.                                                                                                    |
| `auth.token_expired`         | 401         | Token expirado                                                      | Access JWT expirou (após `accessExpiresIn`).                                                                                                   |
| `auth.token_revoked`         | 401         | Token revogado                                                      | Access JWT está na blacklist Redis (pos-logout).                                                                                               |
| `auth.token_invalid`         | 401         | Token inválido                                                      | JWT malformado, assinatura inválida, ou usuário não encontrado.                                                                                |
| `auth.refresh_token_invalid` | 401         | Refresh token inválido ou expirado                                  | Refresh token não encontrado no Redis (expirou ou foi revogado).                                                                               |
| `auth.session_expired`       | 401         | Sessão expirada                                                     | Sessão associada ao refresh token não existe mais.                                                                                             |
| `auth.email_already_exists`  | 409         | Email já cadastrado                                                 | Tentativa de registro com email existente no mesmo tenant.                                                                                     |
| `auth.email_not_verified`    | 403         | Email não verificado                                                | Login com `emailVerification.required = true` e email não verificado.                                                                          |
| `auth.invalid_invitation_token` | 400      | Token de convite inválido ou expirado                               | Token de convite não encontrado no Redis.                                                                                                      |
| `auth.mfa_required`          | 403         | Autenticação de dois fatores necessária                             | Endpoint exige MFA verificado mas JWT não tem `mfaVerified: true`.                                                                             |
| `auth.mfa_invalid_code`      | 401         | Código MFA inválido                                                 | Código TOTP de 6 digitos incorreto.                                                                                                            |
| `auth.mfa_already_enabled`   | 409         | MFA já está habilitado                                              | Tentativa de setup quando MFA já está ativo.                                                                                                   |
| `auth.mfa_not_enabled`       | 400         | MFA não está habilitado                                             | Tentativa de desabilitar quando MFA não está ativo.                                                                                            |
| `auth.mfa_setup_required`    | 400         | Configuração de MFA necessária                                      | Tentativa de verificar sem ter feito setup.                                                                                                    |
| `auth.mfa_temp_token_invalid` | 401        | Token temporário de MFA inválido ou expirado                        | MFA temp token (5 min) expirou ou não existe no Redis.                                                                                         |
| `auth.recovery_code_invalid` | 401         | Código de recuperação inválido                                      | Recovery code não corresponde a nenhum hash armazenado.                                                                                        |
| `auth.password_too_weak`     | 400         | Senha muito fraca                                                   | Senha não atende criterios mínimos (< 8 caracteres).                                                                                           |
| `auth.password_reset_token_invalid` | 400  | Token de redefinição de senha inválido                              | Token de reset não encontrado no Redis.                                                                                                        |
| `auth.password_reset_token_expired` | 400  | Token de redefinição de senha expirado                              | Token existia mas TTL expirou.                                                                                                                 |
| `auth.otp_invalid`           | 401         | Código OTP inválido                                                 | Código OTP não corresponde ao armazenado.                                                                                                      |
| `auth.otp_expired`           | 401         | Código OTP expirado                                                 | OTP não encontrado no Redis (TTL expirou).                                                                                                     |
| `auth.otp_max_attempts`      | 429         | Número máximo de tentativas excedido                                | Excedeu 5 tentativas falhadas para o mesmo OTP.                                                                                                |
| `auth.insufficient_role`     | 403         | Permissao insuficiente                                              | Role do usuário não satisfaz a hierarquia exigida pelo endpoint.                                                                               |
| `auth.forbidden`             | 403         | Acesso negado                                                       | Acesso genérico negado (fallback).                                                                                                             |
| `auth.pending_approval`      | 403         | Conta pendente de aprovação                                         | Status do usuário é PENDING_APPROVAL.                                                                                                          |
| `auth.session_limit_reached` | 409         | Limite de sessões atingido                                          | Número de sessões ativas excedeu o limite (informativo, FIFO resolve automaticamente).                                                         |
| `auth.session_not_found`     | 404         | Sessão não encontrada                                               | Tentativa de revogar sessão inexistente.                                                                                                       |
| `auth.oauth_failed`          | 401         | Falha na autenticação OAuth                                         | Erro genérico no fluxo OAuth (provider rejeitou, etc).                                                                                         |
| `auth.oauth_email_mismatch`  | 409         | Email do OAuth não corresponde                                      | Email do provider OAuth não corresponde ao esperado.                                                                                           |
| `auth.platform_auth_required` | 401        | Autenticação de plataforma necessária                               | Tentativa de acessar endpoint de plataforma com JWT de dashboard.                                                                              |

> **Exceção ao princípio de não-enumeração:** O endpoint `POST /auth/register` necessariamente revela se um email já existe (retornando 409). Isso é uma limitação aceita do fluxo de registro. Para mitigar, a aplicação host pode implementar rate limiting agressivo neste endpoint e considerar estratégias alternativas como enviar um email "você já tem uma conta" em vez de retornar erro.

### 15.4 Constantes de códigos

```typescript
// auth-error-codes.ts
export const AUTH_ERROR_CODES = {
  INVALID_CREDENTIALS: "auth.invalid_credentials",
  ACCOUNT_LOCKED: "auth.account_locked",
  ACCOUNT_INACTIVE: "auth.account_inactive",
  ACCOUNT_SUSPENDED: "auth.account_suspended",
  ACCOUNT_BANNED: "auth.account_banned",
  TOKEN_EXPIRED: "auth.token_expired",
  TOKEN_REVOKED: "auth.token_revoked",
  TOKEN_INVALID: "auth.token_invalid",
  REFRESH_TOKEN_INVALID: "auth.refresh_token_invalid",
  SESSION_EXPIRED: "auth.session_expired",
  EMAIL_ALREADY_EXISTS: "auth.email_already_exists",
  EMAIL_NOT_VERIFIED: "auth.email_not_verified",
  INVALID_INVITATION_TOKEN: "auth.invalid_invitation_token",
  MFA_REQUIRED: "auth.mfa_required",
  MFA_INVALID_CODE: "auth.mfa_invalid_code",
  MFA_ALREADY_ENABLED: "auth.mfa_already_enabled",
  MFA_NOT_ENABLED: "auth.mfa_not_enabled",
  MFA_SETUP_REQUIRED: "auth.mfa_setup_required",
  MFA_TEMP_TOKEN_INVALID: "auth.mfa_temp_token_invalid",
  RECOVERY_CODE_INVALID: "auth.recovery_code_invalid",
  PASSWORD_TOO_WEAK: "auth.password_too_weak",
  PASSWORD_RESET_TOKEN_INVALID: "auth.password_reset_token_invalid",
  PASSWORD_RESET_TOKEN_EXPIRED: "auth.password_reset_token_expired",
  OTP_INVALID: "auth.otp_invalid",
  OTP_EXPIRED: "auth.otp_expired",
  OTP_MAX_ATTEMPTS: "auth.otp_max_attempts",
  INSUFFICIENT_ROLE: "auth.insufficient_role",
  FORBIDDEN: "auth.forbidden",
  PENDING_APPROVAL: "auth.pending_approval",
  SESSION_LIMIT_REACHED: "auth.session_limit_reached",
  SESSION_NOT_FOUND: "auth.session_not_found",
  OAUTH_FAILED: "auth.oauth_failed",
  OAUTH_EMAIL_MISMATCH: "auth.oauth_email_mismatch",
  PLATFORM_AUTH_REQUIRED: "auth.platform_auth_required",
} as const;
```

### 15.5 Princípios de segurança nos erros

1. **Nunca revelar existência de usuário**: `auth.invalid_credentials` é usado tanto para email não encontrado quanto para senha incorreta. A mensagem e sempre "Email ou senha inválidos".

2. **Mascarar PII em logs**: Emails e tokens nunca são logados em texto plano. Usa-se `sha256(email).substring(0, 8)` para referência em logs.

3. **Comparação constant-time**: Senhas, tokens e OTPs são sempre comparados usando `timingSafeEqual` ou equivalente do bcrypt para prevenir timing attacks.

4. **Respostas consistentes**: Todos os erros seguem o mesmo formato JSON, independente do tipo de erro. Isso dificulta fingerprinting.

5. **Anti-enumeração em endpoints públicos**: Os endpoints `POST /auth/verify-email`, `POST /auth/resend-verification`, `POST /auth/password/forgot-password` e `POST /auth/password/resend-otp` retornam **sempre o mesmo status e body** independente de o email existir ou não. Timing de resposta é normalizado (aguarda tempo constante) para prevenir side-channel de tempo.

---

## 16. Rate Limiting

### 16.1 Abordagem

O pacote adota uma abordagem **hibrida** para rate limiting:

1. **Rate limiting por IP** (via `@nestjs/throttler`): A aplicação host configura o `ThrottlerModule` globalmente. O pacote exporta constantes de configuração recomendadas via `AUTH_THROTTLE_CONFIGS`.

2. **Brute-force por email** (via Redis): O `BruteForceService` e **sempre ativo** e rastreia tentativas de login falhadas por email (usando SHA-256 do email como chave). Este mecanismo e independente do `ThrottlerModule`.

### 16.2 Configurações de rate limiting exportadas

O pacote exporta `AUTH_THROTTLE_CONFIGS` como constantes que a aplicação host pode usar nos decorators `@Throttle()`:

```typescript
export const AUTH_THROTTLE_CONFIGS = {
  /** POST /auth/login — 5 requisições por minuto */
  login: { default: { limit: 5, ttl: 60_000 } },

  /** POST /auth/register — 10 requisições por hora */
  register: { default: { limit: 10, ttl: 3_600_000 } },

  /** POST /auth/refresh — 10 requisições por minuto */
  refresh: { default: { limit: 10, ttl: 60_000 } },

  /** POST /auth/password/forgot-password — 3 requisições por 5 minutos */
  forgotPassword: { default: { limit: 3, ttl: 300_000 } },

  /** POST /auth/password/reset-password — 3 requisições por 5 minutos */
  resetPassword: { default: { limit: 3, ttl: 300_000 } },

  /** POST /auth/password/verify-otp — 3 requisições por 5 minutos (alinhado com limite interno de 5 tentativas por OTP) */
  verifyOtp: { default: { limit: 3, ttl: 300_000 } },

  /** POST /auth/mfa/setup — 5 requisições por minuto */
  mfaSetup: { default: { limit: 5, ttl: 60_000 } },

  /** POST /auth/mfa/challenge — 10 requisições por minuto */
  mfaChallenge: { default: { limit: 10, ttl: 60_000 } },

  /** POST /auth/mfa/disable — 3 requisições por 5 minutos */
  mfaDisable: { default: { limit: 3, ttl: 300_000 } },

  /** POST /auth/platform/login — 5 requisições por minuto */
  platformLogin: { default: { limit: 5, ttl: 60_000 } },

  /** POST /auth/verify-email — 5 requisições por minuto */
  verifyEmail: { default: { limit: 5, ttl: 60_000 } },

  /** POST /auth/resend-verification — 3 requisições por 5 minutos */
  resendVerification: { default: { limit: 3, ttl: 300_000 } },

  /** POST /auth/password/resend-otp — 3 requisições por 5 minutos */
  resendPasswordOtp: { default: { limit: 3, ttl: 300_000 } },

  /** POST /auth/invitations/accept — 5 requisições por minuto */
  invitationAccept: { default: { limit: 5, ttl: 60_000 } },
} as const;
```

### 16.3 Tabela resumo de rate limiting

| Endpoint                              | Limite | Janela    | Descrição                                 |
| ------------------------------------- | ------ | --------- | ----------------------------------------- |
| `POST /auth/login`                    | 5 req  | 1 minuto  | Protege contra brute-force por IP         |
| `POST /auth/register`                 | 10 req | 1 hora    | Protege contra criação em massa de contas |
| `POST /auth/refresh`                  | 10 req | 1 minuto  | Limita requisições de refresh             |
| `POST /auth/password/forgot-password` | 3 req  | 5 minutos | Evita spam de emails de reset             |
| `POST /auth/password/reset-password`  | 3 req  | 5 minutos | Protege endpoint de reset                 |
| `POST /auth/password/verify-otp`      | 3 req  | 5 minutos | Protege verificação de OTP (alinhado com máx. 5 tentativas internas por OTP) |
| `POST /auth/mfa/setup`                | 5 req  | 1 minuto  | Limita tentativas de setup                |
| `POST /auth/mfa/challenge`            | 10 req | 1 minuto  | Limita tentativas de MFA                  |
| `POST /auth/mfa/disable`              | 3 req  | 5 minutos | Protege desativação de MFA                |
| `POST /auth/platform/login`           | 5 req  | 1 minuto  | Protege login de admin                    |
| `POST /auth/verify-email`             | 5 req  | 1 minuto  | Limita verificação de email               |
| `POST /auth/resend-verification`      | 3 req  | 5 minutos | Evita spam de emails de verificação       |
| `POST /auth/password/resend-otp`      | 3 req  | 5 minutos | Evita spam de OTPs de reset de senha      |
| `POST /auth/invitations/accept`       | 5 req  | 1 minuto  | Protege aceitação de convites             |

### 16.4 Uso nos controllers

Os controllers aplicam os throttle configs via decorator `@Throttle()`:

```typescript
// auth.controller.ts
@Controller("auth")
export class AuthController {
  @Post("login")
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.login)
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response, // passthrough: true preserva interceptors do NestJS
    @Req() req: Request,
  ) {
    const result = await this.authService.login(
      dto,
      req.ip,
      req.headers["user-agent"],
    );
    // deliverAuthResponse seta cookies (se cookie/both) e retorna o body
    return this.tokenDeliveryService.deliverAuthResponse(res, req, result);
  }

  @Post("register")
  @Public()
  @Throttle(AUTH_THROTTLE_CONFIGS.register)
  async register(
    @Body() dto: RegisterDto,
    @Res({ passthrough: true }) res: Response, // passthrough: true preserva interceptors do NestJS
    @Req() req: Request,
  ) {
    // ...
  }
}
```

### 16.5 Pre-requisito da aplicação host

A aplicação host **deve** configurar o `ThrottlerModule` para que os decorators `@Throttle()` funcionem:

```typescript
// app.module.ts
import { ThrottlerModule, ThrottlerGuard } from "@nestjs/throttler";
import { APP_GUARD } from "@nestjs/core";

@Module({
  imports: [
    ThrottlerModule.forRoot([
      {
        ttl: 60_000, // Padrão global: 100 req/min
        limit: 100,
      },
    ]),
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}
```

---

## 17. O que NÃO está no Pacote

O `@bymax-one/nest-auth` foi projetado com fronteiras claras. Os seguintes itens são **responsabilidade da aplicação host** e não estão incluidos no pacote:

| Item                                    | Motivo                                                                                              | Onde implementar                                                     |
| --------------------------------------- | --------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| **Schemas Prisma / migrações de banco** | O pacote e database-agnostic. Funciona com qualquer ORM via interfaces.                             | Na aplicação host, nos schemas do Prisma/TypeORM/etc.                |
| **Templates de email**                  | O pacote e template-agnostic. Define o que enviar, não como renderizar.                             | Na implementação de `IEmailProvider` da aplicação host.              |
| **Criação de tenants**                  | Lógica de negócio específica da plataforma (plans, billing, onboarding).                            | Módulo de tenants da aplicação host.                                 |
| **Billing, planos e assinaturas**       | Escopo do `@bymax/stripe` ou módulo de billing.                                                     | Módulo de billing da aplicação host.                                 |
| **Autenticação por API key**            | Escopo diferente — para integração M2M, não para usuários.                                          | Módulo separado ou middleware da aplicação host.                     |
| **Portal sessions (Stripe)**            | Especifico do Stripe, não relacionado a autenticação.                                               | Módulo de billing.                                                   |
| **Audit logging**                       | O pacote fornece hooks (`afterLogin`, `afterRegister`, etc.) para a aplicação host registrar.       | Via hooks `IAuthHooks` e módulo de auditoria.                        |
| **CORS / Helmet / CSP**                 | Configuração de infraestrutura, não de autenticação.                                                | `main.ts` ou middleware global da aplicação host.                    |
| **Conexoes com banco de dados**         | O pacote recebe repositórios já conectados via injeção de dependência.                              | Módulo de banco de dados da aplicação host.                          |
| **Campos adicionais de perfil**         | Alem dos campos de `AuthUser`, perfis são responsabilidade da aplicação.                            | Tabela de perfis da aplicação host.                                  |
| **Tenant resolution middleware**        | Como determinar o tenant da requisição (subdomain, header, path) e específico da aplicação.         | Middleware ou interceptor da aplicação host.                         |
| **Validação customizada de senha**      | O pacote verifica apenas comprimento mínimo (8 chars). Regras adicionais ficam na aplicação.        | Via hook `beforeRegister` ou validação no DTO da aplicação.          |
| **Componentes frontend**                | O pacote e backend-only (NestJS).                                                                   | Framework frontend da escolha (React, Vue, etc.).                    |
| **Gerenciamento de estado OAuth**       | O `state` parameter do OAuth (CSRF protection) é gerenciado pelo pacote via Redis (ver seção 11.5). | Automático no fluxo OAuth do pacote.                                 |
| **Fluxo de alteração de email**         | Requer re-verificação do novo email, notificação no email antigo — fluxo complexo e específico      | Implementar na aplicação host usando `IEmailProvider` e `OtpService` |
| **Exclusão de conta (GDPR erasure)**    | Direito ao esquecimento requer anonimização de dados financeiros — lógica de negócio                | Implementar na aplicação host; usar hooks para limpeza de auth       |

---

## 18. Dependências

### 18.1 Peer Dependencies

Estas dependências devem estar instaladas na aplicação host. O pacote não as inclui — ele espera que já existam.

| Pacote               | Versão    | Motivo                                             |
| -------------------- | --------- | -------------------------------------------------- |
| `@nestjs/common`     | `^11.0.0` | Framework core — decorators, exceptions, providers |
| `@nestjs/core`       | `^11.0.0` | Framework core — module system, DI container       |
| `@nestjs/jwt`        | `^11.0.0` | Emissão e verificação de JWTs                      |
| `@nestjs/passport`   | `^11.0.0` | Integração Passport.js com NestJS                  |
| `@nestjs/throttler`  | `^6.0.0`  | Rate limiting via decorators                       |
| `@nestjs/websockets` | `^11.0.0` | Suporte a WebSocket guards (opcional — necessário apenas se usar WsJwtGuard) |
| `bcrypt`             | `^5.0.0`  | Hashing de senhas (bcrypt)                         |
| `class-transformer`  | `^0.5.0`  | Transformação de DTOs                              |
| `class-validator`    | `^0.14.0` | Validação de DTOs                                  |
| `ioredis`            | `^5.0.0`  | Cliente Redis                                      |
| `passport`           | `^0.7.0`  | Framework de autenticação                          |
| `passport-jwt`       | `^4.0.0`  | Estratégia JWT para Passport                       |
| `reflect-metadata`   | `^0.2.0`  | Metadata reflection para decorators                |

### 18.2 Dependencies

Dependências incluidas diretamente no pacote:

| Pacote    | Versão   | Motivo                              |
| --------- | -------- | ----------------------------------- |
| `otpauth` | `^9.0.0` | Geração e verificação de TOTP (MFA) |

### 18.3 Optional Peer Dependencies

Dependências opcionais que so precisam ser instaladas se a funcionalidade correspondente for usada.
São declaradas em `peerDependencies` com `peerDependenciesMeta: { optional: true }` — o npm/yarn
informa ao consumidor sobre sua existência mas não instala automaticamente:

| Pacote                    | Versão   | Quando necessário                      |
| ------------------------- | -------- | -------------------------------------- |
| `passport-google-oauth20` | `^2.0.0` | Quando `oauth.google` está configurado |

### 18.4 Exemplo de `package.json`

```json
{
  "name": "@bymax-one/nest-auth",
  "version": "1.0.0",
  "description": "Módulo NestJS reutilizável de autenticação para o ecossistema Bymax SaaS",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "files": ["dist"],
  "scripts": {
    "build": "tsc -p tsconfig.build.json",
    "lint": "eslint src",
    "test": "jest",
    "test:cov": "jest --coverage",
    "prepublishOnly": "npm run build"
  },
  "peerDependencies": {
    "@nestjs/common": "^11.0.0",
    "@nestjs/core": "^11.0.0",
    "@nestjs/jwt": "^11.0.0",
    "@nestjs/passport": "^11.0.0",
    "@nestjs/throttler": "^6.0.0",
    "@nestjs/websockets": "^11.0.0",
    "bcrypt": "^5.0.0",
    "class-transformer": "^0.5.0",
    "class-validator": "^0.14.0",
    "ioredis": "^5.0.0",
    "passport": "^0.7.0",
    "passport-jwt": "^4.0.0",
    "passport-google-oauth20": "^2.0.0",
    "reflect-metadata": "^0.2.0"
  },
  "dependencies": {
    "otpauth": "^9.0.0"
  },
  "peerDependenciesMeta": {
    "@nestjs/websockets": { "optional": true },
    "passport-google-oauth20": { "optional": true }
  },
  "devDependencies": {
    "@nestjs/testing": "^11.0.0",
    "@types/bcrypt": "^5.0.0",
    "@types/passport-jwt": "^4.0.0",
    "@types/passport-google-oauth20": "^2.0.0",
    "jest": "^29.0.0",
    "ts-jest": "^29.0.0",
    "typescript": "^5.5.0"
  },
  "keywords": [
    "nestjs",
    "auth",
    "authentication",
    "jwt",
    "mfa",
    "totp",
    "oauth",
    "saas",
    "multi-tenant"
  ],
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/bymax-digital/auth.git"
  }
}
```

---

## 19. Fases de Implementação

> **Estratégia de testes:** Testes unitários devem ser escritos **junto com cada fase** (TDD), não acumulados na Fase 6. A Fase 6 foca em testes de integração, E2E e polimento. Cada fase deve atingir 80%+ de cobertura unitária nos services implementados.

### 19.1 Visão geral do cronograma

| Fase | Semana     | Duração  | Foco                              | Entregáveis                                                                                                                  |
| ---- | ---------- | -------- | --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 1    | Semana 1   | 1 semana | Fundação do Core                  | Scaffold, interfaces, config, Redis, password, token manager, cookie, brute-force + testes unitários                         |
| 2    | Semana 2   | 1 semana | Autenticação Core                 | JWT strategy, auth service/controller, roles guard, user status guard, decorators, DTOs, wiring do módulo + testes unitários |
| 3    | Semana 3   | 1 semana | MFA                               | Crypto AES-256-GCM, MFA service/controller, guard, decorator + testes unitários                                              |
| 4    | Semana 3-4 | 1 semana | Sessões + Password Reset          | Session service/controller, password reset service/controller, OTP, verificação de email + testes unitários                  |
| 5    | Semana 4-5 | 1 semana | Platform Admin + OAuth + Convites | PlatformAuth, OAuth module, Google plugin, Invitation service/controller + testes unitários                                  |
| 6    | Semana 5-6 | 1 semana | Integração + Polimento            | WsJwtGuard, testes de integração E2E, error codes completos, JSDoc, README                                                   |

> **Estimativa:** ~6 semanas para 1 desenvolvedor + agente de IA. Com revisão humana rigorosa, adicionar 20% de buffer (~7 semanas total).

### 19.2 Fase 1: Fundação do Core (Semana 1)

**Objetivo:** Criar a estrutura base do pacote com todos os blocos fundamentais.

**Entregaveis:**

1. **Scaffold do projeto**
   - `package.json` com peer dependencies
   - `tsconfig.json` e `tsconfig.build.json`
   - Estrutura de diretórios (`src/`, subdiretórios)
   - `src/index.ts` (barrel export inicial)

2. **Interfaces base**
   - `auth-module-options.interface.ts` — Interface completa de configuração
   - `user-repository.interface.ts` — `AuthUser` e `IUserRepository`
   - `platform-user-repository.interface.ts` — `AuthPlatformUser` e `IPlatformUserRepository`
   - `email-provider.interface.ts` — `IEmailProvider`
   - `auth-hooks.interface.ts` — `IAuthHooks` e interfaces auxiliares
   - `jwt-payload.interface.ts` — Payloads de JWT
   - `authenticated-request.interface.ts` — Request tipado

3. **Configuração**
   - `bymax-one-nest-auth.constants.ts` — Tokens de injeção
   - `config/default-options.ts` — Valores padrão
   - `config/resolved-options.ts` — Merge de opções

4. **Redis**
   - `redis/auth-redis.service.ts` — Wrapper sobre ioredis com namespace
   - `redis/auth-redis.module.ts` — Módulo Redis interno

5. **Serviços fundamentais**
   - `services/password.service.ts` — Hash e comparação bcrypt
   - `services/token-manager.service.ts` — Emissão e verificação de JWTs
   - `services/token-delivery.service.ts` — Entrega de tokens (cookie/bearer/both)
   - `services/brute-force.service.ts` — Proteção contra brute-force

6. **Crypto**
   - `crypto/aes-gcm.ts` — Funções de criptografia AES-256-GCM
   - `crypto/secure-token.ts` — Geração de tokens seguros

7. **Erros**
   - `errors/auth-error-codes.ts` — Constantes de códigos
   - `errors/auth-exception.ts` — Classe AuthException

8. **Testes unitários**
   - Testes para `PasswordService`, `TokenManagerService`, `TokenDeliveryService`, `BruteForceService`
   - Testes para `AuthRedisService` (mock Redis)
   - Cobertura mínima: 80%

### 19.3 Fase 2: Autenticação Core (Semana 2)

**Objetivo:** Implementar o fluxo completo de autenticação (registro, login, logout, refresh).

**Entregaveis:**

1. **JWT Strategy**
   - `strategies/jwt.strategy.ts` — Passport strategy para dashboard
   - Extração do JWT de cookie + header Authorization
   - Validação e população de `request.user`

2. **Guards**
   - `guards/jwt-auth.guard.ts` — Guard JWT padrão com suporte a `@Public()`
   - `guards/roles.guard.ts` — Guard de roles com hierarquia
   - `guards/user-status.guard.ts` — Verificação de status via cache Redis

3. **Decorators**
   - `decorators/current-user.decorator.ts`
   - `decorators/roles.decorator.ts`
   - `decorators/public.decorator.ts`

4. **DTOs**
   - `dto/register.dto.ts`
   - `dto/login.dto.ts`

5. **Auth Service e Controller**
   - `services/auth.service.ts` — Implementação completa (register, login, logout, refresh, getMe)
   - `controllers/auth.controller.ts` — Endpoints com decorators e throttle

6. **Módulo dinâmico**
   - `bymax-one-nest-auth.module.ts` — `registerAsync()`, provider registration, conditional controller loading

7. **Testes unitários**
   - Testes para `AuthService` (register, login, logout, refresh)
   - Testes para guards (JwtAuthGuard, RolesGuard, UserStatusGuard)
   - Cobertura mínima: 80%

### 19.4 Fase 3: MFA (Semana 3)

**Objetivo:** Implementar autenticação multi-fator completa com TOTP.

**Entregaveis:**

1. **Crypto AES-256-GCM**
   - Implementação de `encrypt()` e `decrypt()` em `crypto/aes-gcm.ts`
   - Formato: `iv:authTag:ciphertext` (base64)

2. **MFA Service**
   - `services/mfa.service.ts` — setup, verifyAndEnable, challenge, disable
   - Geração de recovery codes com hash bcrypt
   - Criptografia/descriptografia de secrets TOTP

3. **MFA Controller**
   - `controllers/mfa.controller.ts` — Endpoints setup, verify, challenge, disable

4. **MFA DTOs**
   - `dto/mfa-verify.dto.ts`
   - `dto/mfa-challenge.dto.ts`
   - `dto/mfa-disable.dto.ts`

5. **Guards e Decorators**
   - `guards/mfa-required.guard.ts`
   - `decorators/skip-mfa.decorator.ts`

6. **Testes unitários**
   - Testes para `MfaService` (setup, verify, challenge, disable, recovery codes)
   - Testes para `AES-256-GCM` (encrypt/decrypt round-trip)
   - Testes para `MfaRequiredGuard`
   - Cobertura mínima: 80%

### 19.5 Fase 4: Sessões + Password Reset (Semana 3-4)

**Objetivo:** Implementar gerenciamento de sessões e fluxo de reset de senha.

**Entregaveis:**

1. **Session Service e Controller**
   - `services/session.service.ts` — createSession, listSessions, revokeSession, revokeAllExceptCurrent, enforceSessionLimit
   - `controllers/session.controller.ts` — Endpoints list, revoke, revokeAll

2. **Password Reset Service e Controller**
   - `services/password-reset.service.ts` — initiateReset, resetPassword, verifyOtp
   - `controllers/password-reset.controller.ts` — Endpoints forgot, reset, verifyOtp, resendOtp

3. **OTP Service**
   - `services/otp.service.ts` — generate, store, verify, incrementAttempts

4. **Verificação de Email**
   - Integração no `auth.service.ts` — verifyEmail, resendVerificationEmail
   - Endpoints no `auth.controller.ts`

5. **DTOs**
   - `dto/forgot-password.dto.ts`
   - `dto/reset-password.dto.ts`

6. **Testes unitários**
   - Testes para `SessionService` (create, list, revoke, FIFO eviction)
   - Testes para `PasswordResetService` (token e OTP methods)
   - Testes para `OtpService`
   - Cobertura mínima: 80%

### 19.6 Fase 5: Platform Admin + OAuth + Convites (Semana 4-5)

**Objetivo:** Implementar autenticação de plataforma, OAuth e sistema de convites.

**Entregaveis:**

1. **Platform Auth**
   - `strategies/jwt-platform.strategy.ts` — Strategy separada para JWTs de plataforma
   - `guards/jwt-platform.guard.ts`
   - `guards/platform-roles.guard.ts`
   - `decorators/platform-roles.decorator.ts`
   - `services/platform-auth.service.ts`
   - `controllers/platform-auth.controller.ts`
   - `dto/platform-login.dto.ts`

2. **OAuth Module**
   - `oauth/oauth.module.ts` — Módulo dinâmico para providers OAuth
   - `oauth/oauth.service.ts` — handleCallback, registro de plugins
   - `oauth/google/google-oauth.plugin.ts`
   - `oauth/google/google.strategy.ts`
   - `oauth/google/google-auth.guard.ts`
   - Interfaces: `oauth-provider.interface.ts`

3. **Convites**
   - `services/invitation.service.ts` — invite, acceptInvitation
   - `controllers/invitation.controller.ts`
   - `dto/accept-invitation.dto.ts`

4. **Testes unitários**
   - Testes para `PlatformAuthService`
   - Testes para `InvitationService`
   - Testes para `OAuthService` e Google plugin (mock Passport)
   - Cobertura mínima: 80%

### 19.7 Fase 6: Integração + Polimento (Semana 5-6)

**Objetivo:** Finalizar o pacote com WebSocket support, documentação e testes.

**Entregaveis:**

1. **WebSocket Guard**
   - `guards/ws-jwt.guard.ts` — Autenticação JWT para WebSocket handshake
   - Extração de token via header `Authorization` apenas (não query param — tokens em query params são logados em plaintext por proxies)

2. **Guards adicionais**
   - `guards/self-or-admin.guard.ts`
   - `guards/optional-auth.guard.ts`

3. **Error Codes completos**
   - Mensagens em portugues para todos os códigos
   - Mapeamento de códigos para HTTP status

4. **Documentação**
   - JSDoc em todos os métodos públicos
   - README.md com guia de inicio rapido
   - Exemplos de integração

5. **Testes**
   - Testes unitários para todos os serviços
   - Testes de integração para fluxos completos (register → login → refresh → logout)
   - Testes para MFA (setup → verify → challenge → disable)
   - Testes para brute-force, sessões, password reset
   - Coverage mínimo: 80%

6. **Polimento**
   - Revisao de barrel exports (`index.ts`)
   - Validação de opções na inicialização do módulo
   - Logs estruturados com `Logger` do NestJS
   - Publicação no npm

---

## 20. Limitações Conhecidas

Esta seção documenta limitações técnicas e arquiteturais do pacote que devem ser consideradas antes da adoção.

### 20.1 Framework

| Limitação          | Impacto                                                                | Alternativa                                             |
| ------------------ | ---------------------------------------------------------------------- | ------------------------------------------------------- |
| **Apenas NestJS**  | Não funciona com Express puro, Fastify standalone ou outros frameworks | Extrair services para pacote agnóstico em versão futura |
| **Node.js apenas** | Sem suporte a Deno, Bun ou outros runtimes                             | Sem plano de suporte                                    |

### 20.2 Autenticação

| Limitação                                  | Impacto                                                                                                            | Alternativa                                                      |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- |
| **Apenas HS256 (simétrico)**               | Não suporta RS256/ES256 para verificação distribuída sem compartilhar secret                                       | Planejado para versão futura                                     |
| **Sem WebAuthn/passkeys**                  | Não suporta autenticação por biometria ou chaves de segurança                                                      | Fora do escopo v1                                                |
| **Sem magic links/passwordless**           | Não suporta login por link enviado por email                                                                       | Fora do escopo v1                                                |
| **bcrypt trunca senhas acima de 72 bytes** | Senhas muito longas são silenciosamente truncadas                                                                  | Documentar requisito de senha máxima 128 chars nos DTOs          |

### 20.3 Infraestrutura

| Limitação                                    | Impacto                                                                          | Alternativa                                                     |
| -------------------------------------------- | -------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| **Redis é ponto único de falha**             | Se Redis cair, refresh, logout, brute-force, MFA e sessions falham               | Usar Redis com replicação (Sentinel/Cluster)                    |
| **Single-region**                            | Sem discussão de multi-region Redis replication ou JWT validation across regions | Aplicação host deve configurar Redis Cluster multi-region       |
| **Sem key rotation para JWT secret**         | Se o secret for comprometido, todos os tokens são comprometidos                  | Reiniciar secret invalida todos os tokens; sem dual-key support |
| **Sem key rotation para MFA encryption key** | Se a chave AES for comprometida, todos os TOTP secrets são expostos              | Sem mecanismo de re-encriptação automática                      |

### 20.4 Multi-tenancy

| Limitação                 | Impacto                                                               | Alternativa                                              |
| ------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------- |
| **Single-tenant JWT**     | Usuário que pertence a múltiplos tenants precisa de sessões separadas | Aplicação host gerencia troca de tenant                  |
| **Sem tenant resolution** | Pacote não resolve tenant de subdomínio, header ou body               | Aplicação host deve resolver tenant antes de chamar auth |

### 20.5 Funcionalidades ausentes

| Funcionalidade                     | Status       | Previsão                                |
| ---------------------------------- | ------------ | --------------------------------------- |
| Login por API key (header Bearer)  | Não incluído | Responsabilidade de cada SaaS           |
| Portal sessions (token temporário) | Não incluído | Responsabilidade de cada SaaS           |
| Email change flow                  | Não incluído | Versão futura                           |
| Account deletion (GDPR erasure)    | Não incluído | Responsabilidade de cada SaaS via hooks |
| Recovery code regeneration         | Não incluído | Versão futura                           |
| OAuth account unlinking            | Não incluído | Versão futura                           |

---

## Apêndice A: Fluxos Detalhados

### A.1 Fluxo completo de registro

```
Cliente                    AuthController              AuthService                 Repositório/Redis
  │                            │                          │                            │
  │ POST /auth/register        │                          │                            │
  │ { email, password,         │                          │                            │
  │   name, tenantId }         │                          │                            │
  │────────────────────────────>│                          │                            │
  │                            │ register(dto, res, req)  │                            │
  │                            │─────────────────────────>│                            │
  │                            │                          │ hooks.beforeRegister()      │
  │                            │                          │─────┐                      │
  │                            │                          │<────┘ { allowed: true }     │
  │                            │                          │                            │
  │                            │                          │ findByEmail(email, tenant)  │
  │                            │                          │───────────────────────────>│
  │                            │                          │<───────────────────────────│ null
  │                            │                          │                            │
  │                            │                          │ hash(password)              │
  │                            │                          │─────┐                      │
  │                            │                          │<────┘ passwordHash          │
  │                            │                          │                            │
  │                            │                          │ create({ ... })             │
  │                            │                          │───────────────────────────>│
  │                            │                          │<───────────────────────────│ user
  │                            │                          │                            │
  │                            │                          │ [Se emailVerification.required]
  │                            │                          │ otpService.generate()       │
  │                            │                          │ otpService.store()          │
  │                            │                          │ emailProvider.sendVerificationOtp()
  │                            │                          │                            │
  │                            │                          │ tokenManager.issueTokens()
  │                            │                          │───────────────────────────>│ SET rt:...
  │                            │                          │                            │
  │                            │                          │ hooks.afterRegister()       │
  │                            │                          │─────┐                      │
  │                            │                          │<────┘                      │
  │                            │                          │                            │
  │                            │<─────────────────────────│ AuthResult                  │
  │                            │ tokenDelivery.deliverAuthResponse()                    │
  │<────────────────────────────│ 201 Created (cookie/body conforme tokenDelivery)       │
```

### A.2 Fluxo completo de login com MFA

```
Cliente                    AuthController              AuthService                 Redis/MFA
  │                            │                          │                          │
  │ POST /auth/login           │                          │                          │
  │ { email, password, tid }   │                          │                          │
  │────────────────────────────>│                          │                          │
  │                            │ login(dto, res, req)     │                          │
  │                            │─────────────────────────>│                          │
  │                            │                          │ bruteForce.isLockedOut()  │
  │                            │                          │─────────────────────────>│
  │                            │                          │<─────────────────────────│ false
  │                            │                          │                          │
  │                            │                          │ findByEmail() → user      │
  │                            │                          │ password.compare() → true │
  │                            │                          │                          │
  │                            │                          │ user.mfaEnabled = true    │
  │                            │                          │ issueMfaTempToken(userId) │
  │                            │                          │─────────────────────────>│ SET mfa:...
  │                            │<─────────────────────────│                          │
  │<────────────────────────────│ 200 { mfaRequired, token }                        │
  │                            │                          │                          │
  │ POST /auth/mfa/challenge   │                          │                          │
  │ { mfaTempToken, code }     │                          │                          │
  │────────────────────────────>│                          │                          │
  │                            │ MfaController            │                          │
  │                            │─────────────────────────>│ mfa.challenge()          │
  │                            │                          │ verifyMfaTempToken()     │
  │                            │                          │─────────────────────────>│ GET mfa:...
  │                            │                          │<─────────────────────────│ userId
  │                            │                          │                          │
  │                            │                          │ decryptSecret()          │
  │                            │                          │ verifyTOTP(secret, code) │
  │                            │                          │                          │
  │                            │                          │ tokenManager.issueTokens()
  │                            │                          │ (mfaVerified: true)      │
  │                            │                          │─────────────────────────>│ SET rt:...
  │                            │                          │                          │
  │                            │                          │ hooks.afterLogin()       │
  │                            │<─────────────────────────│ user                     │
  │                            │ tokenDelivery.deliverAuthResponse()                  │
  │<────────────────────────────│ 200 (cookie/body conforme tokenDelivery)             │
```

### A.3 Fluxo de refresh com rotação

```
Cliente                    AuthController              TokenManager               Redis
  │                            │                          │                          │
  │ POST /auth/refresh         │                          │                          │
  │ (cookie ou body conforme   │                          │                          │
  │  tokenDelivery)            │                          │                          │
  │────────────────────────────>│                          │                          │
  │                            │ refresh(req, res)        │                          │
  │                            │─────────────────────────>│                          │
  │                            │                          │ GET rt:{sha256(OLD)}      │
  │                            │                          │─────────────────────────>│
  │                            │                          │<─────────────────────────│ sessionData
  │                            │                          │                          │
  │                            │                          │ Gera NEW = UUID v4        │
  │                            │                          │                          │
  │                            │                          │ SET rp:{sha256(OLD)} = NEW│
  │                            │                          │ EX 30                     │
  │                            │                          │─────────────────────────>│ (grace window)
  │                            │                          │                          │
  │                            │                          │ SET rt:{sha256(NEW)} = ...│
  │                            │                          │─────────────────────────>│ (nova sessão)
  │                            │                          │                          │
  │                            │                          │ DEL rt:{sha256(OLD)}      │
  │                            │                          │─────────────────────────>│
  │                            │                          │                          │
  │                            │                          │ issueAccess(payload)      │
  │                            │                          │ retorna AuthResult        │
  │                            │<─────────────────────────│                          │
  │                            │ tokenDelivery.deliverRefreshResponse()              │
  │<────────────────────────────│ 200 + tokens (cookie/body conforme tokenDelivery)  │
```

### A.4 Fluxo de password reset (token)

```
Usuário          Controller              PasswordResetService      Redis           EmailProvider       UserRepository
  |                   |                          |                    |                  |                   |
  |--- POST /auth/forgot-password (email) ------>|                    |                  |                   |
  |                   |                          |--- findByEmail ----|------------------|------------------>|
  |                   |                          |<--- user ou null --|------------------|-------------------|
  |                   |                          |                    |                  |                   |
  |                   |                          |  [Sempre retorna 200 — não revela se email existe]       |
  |                   |                          |                    |                  |                   |
  |                   |                          |  [Se user existe:]  |                  |                   |
  |                   |                          |--- SET auth:pr:{hash} → userId, TTL 1h -->|              |
  |                   |                          |--- sendPasswordResetToken(email, token) -->|              |
  |                   |                          |                    |                  |                   |
  |<-- 200 { message: "Se o email existir..." } -|                    |                  |                   |
  |                   |                          |                    |                  |                   |
  |--- POST /auth/reset-password (token, newPassword) --------------->|                    |                   |
  |                   |                          |--- GET auth:pr:{hash} --------------->|                   |
  |                   |                          |<--- userId --------|                  |                   |
  |                   |                          |--- DEL auth:pr:{hash} --------------->|                   |
  |                   |                          |--- hash(newPassword) ----------------->|                   |
  |                   |                          |--- updatePassword(userId, hash) -------|------------------>|
  |                   |                          |--- [Invalida todas as sessões] ------->|                   |
  |                   |                          |--- hook.afterPasswordReset() -------->                    |
  |<-- 200 { message: "Senha redefinida" } ------|                    |                  |                   |
```

### A.5 Fluxo de logout

```
Usuário          Controller        AuthService         TokenDeliveryService  Redis
  |                   |                  |                    |                 |
  |--- POST /auth/logout (cookie/header) -->|                    |                 |
  |                   |                  |--- blacklist access JWT ----------->|
  |                   |                  |    SET auth:rv:{hash} TTL restante  |
  |                   |                  |--- delete refresh session --------->|
  |                   |                  |    DEL auth:rt:{hash}              |
  |                   |                  |--- remove from session SET -------->|
  |                   |                  |    SREM auth:sess:{userId}         |
  |                   |                  |--- hook.afterLogout() -->           |
  |                   |--- clearAuthSession() -->|                            |
  |<-- 200 (sessão limpa conforme tokenDelivery) |                            |
```

---

## Apêndice B: Checklist de Segurança

| Item                                     | Implementação                                     |
| ---------------------------------------- | ------------------------------------------------- |
| Senhas hasheadas com bcrypt (12 rounds)  | `PasswordService.hash()`                          |
| Comparação constant-time de senhas       | `bcrypt.compare()` internamente usa constant-time |
| Secrets TOTP criptografados em repouso   | AES-256-GCM em `MfaService.encryptSecret()`       |
| Recovery codes hasheados individualmente | Bcrypt hash de cada code                          |
| Refresh tokens opacos (não JWT)          | UUID v4, armazenados no Redis                     |
| Rotação de refresh tokens                | Novo token a cada refresh, antigo invalidado      |
| Grace window para rotação                | 30s ponteiro `rp:` para requisições concorrentes  |
| Blacklist de access tokens               | Redis key `rv:{sha256(jwt)}` no logout            |
| HttpOnly cookies (modo cookie/both)      | Access e refresh tokens nunca acessíveis via JS   |
| Secure storage (modo bearer)             | Mobile usa `SecureStore`/`Keychain` do OS — inacessível por outras apps |
| SameSite Strict no refresh (modo cookie) | Previne CSRF no endpoint de refresh               |
| Path restrito no refresh cookie          | `/auth` — não enviado em outras rotas (modo cookie/both) |
| Proteção brute-force                     | Lockout por email após N tentativas               |
| Rate limiting por IP                     | `@Throttle()` em todos os endpoints sensíveis     |
| Não revela existência de usuário         | Mensagem genérica em login e forgot-password      |
| PII mascarado em logs                    | `sha256(email).substring(0, 8)` para referência   |
| Cache de status com TTL                  | Redis cache de 60s evita queries excessivas       |
| Tokens com SHA-256 como chave Redis      | Tokens nunca armazenados em texto plano no Redis  |
| MFA temp token com TTL curto             | 5 minutos de validade                             |
| OTP com limite de tentativas             | Máximo 5 tentativas por OTP                       |
| Convites com TTL                         | 7 dias de validade por padrão                     |

---

_Fim da específicacao tecnica do `@bymax-one/nest-auth`._
