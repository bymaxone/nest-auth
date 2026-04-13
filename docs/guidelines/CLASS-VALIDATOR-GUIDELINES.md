# class-validator & class-transformer Guidelines — @bymax-one/nest-auth

> **Audience:** AI agents and developers working on this codebase.
> **Stack:** class-validator ^0.14+, class-transformer ^0.5, NestJS 11
> **Rule:** Follow these guidelines for all DTO validation in this project.

---

## Table of Contents

1. [DTO Structure](#1-dto-structure)
2. [Common Validators](#2-common-validators)
3. [Password Validation](#3-password-validation)
4. [Transformation](#4-transformation)
5. [Custom Validators](#5-custom-validators)
6. [Validation Groups](#6-validation-groups)
7. [Nested Validation](#7-nested-validation)
8. [Security Considerations](#8-security-considerations)
9. [Error Messages](#9-error-messages)
10. [Anti-Patterns](#10-anti-patterns)
11. [Quick Reference Checklist](#quick-reference-checklist)

---

## 1. DTO Structure

### 1.1 Fundamental Principles

Every Data Transfer Object (DTO) in this project is a **plain TypeScript class** decorated with class-validator decorators. DTOs are validated automatically by NestJS's `ValidationPipe` before the request reaches the controller handler.

- DTOs live under `src/server/dto/` (or the relevant module directory).
- One DTO per file. File name follows the pattern `<action>.dto.ts` (e.g., `register.dto.ts`).
- Class name follows PascalCase with a `Dto` suffix (e.g., `RegisterDto`).
- Every public property MUST have at least one validation decorator.
- Properties without decorators are silently stripped when `whitelist: true` is enabled.

### 1.2 Basic DTO Template

```typescript
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class RegisterDto {
  @IsEmail({}, { message: 'A valid email address is required.' })
  email: string;

  @IsString({ message: 'Password must be a string.' })
  @IsNotEmpty({ message: 'Password is required.' })
  @MinLength(8, { message: 'Password must be at least 8 characters.' })
  password: string;
}
```

### 1.3 ValidationPipe Integration

The global `ValidationPipe` MUST be configured in the NestJS application bootstrap or as a module-level provider exported by this library. The canonical configuration is:

```typescript
import { ValidationPipe } from '@nestjs/common';

app.useGlobalPipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
    transformOptions: {
      enableImplicitConversion: false,
    },
    stopAtFirstError: false,
    validationError: {
      target: false,
      value: false,
    },
  }),
);
```

**Key settings explained:**

| Option | Value | Purpose |
|---|---|---|
| `whitelist` | `true` | Strips properties without decorators |
| `forbidNonWhitelisted` | `true` | Throws 400 if extra properties are sent |
| `transform` | `true` | Runs class-transformer to convert plain objects to class instances |
| `enableImplicitConversion` | `false` | Prevents automatic type coercion; all conversions must be explicit |
| `target` | `false` | Hides the DTO class instance from error responses |
| `value` | `false` | Hides the offending value from error responses |

### 1.4 DTOs in This Project

The following DTOs are defined or planned for `@bymax-one/nest-auth`:

| DTO | Purpose |
|---|---|
| `RegisterDto` | New user registration (email, password, optional display name) |
| `LoginDto` | Email + password authentication |
| `ForgotPasswordDto` | Initiate password-reset flow (email only) |
| `ResetPasswordDto` | Complete password reset (token + new password) |
| `MfaVerifyDto` | Verify a TOTP/backup code during MFA challenge |
| `MfaChallengeDto` | Request an MFA challenge (session token) |
| `MfaDisableDto` | Disable MFA on an account (password or TOTP confirmation) |
| `PlatformLoginDto` | OAuth/social login callback data |
| `AcceptInvitationDto` | Accept a tenant/org invitation (token + optional password) |
| `CreateInvitationDto` | Create a new invitation (email, role, tenant) |

---

## 2. Common Validators

### 2.1 String Validators

```typescript
import {
  IsString,
  IsNotEmpty,
  MinLength,
  MaxLength,
  Matches,
} from 'class-validator';

// Basic non-empty string
@IsString({ message: 'Field must be a string.' })
@IsNotEmpty({ message: 'Field is required.' })
fieldName: string;

// Bounded string length
@IsString()
@MinLength(2, { message: 'Name must be at least 2 characters.' })
@MaxLength(100, { message: 'Name must not exceed 100 characters.' })
displayName: string;

// Regex-constrained string
@IsString()
@Matches(/^[a-z0-9-]+$/, { message: 'Slug must contain only lowercase letters, numbers, and hyphens.' })
slug: string;
```

### 2.2 Email Validation

Always use `@IsEmail` with an explicit empty options object and a custom message:

```typescript
@IsEmail({}, { message: 'A valid email address is required.' })
email: string;
```

Do NOT rely on `@IsEmail` alone for security -- emails are validated for format only. Downstream verification (confirmation link) is still required.

### 2.3 Enum Validation

```typescript
import { IsEnum } from 'class-validator';

export enum MfaMethod {
  TOTP = 'totp',
  SMS = 'sms',
  EMAIL = 'email',
}

@IsEnum(MfaMethod, { message: 'MFA method must be one of: totp, sms, email.' })
method: MfaMethod;
```

### 2.4 Optional Fields

Use `@IsOptional()` as the **first** decorator. When a property is optional, subsequent validators only run if the value is present (not `undefined` or `null`).

```typescript
import { IsOptional, IsString, MaxLength } from 'class-validator';

@IsOptional()
@IsString()
@MaxLength(200)
displayName?: string;
```

### 2.5 Boolean and Numeric Validators

```typescript
import { IsBoolean, IsInt, Min, Max } from 'class-validator';

@IsBoolean({ message: 'rememberMe must be a boolean.' })
rememberMe: boolean;

@IsInt({ message: 'Code must be an integer.' })
@Min(100000, { message: 'Code must be 6 digits.' })
@Max(999999, { message: 'Code must be 6 digits.' })
totpCode: number;
```

### 2.6 UUID Validation

```typescript
import { IsUUID } from 'class-validator';

@IsUUID('4', { message: 'Token must be a valid UUID v4.' })
token: string;
```

### 2.7 Array Validation

```typescript
import { IsArray, ArrayMinSize, ArrayMaxSize, IsString } from 'class-validator';

@IsArray()
@ArrayMinSize(1, { message: 'At least one role is required.' })
@ArrayMaxSize(10, { message: 'Cannot assign more than 10 roles.' })
@IsString({ each: true, message: 'Each role must be a string.' })
roles: string[];
```

The `each: true` option is critical -- it applies the validator to each element in the array rather than to the array itself.

---

## 3. Password Validation

### 3.1 Password Strength Requirements

For an authentication library, password validation is security-critical. Define a reusable custom decorator rather than scattering regex patterns across DTOs.

#### Recommended: `@IsStrongPassword` (class-validator ^0.14+)

```typescript
import { IsStrongPassword } from 'class-validator';

@IsStrongPassword(
  {
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1,
  },
  {
    message:
      'Password must be at least 8 characters and include uppercase, lowercase, number, and symbol.',
  },
)
password: string;
```

### 3.2 Custom Password Decorator (Project Standard)

Create a reusable decorator that reads strength requirements from the library's configuration. This is the **preferred** pattern in `@bymax-one/nest-auth`:

```typescript
// src/server/decorators/is-valid-password.decorator.ts

import {
  registerDecorator,
  ValidationOptions,
  ValidationArguments,
} from 'class-validator';

export interface PasswordPolicy {
  minLength: number;
  maxLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireDigit: boolean;
  requireSymbol: boolean;
}

export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireDigit: true,
  requireSymbol: true,
};

export function IsValidPassword(
  policy: Partial<PasswordPolicy> = {},
  validationOptions?: ValidationOptions,
) {
  const merged = { ...DEFAULT_PASSWORD_POLICY, ...policy };

  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'isValidPassword',
      target: object.constructor,
      propertyName,
      options: validationOptions,
      validator: {
        validate(value: unknown): boolean {
          if (typeof value !== 'string') return false;
          if (value.length < merged.minLength) return false;
          if (value.length > merged.maxLength) return false;
          if (merged.requireUppercase && !/[A-Z]/.test(value)) return false;
          if (merged.requireLowercase && !/[a-z]/.test(value)) return false;
          if (merged.requireDigit && !/\d/.test(value)) return false;
          if (merged.requireSymbol && !/[^A-Za-z0-9]/.test(value)) return false;
          return true;
        },
        defaultMessage(args: ValidationArguments): string {
          return `${args.property} does not meet the password policy requirements.`;
        },
      },
    });
  };
}
```

#### Usage in DTOs

```typescript
import { IsValidPassword } from '../decorators/is-valid-password.decorator';

export class RegisterDto {
  @IsValidPassword()
  password: string;
}

export class ResetPasswordDto {
  @IsUUID('4')
  token: string;

  @IsValidPassword()
  newPassword: string;
}
```

### 3.3 Password Confirmation Fields

When a DTO includes both `password` and `confirmPassword`, use a custom decorator that compares the two:

```typescript
import {
  registerDecorator,
  ValidationOptions,
  ValidationArguments,
} from 'class-validator';

export function Match(
  relatedProperty: string,
  validationOptions?: ValidationOptions,
) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'match',
      target: object.constructor,
      propertyName,
      constraints: [relatedProperty],
      options: validationOptions,
      validator: {
        validate(value: unknown, args: ValidationArguments): boolean {
          const related = (args.object as Record<string, unknown>)[
            args.constraints[0]
          ];
          return value === related;
        },
        defaultMessage(args: ValidationArguments): string {
          return `${args.property} must match ${args.constraints[0]}.`;
        },
      },
    });
  };
}
```

```typescript
export class ResetPasswordDto {
  @IsValidPassword()
  newPassword: string;

  @Match('newPassword', { message: 'Passwords do not match.' })
  confirmPassword: string;
}
```

---

## 4. Transformation

### 4.1 Core Concepts

class-transformer converts plain JavaScript objects (e.g., `req.body`) into typed class instances. This is triggered automatically by NestJS's `ValidationPipe` when `transform: true`.

### 4.2 `@Transform` Decorator

Use `@Transform` for inline transformations on individual properties:

```typescript
import { Transform } from 'class-transformer';

// Trim and lowercase email before validation
@Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase() : value)
@IsEmail({}, { message: 'A valid email address is required.' })
email: string;

// Trim whitespace from string inputs
@Transform(({ value }) => typeof value === 'string' ? value.trim() : value)
@IsString()
@IsNotEmpty()
displayName: string;
```

**Important:** `@Transform` runs BEFORE validation decorators. This means the transformed value is what gets validated. Always guard against unexpected types in the transform function.

### 4.3 `@Type` Decorator

Use `@Type` to specify the class for nested objects or to coerce primitives:

```typescript
import { Type } from 'class-transformer';

// Nested object typing
@Type(() => AddressDto)
@ValidateNested()
address: AddressDto;

// Date coercion (use sparingly -- prefer explicit transforms)
@Type(() => Date)
expiresAt: Date;
```

### 4.4 `@Exclude` and `@Expose`

Use these for **response serialization**, not for input DTOs. They control which properties appear in the serialized output when using `ClassSerializerInterceptor` or `instanceToPlain`.

```typescript
import { Exclude, Expose } from 'class-transformer';

export class UserResponseDto {
  @Expose()
  id: string;

  @Expose()
  email: string;

  @Expose()
  displayName: string;

  @Exclude()
  passwordHash: string;

  @Exclude()
  totpSecret: string;
}
```

### 4.5 `plainToInstance` and `instanceToPlain`

```typescript
import { plainToInstance, instanceToPlain } from 'class-transformer';

// Convert plain object to class instance (for manual validation outside pipes)
const dto = plainToInstance(RegisterDto, requestBody, {
  excludeExtraneousValues: false,
});

// Convert class instance to plain object (for responses)
const response = instanceToPlain(user, {
  excludePrefixes: ['_'],
});
```

### 4.6 Transformation Options Reference

| Option | Type | Default | Purpose |
|---|---|---|---|
| `excludeExtraneousValues` | `boolean` | `false` | Only keep `@Expose()`-decorated properties |
| `enableImplicitConversion` | `boolean` | `false` | Auto-convert types based on TS metadata |
| `exposeDefaultValues` | `boolean` | `false` | Include properties with default values in output |
| `groups` | `string[]` | `[]` | Only include properties matching these groups |
| `excludePrefixes` | `string[]` | `[]` | Exclude properties whose names start with these prefixes |
| `enableCircularCheck` | `boolean` | `false` | Prevent infinite loops with circular references |

### 4.7 Email Normalization Pattern (Project Standard)

All DTOs that accept an email field MUST normalize it:

```typescript
@Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase() : value)
@IsEmail({}, { message: 'A valid email address is required.' })
email: string;
```

This ensures consistent email comparison and storage. Apply this pattern in: `RegisterDto`, `LoginDto`, `ForgotPasswordDto`, `CreateInvitationDto`, and any other DTO accepting email input.

---

## 5. Custom Validators

### 5.1 Using `registerDecorator`

The simplest way to create a custom validator for a single-property check:

```typescript
import {
  registerDecorator,
  ValidationOptions,
  ValidationArguments,
} from 'class-validator';

export function IsNotDisposableEmail(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'isNotDisposableEmail',
      target: object.constructor,
      propertyName,
      options: {
        message: 'Disposable email addresses are not allowed.',
        ...validationOptions,
      },
      validator: {
        validate(value: unknown): boolean {
          if (typeof value !== 'string') return false;
          const domain = value.split('@')[1]?.toLowerCase();
          const disposableDomains = ['tempmail.com', 'throwaway.email', 'mailinator.com'];
          return !disposableDomains.includes(domain);
        },
      },
    });
  };
}
```

### 5.2 Using `ValidatorConstraint` (Class-Based)

For validators that need dependency injection or complex logic, use the class-based approach:

```typescript
import {
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
  Validate,
} from 'class-validator';

@ValidatorConstraint({ name: 'isTotpCode', async: false })
export class IsTotpCodeConstraint implements ValidatorConstraintInterface {
  validate(value: unknown, _args: ValidationArguments): boolean {
    if (typeof value !== 'string') return false;
    return /^\d{6}$/.test(value);
  }

  defaultMessage(_args: ValidationArguments): string {
    return 'TOTP code must be exactly 6 digits.';
  }
}
```

Apply it with `@Validate`:

```typescript
import { Validate } from 'class-validator';

export class MfaVerifyDto {
  @Validate(IsTotpCodeConstraint)
  code: string;
}
```

Or wrap it into a decorator for ergonomic reuse:

```typescript
import { registerDecorator, ValidationOptions } from 'class-validator';
import { IsTotpCodeConstraint } from './is-totp-code.constraint';

export function IsTotpCode(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsTotpCodeConstraint,
    });
  };
}
```

### 5.3 Async Validators

For validators that need to perform I/O (database checks, external API calls). Use with caution -- async validators run on every request and can introduce latency.

```typescript
@ValidatorConstraint({ name: 'isEmailUnique', async: true })
export class IsEmailUniqueConstraint implements ValidatorConstraintInterface {
  // Note: NestJS DI does NOT automatically inject into ValidatorConstraint classes.
  // You must use useContainer() -- see section 5.4.

  constructor(private readonly userService: UserService) {}

  async validate(email: string): Promise<boolean> {
    const user = await this.userService.findByEmail(email);
    return !user;
  }

  defaultMessage(): string {
    return 'Email is already registered.';
  }
}
```

### 5.4 Enabling NestJS Dependency Injection in Validators

By default, class-validator instantiates constraint classes with `new`. To enable NestJS DI:

```typescript
// In your main.ts or module setup
import { useContainer } from 'class-validator';
import { AppModule } from './app.module';

const app = await NestFactory.create(AppModule);
useContainer(app.select(AppModule), { fallbackOnErrors: true });
```

Then register the constraint as a provider in the module:

```typescript
@Module({
  providers: [IsEmailUniqueConstraint],
})
export class AuthModule {}
```

**Guidance for @bymax-one/nest-auth:** Since this is a library (not an application), document that consumers must call `useContainer()` in their bootstrap if they use async validators that require DI. Provide a setup helper or document it clearly.

### 5.5 Custom Validator File Organization

```
src/server/
  validators/
    is-totp-code.constraint.ts
    is-valid-password.validator.ts
    match.validator.ts
    is-not-disposable-email.validator.ts
  decorators/
    is-valid-password.decorator.ts
    is-totp-code.decorator.ts
    match.decorator.ts
```

Each validator constraint gets its own file. The corresponding decorator wrapper (if any) lives in the `decorators/` directory.

---

## 6. Validation Groups

### 6.1 Concept

Validation groups allow different validation rules to apply depending on the operation context. A property only gets validated if at least one of its groups matches the groups passed to the `validate()` call. If no groups are specified on a decorator, it runs in ALL contexts.

### 6.2 Defining Groups

Define group names as string constants to avoid typos:

```typescript
// src/server/constants/validation-groups.ts

export const ValidationGroup = {
  CREATE: 'create',
  UPDATE: 'update',
  ADMIN: 'admin',
  SELF: 'self',
} as const;

export type ValidationGroup = (typeof ValidationGroup)[keyof typeof ValidationGroup];
```

### 6.3 Applying Groups to Decorators

```typescript
import { IsNotEmpty, IsOptional, IsEmail, IsString } from 'class-validator';
import { ValidationGroup } from '../constants/validation-groups';

export class UserDto {
  @IsEmail({}, { groups: [ValidationGroup.CREATE], message: 'Email is required.' })
  email: string;

  @IsNotEmpty({ groups: [ValidationGroup.CREATE] })
  @IsOptional({ groups: [ValidationGroup.UPDATE] })
  @IsString()
  password: string;

  @IsOptional({ groups: [ValidationGroup.CREATE, ValidationGroup.UPDATE] })
  @IsString()
  displayName?: string;
}
```

### 6.4 Using Groups with ValidationPipe

```typescript
@Post()
@UsePipes(new ValidationPipe({ groups: [ValidationGroup.CREATE] }))
create(@Body() dto: UserDto) { ... }

@Patch(':id')
@UsePipes(new ValidationPipe({ groups: [ValidationGroup.UPDATE] }))
update(@Body() dto: UserDto) { ... }
```

### 6.5 Groups with class-transformer

class-transformer also supports groups for `@Expose`/`@Exclude`:

```typescript
export class UserResponseDto {
  @Expose({ groups: ['admin'] })
  internalId: string;

  @Expose()
  email: string;
}

// Serialization with groups
const result = instanceToPlain(user, { groups: ['admin'] });
```

### 6.6 When to Use Groups in @bymax-one/nest-auth

- **Invitation DTOs:** `CreateInvitationDto` requires `email` and `role`; `AcceptInvitationDto` requires `token` and `password` but not `email`.
- **Admin vs self-service operations:** Admin may create users without password (inviting), while self-registration always requires password.
- **Partial updates:** If a PATCH endpoint reuses the same DTO, `UPDATE` group decorators should use `@IsOptional`.

**Prefer separate DTOs over groups when the shapes are substantially different.** Groups work best when the same DTO is reused with minor conditional differences.

---

## 7. Nested Validation

### 7.1 Validating Nested Objects

Use `@ValidateNested()` combined with `@Type()` to validate nested objects:

```typescript
import { ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class OAuthProfileDto {
  @IsString()
  @IsNotEmpty()
  providerId: string;

  @IsString()
  @IsNotEmpty()
  providerUserId: string;

  @IsOptional()
  @IsEmail()
  email?: string;
}

export class PlatformLoginDto {
  @IsString()
  @IsNotEmpty()
  provider: string;

  @IsString()
  @IsNotEmpty()
  accessToken: string;

  @ValidateNested()
  @Type(() => OAuthProfileDto)
  profile: OAuthProfileDto;
}
```

**Critical:** Without `@Type(() => OAuthProfileDto)`, the nested object remains a plain object and validators on `OAuthProfileDto` will NOT run.

### 7.2 Validating Arrays of Nested Objects

```typescript
@ValidateNested({ each: true })
@Type(() => PermissionDto)
@IsArray()
@ArrayMinSize(1)
permissions: PermissionDto[];
```

The `{ each: true }` option tells `@ValidateNested` to validate every element in the array.

### 7.3 Optional Nested Objects

```typescript
@IsOptional()
@ValidateNested()
@Type(() => MfaSettingsDto)
mfaSettings?: MfaSettingsDto;
```

### 7.4 Deeply Nested Structures

class-validator validates nested objects recursively. If `OAuthProfileDto` itself contains a `@ValidateNested()` property, it will be validated too. Be cautious with deeply nested structures -- limit nesting depth to avoid performance issues. For `@bymax-one/nest-auth`, most DTOs should be flat with at most one level of nesting.

---

## 8. Security Considerations

### 8.1 Mandatory ValidationPipe Settings

These settings are **non-negotiable** for an authentication library:

```typescript
new ValidationPipe({
  whitelist: true,               // REQUIRED: strip undecorated properties
  forbidNonWhitelisted: true,    // REQUIRED: reject requests with extra properties
  transform: true,               // REQUIRED: enable class-transformer
  transformOptions: {
    enableImplicitConversion: false,  // REQUIRED: prevent type coercion attacks
  },
  validationError: {
    target: false,   // REQUIRED: never expose DTO class in error responses
    value: false,    // REQUIRED: never expose submitted values in error responses
  },
})
```

### 8.2 Why Each Setting Matters

**`whitelist: true`** -- Without this, an attacker can inject properties like `isAdmin: true` or `role: 'superadmin'` that bypass validation entirely and reach your service layer.

**`forbidNonWhitelisted: true`** -- Goes further than whitelist by actively rejecting the request (400 error) rather than silently stripping. This makes injection attempts visible in logs.

**`enableImplicitConversion: false`** -- When `true`, class-transformer auto-converts types based on TypeScript metadata. This can lead to unexpected coercions: `"true"` becomes `true`, `"0"` becomes `0`. In an auth context, this creates bypass vectors. Always convert explicitly with `@Transform`.

**`target: false` and `value: false`** -- Prevents leaking the DTO class name or the raw submitted value in error responses. Leaking values could expose passwords or tokens in API error responses.

### 8.3 Prototype Pollution Prevention

class-transformer's `plainToInstance` does NOT spread the source object's prototype. It creates a fresh class instance and copies properties. This is inherently safe against prototype pollution -- but only when using `plainToInstance`, not manual object spread.

**Never do this:**

```typescript
// DANGEROUS -- prototype pollution risk
const dto = Object.assign(new RegisterDto(), req.body);
```

**Always rely on the ValidationPipe or use:**

```typescript
const dto = plainToInstance(RegisterDto, req.body);
```

### 8.4 Rate Limiting and Validation

Validation runs before rate limiting in most NestJS setups. Since class-validator must parse the full request body, malformed requests still consume CPU. Pair with `@nestjs/throttler` (already a peer dependency) to protect validation endpoints.

### 8.5 Sensitive Field Handling

Never log or expose validated DTO instances that contain passwords or tokens:

```typescript
// WRONG -- leaks password to logs
this.logger.log('Registration attempt', dto);

// CORRECT -- omit sensitive fields
this.logger.log('Registration attempt', { email: dto.email });
```

### 8.6 Input Length Limits

Always apply `@MaxLength` to string fields to prevent memory exhaustion attacks:

```typescript
@IsString()
@MaxLength(255, { message: 'Email must not exceed 255 characters.' })
@IsEmail()
email: string;

@IsString()
@MaxLength(128, { message: 'Password must not exceed 128 characters.' })
@IsValidPassword()
password: string;

@IsString()
@MaxLength(2048, { message: 'Token must not exceed 2048 characters.' })
token: string;
```

Recommended upper bounds for this project:

| Field Type | Max Length |
|---|---|
| Email | 255 |
| Password | 128 |
| Display name | 200 |
| UUID token | 36 |
| JWT / opaque token | 2048 |
| TOTP code | 6 |
| Backup code | 20 |
| URL / redirect URI | 2048 |

---

## 9. Error Messages

### 9.1 Message Format Conventions

All custom validation messages in this project MUST follow these rules:

1. **Human-readable sentences** -- Start with uppercase, end with a period.
2. **Field-agnostic when possible** -- Use `$property` placeholder for reusable messages.
3. **No internal implementation details** -- Do not mention database columns, internal types, or class names.
4. **Consistent tone** -- Descriptive, not imperative. Prefer "Email is required." over "Enter your email."

### 9.2 Using Placeholders

class-validator supports `$property`, `$value`, `$target`, and `$constraint1`/`$constraint2` placeholders:

```typescript
@MinLength(8, { message: '$property must be at least $constraint1 characters.' })
// Outputs: "password must be at least 8 characters."
```

Available placeholders:

| Placeholder | Description |
|---|---|
| `$property` | The property name being validated |
| `$value` | The current value being validated |
| `$target` | The class name of the DTO |
| `$constraint1` | The first constraint parameter |
| `$constraint2` | The second constraint parameter |

**Security warning:** Do not use `$value` in messages for sensitive fields (passwords, tokens). The value would appear in the API error response.

### 9.3 Callback Messages

For dynamic messages based on validation context:

```typescript
@MinLength(8, {
  message: (args: ValidationArguments) => {
    return `${args.property} is too short. Minimum length is ${args.constraints[0]}, but you provided ${(args.value as string).length} characters.`;
  },
})
password: string;
```

**Note:** Avoid exposing `args.value` for sensitive fields. Use callback messages only when the additional context is safe to expose.

### 9.4 i18n Pattern

For internationalization, use message keys instead of hardcoded strings. The consuming application can then map these keys to localized strings:

```typescript
@IsEmail({}, { message: 'validation.email.invalid' })
email: string;

@MinLength(8, { message: 'validation.password.minLength' })
password: string;
```

Since `@bymax-one/nest-auth` is a library, support both patterns: provide a default English message but allow consumers to override via configuration or i18n message keys.

### 9.5 Error Response Structure

NestJS's `ValidationPipe` formats errors as:

```json
{
  "statusCode": 400,
  "message": [
    "A valid email address is required.",
    "Password must be at least 8 characters."
  ],
  "error": "Bad Request"
}
```

With `validationError.target: false` and `validationError.value: false`, no internal data leaks. Consumers can customize this shape with a custom exception filter.

---

## 10. Anti-Patterns

### 10.1 Missing `whitelist` and `forbidNonWhitelisted`

```typescript
// WRONG -- allows arbitrary property injection
app.useGlobalPipes(new ValidationPipe({ transform: true }));

// CORRECT
app.useGlobalPipes(
  new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }),
);
```

### 10.2 Using Interfaces Instead of Classes

```typescript
// WRONG -- interfaces are erased at runtime; no validation occurs
interface RegisterInput {
  email: string;
  password: string;
}

@Post('register')
register(@Body() input: RegisterInput) { ... }

// CORRECT -- classes carry runtime metadata for decorators
class RegisterDto {
  @IsEmail()
  email: string;

  @IsValidPassword()
  password: string;
}

@Post('register')
register(@Body() dto: RegisterDto) { ... }
```

### 10.3 Enabling `enableImplicitConversion`

```typescript
// WRONG -- implicit conversion can bypass validation
new ValidationPipe({
  transform: true,
  transformOptions: { enableImplicitConversion: true },
});

// CORRECT -- explicit transforms only
new ValidationPipe({
  transform: true,
  transformOptions: { enableImplicitConversion: false },
});

// Explicit conversion when needed
@Transform(({ value }) => value === 'true')
@IsBoolean()
rememberMe: boolean;
```

### 10.4 Forgetting `@Type` with `@ValidateNested`

```typescript
// WRONG -- nested object is a plain object; its decorators are NOT evaluated
@ValidateNested()
profile: OAuthProfileDto;

// CORRECT -- @Type ensures class-transformer instantiates the nested class
@ValidateNested()
@Type(() => OAuthProfileDto)
profile: OAuthProfileDto;
```

### 10.5 Decorating Properties Without Validation

```typescript
// WRONG -- property passes through without any validation
export class LoginDto {
  email: string;    // No decorators! Stripped by whitelist
  password: string; // No decorators! Stripped by whitelist
}

// CORRECT -- every property has at least one validator
export class LoginDto {
  @IsEmail({}, { message: 'A valid email address is required.' })
  email: string;

  @IsString()
  @IsNotEmpty({ message: 'Password is required.' })
  password: string;
}
```

### 10.6 Exposing `$value` in Error Messages for Sensitive Fields

```typescript
// WRONG -- leaks password in error response
@MinLength(8, { message: 'Password "$value" is too short.' })
password: string;

// CORRECT -- no value exposure
@MinLength(8, { message: 'Password must be at least 8 characters.' })
password: string;
```

### 10.7 Using `Object.assign` Instead of `plainToInstance`

```typescript
// WRONG -- bypasses class-transformer; prototype pollution risk
const dto = Object.assign(new RegisterDto(), rawBody);

// CORRECT -- safe transformation
const dto = plainToInstance(RegisterDto, rawBody);
```

### 10.8 Unguarded `@Transform` Functions

```typescript
// WRONG -- crashes if value is not a string
@Transform(({ value }) => value.trim().toLowerCase())
email: string;

// CORRECT -- type guard prevents runtime errors
@Transform(({ value }) => typeof value === 'string' ? value.trim().toLowerCase() : value)
email: string;
```

### 10.9 Missing `@MaxLength` on String Fields

```typescript
// WRONG -- no upper bound; attacker can send megabytes of data
@IsString()
@IsNotEmpty()
displayName: string;

// CORRECT -- bounded input
@IsString()
@IsNotEmpty()
@MaxLength(200, { message: 'Display name must not exceed 200 characters.' })
displayName: string;
```

### 10.10 Reusing DTOs Across Unrelated Endpoints

```typescript
// WRONG -- same DTO for register and password reset leads to confusion
export class AuthDto {
  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsString()
  password?: string;

  @IsOptional()
  @IsString()
  token?: string;
}

// CORRECT -- separate DTOs with precise shapes
export class RegisterDto {
  @IsEmail()
  email: string;

  @IsValidPassword()
  password: string;
}

export class ResetPasswordDto {
  @IsUUID('4')
  token: string;

  @IsValidPassword()
  newPassword: string;
}
```

---

## Quick Reference Checklist

Use this checklist when creating or reviewing any DTO in `@bymax-one/nest-auth`:

- [ ] **DTO is a class**, not an interface or type alias.
- [ ] **Every property** has at least one validation decorator.
- [ ] **Email fields** use `@Transform` for trim + lowercase, followed by `@IsEmail`.
- [ ] **Password fields** use `@IsValidPassword()` custom decorator.
- [ ] **All string fields** have `@MaxLength` with an appropriate upper bound.
- [ ] **Optional fields** use `@IsOptional()` as the first decorator.
- [ ] **Nested objects** use both `@ValidateNested()` and `@Type(() => ChildDto)`.
- [ ] **Array fields** use `{ each: true }` on element validators.
- [ ] **Error messages** are human-readable sentences, do not expose `$value` for sensitive fields.
- [ ] **No implicit conversion** -- `enableImplicitConversion` is `false`.
- [ ] **`@Transform` callbacks** include type guards (`typeof value === 'string'`).
- [ ] **ValidationPipe** uses `whitelist: true`, `forbidNonWhitelisted: true`.
- [ ] **`validationError.target`** and **`validationError.value`** are both `false`.
- [ ] **Sensitive fields** (passwords, tokens, secrets) are never logged or exposed in error messages.
- [ ] **Separate DTOs** for each distinct endpoint -- no overloaded "god DTOs."
- [ ] **Custom validators** are in `src/server/validators/` with decorator wrappers in `src/server/decorators/`.
- [ ] **File naming** follows `<name>.dto.ts` for DTOs, `<name>.validator.ts` for constraints, `<name>.decorator.ts` for decorator wrappers.
