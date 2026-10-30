/**
 * @fileoverview The request-body schemas of every DTO this library declares, compiled into the
 * bundle so the OpenAPI contributor can hand them to the document builder.
 *
 * GENERATED from the DTOs' class-validator metadata and identical to
 * `conformance/openapi-request-schemas.json`. Do not edit by hand: run `pnpm gen:openapi-schemas`
 * and review the diff. `request-schemas.conformance.spec.ts` fails when this file differs from
 * what the decorators produce.
 *
 * @layer OpenAPI
 */
import type { DerivedObjectSchema } from '../derive-request-schemas'

/** Request-body schemas keyed by DTO class name; OpenAPI 3.0. */
export const REQUEST_SCHEMAS: Readonly<Record<string, DerivedObjectSchema>> = {
  "AcceptInvitationDto": {
    "type": "object",
    "properties": {
      "token": {
        "type": "string",
        "minLength": 64,
        "maxLength": 64
      },
      "name": {
        "type": "string",
        "minLength": 2,
        "maxLength": 100
      },
      "password": {
        "type": "string",
        "minLength": 8,
        "maxLength": 128
      }
    },
    "required": [
      "name",
      "password",
      "token"
    ]
  },
  "ChangeEmailDto": {
    "type": "object",
    "properties": {
      "newEmail": {
        "type": "string",
        "maxLength": 255,
        "minLength": 1,
        "format": "email"
      },
      "currentPassword": {
        "type": "string",
        "maxLength": 128,
        "minLength": 1
      }
    },
    "required": [
      "currentPassword",
      "newEmail"
    ]
  },
  "ChangePasswordDto": {
    "type": "object",
    "properties": {
      "currentPassword": {
        "type": "string",
        "maxLength": 128,
        "minLength": 1
      },
      "newPassword": {
        "type": "string",
        "maxLength": 128,
        "minLength": 8
      },
      "refreshToken": {
        "type": "string",
        "maxLength": 512
      }
    },
    "required": [
      "currentPassword",
      "newPassword"
    ]
  },
  "ConfirmEmailChangeDto": {
    "type": "object",
    "properties": {
      "token": {
        "type": "string",
        "minLength": 64,
        "maxLength": 64
      }
    },
    "required": [
      "token"
    ]
  },
  "CreateInvitationDto": {
    "type": "object",
    "properties": {
      "email": {
        "type": "string",
        "maxLength": 255,
        "minLength": 1,
        "format": "email"
      },
      "role": {
        "type": "string",
        "maxLength": 64,
        "minLength": 1
      },
      "tenantName": {
        "type": "string",
        "maxLength": 128,
        "minLength": 1
      }
    },
    "required": [
      "email",
      "role"
    ]
  },
  "ForgotPasswordDto": {
    "type": "object",
    "properties": {
      "email": {
        "type": "string",
        "maxLength": 255,
        "format": "email"
      },
      "tenantId": {
        "type": "string",
        "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
        "maxLength": 128,
        "minLength": 1
      }
    },
    "required": [
      "email"
    ]
  },
  "LoginDto": {
    "type": "object",
    "properties": {
      "email": {
        "type": "string",
        "maxLength": 255,
        "format": "email"
      },
      "password": {
        "type": "string",
        "maxLength": 128,
        "minLength": 1
      },
      "tenantId": {
        "type": "string",
        "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
        "maxLength": 128,
        "minLength": 1
      }
    },
    "required": [
      "email",
      "password"
    ]
  },
  "MfaChallengeDto": {
    "type": "object",
    "properties": {
      "mfaTempToken": {
        "type": "string",
        "maxLength": 512,
        "minLength": 1
      },
      "code": {
        "type": "string",
        "maxLength": 29,
        "minLength": 1,
        "pattern": "^(\\d{6}|[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})$"
      }
    },
    "required": [
      "code"
    ]
  },
  "MfaDisableDto": {
    "type": "object",
    "properties": {
      "code": {
        "type": "string",
        "minLength": 1,
        "pattern": "^\\d{6}$",
        "maxLength": 6
      }
    },
    "required": [
      "code"
    ]
  },
  "MfaRegenerateRecoveryCodesDto": {
    "type": "object",
    "properties": {
      "code": {
        "type": "string",
        "minLength": 1,
        "pattern": "^\\d{6}$",
        "maxLength": 6
      }
    },
    "required": [
      "code"
    ]
  },
  "MfaSetupDto": {
    "type": "object",
    "properties": {
      "password": {
        "type": "string",
        "maxLength": 128,
        "minLength": 1
      }
    },
    "required": []
  },
  "MfaVerifyDto": {
    "type": "object",
    "properties": {
      "code": {
        "type": "string",
        "minLength": 1,
        "pattern": "^\\d{6}$",
        "maxLength": 6
      }
    },
    "required": [
      "code"
    ]
  },
  "OAuthCallbackQueryDto": {
    "type": "object",
    "properties": {
      "code": {
        "type": "string",
        "maxLength": 2048,
        "minLength": 1
      },
      "error": {
        "type": "string",
        "maxLength": 128
      },
      "error_description": {
        "type": "string",
        "maxLength": 512
      },
      "error_uri": {
        "type": "string",
        "maxLength": 512
      },
      "state": {
        "type": "string",
        "maxLength": 128,
        "minLength": 1
      },
      "iss": {
        "type": "string",
        "maxLength": 512
      },
      "scope": {
        "type": "string",
        "maxLength": 2048
      },
      "authuser": {
        "type": "string",
        "maxLength": 16
      },
      "prompt": {
        "type": "string",
        "maxLength": 64
      },
      "hd": {
        "type": "string",
        "maxLength": 253
      }
    },
    "required": [
      "state"
    ]
  },
  "OAuthInitiateQueryDto": {
    "type": "object",
    "properties": {
      "tenantId": {
        "type": "string",
        "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
        "maxLength": 128,
        "minLength": 1
      }
    },
    "required": []
  },
  "PlatformLoginDto": {
    "type": "object",
    "properties": {
      "email": {
        "type": "string",
        "maxLength": 255,
        "minLength": 1,
        "format": "email"
      },
      "password": {
        "type": "string",
        "maxLength": 128,
        "minLength": 1,
        "pattern": "\\S"
      }
    },
    "required": [
      "email",
      "password"
    ]
  },
  "RegisterDto": {
    "type": "object",
    "properties": {
      "email": {
        "type": "string",
        "maxLength": 255,
        "format": "email"
      },
      "password": {
        "type": "string",
        "maxLength": 128,
        "minLength": 8
      },
      "name": {
        "type": "string",
        "maxLength": 128,
        "minLength": 2
      },
      "tenantId": {
        "type": "string",
        "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
        "maxLength": 128,
        "minLength": 1
      }
    },
    "required": [
      "email",
      "name",
      "password"
    ]
  },
  "ResendOtpDto": {
    "type": "object",
    "properties": {
      "email": {
        "type": "string",
        "maxLength": 255,
        "format": "email"
      },
      "tenantId": {
        "type": "string",
        "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
        "maxLength": 128,
        "minLength": 1
      }
    },
    "required": [
      "email"
    ]
  },
  "ResendVerificationDto": {
    "type": "object",
    "properties": {
      "email": {
        "type": "string",
        "maxLength": 255,
        "format": "email"
      },
      "tenantId": {
        "type": "string",
        "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
        "maxLength": 128,
        "minLength": 1
      }
    },
    "required": [
      "email"
    ]
  },
  "ResetPasswordDto": {
    "type": "object",
    "properties": {
      "email": {
        "type": "string",
        "maxLength": 255,
        "format": "email"
      },
      "newPassword": {
        "type": "string",
        "maxLength": 128,
        "minLength": 8
      },
      "token": {
        "type": "string",
        "maxLength": 2048,
        "minLength": 1
      },
      "otp": {
        "type": "string",
        "minLength": 4,
        "maxLength": 8
      },
      "verifiedToken": {
        "type": "string",
        "minLength": 64,
        "maxLength": 64
      },
      "tenantId": {
        "type": "string",
        "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
        "maxLength": 128,
        "minLength": 1
      }
    },
    "required": [
      "email",
      "newPassword"
    ]
  },
  "RevokeInvitationDto": {
    "type": "object",
    "properties": {
      "email": {
        "type": "string",
        "maxLength": 255,
        "minLength": 1,
        "format": "email"
      }
    },
    "required": [
      "email"
    ]
  },
  "VerifyEmailDto": {
    "type": "object",
    "properties": {
      "email": {
        "type": "string",
        "maxLength": 255,
        "format": "email"
      },
      "otp": {
        "type": "string",
        "minLength": 6,
        "maxLength": 6
      },
      "tenantId": {
        "type": "string",
        "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
        "maxLength": 128,
        "minLength": 1
      }
    },
    "required": [
      "email",
      "otp"
    ]
  },
  "VerifyOtpDto": {
    "type": "object",
    "properties": {
      "email": {
        "type": "string",
        "maxLength": 255,
        "format": "email"
      },
      "otp": {
        "type": "string",
        "minLength": 4,
        "maxLength": 8
      },
      "tenantId": {
        "type": "string",
        "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
        "maxLength": 128,
        "minLength": 1
      }
    },
    "required": [
      "email",
      "otp"
    ]
  }
}
