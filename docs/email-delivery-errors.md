# Keeping delivery errors out of your logs

Part of the [`@bymax-one/nest-auth` README](../README.md), step 3 of the Quick Start.

**Never log the error your transport rejects with — it can contain the code you just sent.**
A policy, DLP or anti-spam relay answering `550` commonly **quotes the offending message body**,
so the error your `send()` throws carries the OTP or token this library rendered into it. Logging
that error, or attaching it as a `cause` to one you log, puts a working credential into your log
pipeline in clear text until it expires.

This is your half: the library cannot reach inside your provider implementation.
**`describeChannelStatus` is exported for it** — the same helper the bundled provider uses on
every one of its own log lines, so you get the whole treatment rather than just redaction:

```typescript
import { describeChannelStatus } from '@bymax-one/nest-auth'

async sendPasswordResetOtp(tenantId: string, email: string, otp: string): Promise<void> {
  try {
    await this.resend.emails.send({ /* ... */ })
  } catch (error: unknown) {
    // Never `logger.error(msg, error)` here, and never `new Error(msg, { cause: error })`
    // into something that logs — both carry the quoted body.
    this.logger.error(`reset OTP delivery failed: ${describeChannelStatus(error)}`)
    throw error
  }
}
```

Two functions, not one with a mode: which one you call IS the decision, and there is no
permissive default to inherit by forgetting.

**`describeChannelStatus(error)` wherever the body rendered something you would withhold.** It
takes no secrets, and that is the guarantee rather than an omission — nothing the channel wrote
is published, so there is nothing to name. Redaction alone does not close this, and neither does
a length cap. A relay may quote the body it rejected in transfer encoding rather
than verbatim; base64 is the ordinary case and defeats both at once — substring matching finds
nothing because the credential's characters are not in the line, and the cap does not help
because the encoding runs from the body's first byte, so the code is in the first sentence.
A reset-code body is 96 base64 characters end to end, and the first 200 characters of
the line decode straight back to the OTP. Under `describeChannelStatus` NOTHING the channel wrote
reaches the line — not the message, not the `name`, not a status parsed off the front. Validating a line's shape would admit `MTIzNDU2`, the base64 of
OTP `123456`, and a status grammar would admit `424-242`, an OTP grouped, publishing `424`. What you keep is which
message failed. What you lose is the transient-versus-permanent split, which your mail provider's
dashboard has and this library does not.

**`describeError(error, [values])` for errors whose text you have a reason to trust**, where the
values you name appear the way you wrote them and redaction reaches them. The bundled provider
uses it nowhere — every one of its paths uses the opaque form, including the notices that
render nothing secret, because a relay may re-encode whatever it quotes and the recipient address
is in the message either way. If you can say the same about your channel, prefer
`describeChannelStatus` and keep this one for strings you built yourself.

Neither reads `stack`, and neither reads the transport's own fields — nodemailer hangs the
server's full reply on `response`. Beyond that they differ, and the difference is the point:
`describeError` reads `name` and `message`, strips the values you named, caps the length and
removes control characters so a relay cannot forge extra records in a line-oriented pipeline.
`describeChannelStatus` reads **neither** — the only thing it touches is `cause`, walked to count
the links. Both walk that chain and never throw, whatever the transport's error does.

`redactSecrets(text, [otp])` is exported too, for a string you built yourself and know contains
the literal value. It is **not** a substitute for either description on a transport's error: a
substring match cannot see through an encoding, which is the whole reason the bundled provider
stopped relying on it.

If you use the bundled `DefaultAuthEmailProvider` with `onDeliveryError: 'rethrow'`, the error it
re-throws is the channel's original and is still yours to contain the same way.
