# Draft upstream issue: `ap2.checkout_mandate` pattern rejects valid SD-JWT mandates

Target repository: https://github.com/Universal-Commerce-Protocol/ucp

Status: draft, not filed. Review before posting.

## Title

`payment_ap2_mandate.json`: `checkout_mandate` pattern rejects SD-JWT with key binding and the AP2 chained mandate form

## Summary

The `pattern` on `$defs.checkout_mandate` in `source/schemas/common/payment_ap2_mandate.json`
only allows non-empty base64url elements after the first `~`:

```text
^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+(~[A-Za-z0-9_-]+)*$
```

Because elements after the first `~` cannot contain `.` and cannot be empty, the pattern rejects
the serializations that the AP2 mandate format needs:

1. An SD-JWT with key binding (RFC 9901). The last element is a key-binding JWT, which contains
   two dots.
2. A serialized SD-JWT that ends in `~` (RFC 9901 section 4.3.1 defines the serialized form as
   `<Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~`).
3. The chained form in the Delegate SD-JWT draft, which requires "exactly one empty component
   between the last component of each SD-JWT or KB-SD-JWT and the following KB-SD-JWT" (a `~~`),
   and whose later links are JWTs containing dots.

The AP2 v0.2.0 documentation includes worked examples of this form
(`docs/ap2/checkout_mandate.md`, "Open Checkout Mandate chained with a Closed Checkout Mandate").
Those example tokens fail the UCP pattern.

Since the description of the field says it carries an "SD-JWT+kb credential", a conforming
mandate cannot pass schema validation for `complete` requests.

## Versions

- UCP release `v2026-08-25`, commit `cd78fb38e819de77d9b527d110476eccb876f1bd`
- AP2 `v0.2.0`, commit `b4587ac1d055888a73b4b21750973cffba961793`
- RFC 9901
- Delegate SD-JWT draft (`draft-ietf-oauth-delegate-sd-jwt`)

## Reproduction

Python, standard library only. The strings are shape-only placeholders. The first three are the
forms described above, the last is the shape the current pattern accepts.

```python
import re

pattern = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+(~[A-Za-z0-9_-]+)*$")

cases = {
    # issuer JWT ~ disclosure ~ key-binding JWT (RFC 9901 SD-JWT+KB)
    "sd-jwt+kb": "aGVhZA.cGF5bG9hZA.c2ln~ZGlzYzE~a2ho.a2Jw.a2ti",
    # issuer JWT ~ disclosure ~ (RFC 9901 serialized SD-JWT without key binding)
    "trailing tilde": "aGVhZA.cGF5bG9hZA.c2ln~ZGlzYzE~",
    # SD-JWT ~~ KB-SD-JWT ~ disclosure ~ (Delegate SD-JWT chain)
    "chain": "aGVhZA.cGF5bG9hZA.c2ln~ZGlzYzE~~a2ho.a2Jw.a2ti~ZGlzYzI~",
    # only what the current pattern accepts
    "no trailing tilde": "aGVhZA.cGF5bG9hZA.c2ln~ZGlzYzE~ZGlzYzI",
}
for name, value in cases.items():
    print(f"{name:18} matches: {bool(pattern.match(value))}")
```

Output with the current pattern:

```text
sd-jwt+kb          matches: False
trailing tilde     matches: False
chain              matches: False
no trailing tilde  matches: True
```

The same result holds for the three encoded tokens in the AP2 `checkout_mandate.md` examples.

## Expected

A mandate serialized as an SD-JWT with key binding, or as an AP2 chained mandate, passes the
schema.

## Suggested change

Allow dots and empty elements after the `~`:

```text
^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+(~[A-Za-z0-9._-]*)*$
```

This accepts all four cases above and still rejects values with spaces or characters outside
base64url, `.` and `~`. It is only a coarse shape check. Signature, disclosure, key-binding and
chain verification have to be done by an SD-JWT verifier, so another option is to relax the schema
to `type: string` with a `maxLength` and describe the format normatively.

## Related note

`docs/documentation/ucp-and-ap2.md` still uses the field names `checkoutSignature`,
`CheckoutMandate` and `PaymentMandate`, which differ from the extension specification
(`ap2.merchant_authorization`, `ap2.checkout_mandate`). It may be worth aligning.
