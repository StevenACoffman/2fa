# 2fa

> **This is a fork of [rsc/2fa](https://github.com/rsc/2fa)** by Russ Cox.
> It adds `2fa -export` for moving keys to another authenticator app, along
> with lint, CI, and release tooling. Report problems with this fork here, not
> upstream.

2fa is a two-factor authentication agent.

Usage:

```text
go install github.com/StevenACoffman/2fa@latest

2fa -add [-7] [-8] [-hotp] name
2fa -list
2fa [-clip] name
2fa -export name
```

`2fa -add name` adds a new key to the 2fa keychain with the given name. It
prints a prompt to standard error and reads a two-factor key from standard
input. Two-factor keys are short case-insensitive strings of letters A-Z and
digits 2-7.

By default the new key generates time-based (TOTP) authentication codes; the
`-hotp` flag makes the new key generate counter-based (HOTP) codes instead.

By default the new key generates 6-digit codes; the `-7` and `-8` flags select
7- and 8-digit codes instead.

`2fa -list` lists the names of all the keys in the keychain.

`2fa name` prints a two-factor authentication code from the key with the
given name. If `-clip` is specified, `2fa` also copies the code to the system
clipboard.

`2fa -export name` prints the key `name` as an `otpauth://` URI in
the [Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format),
for importing into another authenticator app:

```text
$ 2fa -export github
otpauth://totp/github:github?secret=NZXXIIDBEBVWK6JB&issuer=github
```

The name is used as both the issuer and the account name, so names containing a
colon cannot be exported. The URI contains the secret itself, so treat it like
the keychain file.

With no arguments, `2fa` prints two-factor authentication codes from all
known time-based keys.

The default time-based authentication codes are derived from a hash of the
key and the current time, so it is important that the system clock have at
least one-minute accuracy.

The keychain is stored unencrypted in the text file `$HOME/.2fa`.

## Example

During GitHub 2FA setup, at the “Scan this barcode with your app” step,
click the “enter this text code instead” link. A window pops up showing
“your two-factor secret,” a short string of letters and digits.

Add it to 2fa under the name github, typing the secret at the prompt:

```text
$ 2fa -add github
2fa key for github: nzxxiidbebvwk6jb
$
```

Then whenever GitHub prompts for a 2FA code, run 2fa to obtain one:

```text
$ 2fa github
268346
$
```

Or to type less:

```text
$ 2fa
268346	github
$
```
