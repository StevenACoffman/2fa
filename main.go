// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// 2fa is a two-factor authentication agent.
//
// Usage:
//
//	2fa -add [-7] [-8] [-hotp] name
//	2fa -list
//	2fa [-clip] name
//	2fa -export name
//
// “2fa -add name” adds a new key to the 2fa keychain with the given name.
// It prints a prompt to standard error and reads a two-factor key from standard input.
// Two-factor keys are short case-insensitive strings of letters A-Z and digits 2-7.
//
// By default the new key generates time-based (TOTP) authentication codes;
// the -hotp flag makes the new key generate counter-based (HOTP) codes instead.
//
// By default the new key generates 6-digit codes; the -7 and -8 flags select
// 7- and 8-digit codes instead.
//
// “2fa -list” lists the names of all the keys in the keychain.
//
// “2fa name” prints a two-factor authentication code from the key with the
// given name. If “-clip” is specified, 2fa also copies the code to the system
// clipboard.
//
// “2fa -export name” prints the key with the given name as an otpauth:// URI
// (for example, otpauth://totp/name:name?secret=SECRET&issuer=name), suitable
// for importing into another authenticator app. Keys with names containing
// a colon cannot be exported.
//
// With no arguments, 2fa prints two-factor authentication codes from all
// known time-based keys.
//
// The default time-based authentication codes are derived from a hash of
// the key and the current time, so it is important that the system clock have
// at least one-minute accuracy.
//
// The keychain is stored unencrypted in the text file $HOME/.2fa.
//
// # Example
//
// During GitHub 2FA setup, at the “Scan this barcode with your app” step,
// click the “enter this text code instead” link. A window pops up showing
// “your two-factor secret,” a short string of letters and digits.
//
// Add it to 2fa under the name github, typing the secret at the prompt:
//
//	$ 2fa -add github
//	2fa key for github: nzxxiidbebvwk6jb
//	$
//
// Then whenever GitHub prompts for a 2FA code, run 2fa to obtain one:
//
//	$ 2fa github
//	268346
//	$
//
// Or to type less:
//
//	$ 2fa
//	268346	github
//	$
package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HOTP and TOTP are defined as HMAC-SHA1 (RFC 4226, RFC 6238)
	"encoding/base32"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/atotto/clipboard"
)

const counterLen = 20

// errUsage reports a command line that does not match any usage form.
// The usage message has already been printed.
var errUsage = errors.New("usage")

// options holds the command-line flags.
type options struct {
	add, list, hotp, seven, eight, clip, export bool
}

// Keychain is the set of keys stored in the keychain file.
type Keychain struct {
	file string
	data []byte
	keys map[string]Key
}

// Key is a single two-factor key.
type Key struct {
	raw    []byte
	digits int
	offset int // offset of counter
}

func main() {
	err := run(os.Args[1:], os.Getenv("HOME"), os.Stdin, os.Stdout, os.Stderr)
	if errors.Is(err, errUsage) {
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "2fa: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, home string, stdin io.Reader, stdout, stderr io.Writer) error {
	opts, names, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}
	if !opts.valid(len(names)) {
		usage(stderr)
		return errUsage
	}

	k, err := readKeychain(filepath.Join(home, ".2fa"), stderr)
	if err != nil {
		return err
	}
	if opts.list {
		return k.list(stdout)
	}
	if len(names) == 0 {
		return k.showAll(stdout)
	}
	return runKey(k, opts, names[0], stdin, stdout, stderr)
}

// runKey adds, exports, or shows the key with the given name.
func runKey(
	k *Keychain,
	opts options,
	name string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		return errors.New("name must not contain spaces")
	}
	switch {
	case opts.add:
		digits, err := opts.digits()
		if err != nil {
			return err
		}
		return k.add(name, digits, opts.hotp, stdin, stderr)
	case opts.export:
		return k.export(name, stdout)
	default:
		return k.show(name, opts.clip, stdout)
	}
}

func parseFlags(args []string, stderr io.Writer) (options, []string, error) {
	var opts options
	flags := flag.NewFlagSet("2fa", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { usage(stderr) }
	flags.BoolVar(&opts.add, "add", false, "add a key")
	flags.BoolVar(&opts.list, "list", false, "list keys")
	flags.BoolVar(&opts.hotp, "hotp", false, "add key as HOTP (counter-based) key")
	flags.BoolVar(&opts.seven, "7", false, "generate 7-digit code")
	flags.BoolVar(&opts.eight, "8", false, "generate 8-digit code")
	flags.BoolVar(&opts.clip, "clip", false, "copy code to the clipboard")
	flags.BoolVar(&opts.export, "export", false, "print key as an otpauth:// URI")
	if err := flags.Parse(args); err != nil {
		// The flag package has already reported the error and printed the usage.
		return opts, nil, errUsage
	}
	return opts, flags.Args(), nil
}

func usage(w io.Writer) {
	fmt.Fprint(w, "usage:\n"+
		"\t2fa -add [-7] [-8] [-hotp] keyname\n"+
		"\t2fa -list\n"+
		"\t2fa [-clip] keyname\n"+
		"\t2fa -export keyname\n")
}

// valid reports whether the flags can be used with nargs key names.
func (o options) valid(nargs int) bool {
	switch {
	case o.list:
		return nargs == 0
	case nargs == 0 && !o.add:
		return !o.clip && !o.export
	case nargs != 1:
		return false
	case o.add:
		return !o.clip && !o.export
	default:
		return !o.clip || !o.export
	}
}

// digits returns the code length selected by the -7 and -8 flags.
func (o options) digits() (int, error) {
	switch {
	case o.seven && o.eight:
		return 0, errors.New("cannot use -7 and -8 together")
	case o.seven:
		return 7, nil
	case o.eight:
		return 8, nil
	default:
		return 6, nil
	}
}

// readKeychain reads the keychain file, reporting malformed keys to warn.
// A missing file is an empty keychain.
func readKeychain(file string, warn io.Writer) (*Keychain, error) {
	c := &Keychain{
		file: file,
		keys: make(map[string]Key),
	}
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading keychain: %w", err)
	}
	c.data = data

	start := 0
	for i, line := range bytes.SplitAfter(data, []byte("\n")) {
		text := bytes.TrimSuffix(line, []byte("\n"))
		if len(text) > 0 {
			name, k, ok := parseKey(text)
			if !ok {
				fmt.Fprintln(warn, "2fa: "+file+":"+strconv.Itoa(i+1)+": malformed key")
			} else {
				if k.offset != 0 {
					k.offset += start
				}
				c.keys[name] = k
			}
		}
		start += len(line)
	}
	return c, nil
}

// parseKey parses a keychain line of the form "name digits key [counter]".
// For a counter-based key, the returned offset is the counter's offset within text.
func parseKey(text []byte) (string, Key, bool) {
	var k Key
	f := bytes.Split(text, []byte(" "))
	if len(f) != 3 && len(f) != 4 {
		return "", k, false
	}
	if len(f[1]) != 1 || f[1][0] < '6' || '8' < f[1][0] {
		return "", k, false
	}
	k.digits = int(f[1][0] - '0')
	raw, err := decodeKey(string(f[2]))
	if err != nil {
		return "", k, false
	}
	k.raw = raw
	if len(f) == 4 {
		if len(f[3]) != counterLen {
			return "", k, false
		}
		if _, err := strconv.ParseUint(string(f[3]), 10, 64); err != nil {
			return "", k, false
		}
		k.offset = len(text) - counterLen
	}
	return string(f[0]), k, true
}

func (c *Keychain) list(w io.Writer) error {
	var names []string
	for name := range c.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := fmt.Fprintln(w, name); err != nil {
			return fmt.Errorf("writing key list: %w", err)
		}
	}
	return nil
}

func noSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}

// add prompts on stderr for a key read from stdin and appends it to the keychain.
func (c *Keychain) add(
	name string,
	digits int,
	hotp bool,
	stdin io.Reader,
	stderr io.Writer,
) error {
	fmt.Fprint(stderr, "2fa key for "+name+": ")
	text, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading key: %w", err)
	}
	text = strings.Map(noSpace, text)
	text += strings.Repeat("=", -len(text)&7) // pad to 8 bytes
	if _, err := decodeKey(text); err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}

	line := fmt.Sprintf("%s %d %s", name, digits, text)
	if hotp {
		line += " " + strings.Repeat("0", counterLen)
	}
	line += "\n"
	// Start a new line if the file's last line was not terminated,
	// rather than appending the key onto it.
	if len(c.data) > 0 && c.data[len(c.data)-1] != '\n' {
		line = "\n" + line
	}

	f, err := os.OpenFile(c.file, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("opening keychain: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("opening keychain: %w", err)
	}
	if _, err := f.WriteString(line); err != nil {
		_ = f.Close()
		return fmt.Errorf("adding key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("adding key: %w", err)
	}
	return nil
}

// lookup returns the key with the given name.
func (c *Keychain) lookup(name string) (Key, error) {
	k, ok := c.keys[name]
	if !ok {
		return k, fmt.Errorf("no such key %q", name)
	}
	return k, nil
}

// counter returns the current counter of the counter-based key k.
func (c *Keychain) counter(name string, k Key) (uint64, error) {
	text := c.data[k.offset : k.offset+counterLen]
	n, err := strconv.ParseUint(string(text), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("malformed key counter for %q (%q)", name, text)
	}
	return n, nil
}

// nextCounter increments the counter of the counter-based key k
// in the keychain file and returns the new value.
func (c *Keychain) nextCounter(name string, k Key) (uint64, error) {
	n, err := c.counter(name, k)
	if err != nil {
		return 0, err
	}
	n++
	f, err := os.OpenFile(c.file, os.O_RDWR, 0o600)
	if err != nil {
		return 0, fmt.Errorf("opening keychain: %w", err)
	}
	if _, err := f.WriteAt(
		fmt.Appendf(nil, "%0*d", counterLen, n),
		int64(k.offset),
	); err != nil {
		_ = f.Close()
		return 0, fmt.Errorf("updating keychain: %w", err)
	}
	if err := f.Close(); err != nil {
		return 0, fmt.Errorf("updating keychain: %w", err)
	}
	return n, nil
}

func (c *Keychain) code(name string) (string, error) {
	k, err := c.lookup(name)
	if err != nil {
		return "", err
	}
	var code int
	if k.offset != 0 {
		n, err := c.nextCounter(name, k)
		if err != nil {
			return "", err
		}
		code = hotp(k.raw, n, k.digits)
	} else {
		// Time-based key.
		code = totp(k.raw, time.Now(), k.digits)
	}
	return fmt.Sprintf("%0*d", k.digits, code), nil
}

func (c *Keychain) show(name string, clip bool, w io.Writer) error {
	code, err := c.code(name)
	if err != nil {
		return err
	}
	if clip {
		if err := clipboard.WriteAll(code); err != nil {
			return fmt.Errorf("copying code to clipboard: %w", err)
		}
	}
	if _, err := fmt.Fprintln(w, code); err != nil {
		return fmt.Errorf("writing code: %w", err)
	}
	return nil
}

// export prints the key with the given name as an otpauth:// URI,
// the format used by authenticator apps to import keys.
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
// The key name is used as both the issuer and the account name.
func (c *Keychain) export(name string, w io.Writer) error {
	k, err := c.lookup(name)
	if err != nil {
		return err
	}
	// Neither issuer nor account name may contain a colon,
	// not even URL-encoded, since it separates them in the label.
	if strings.Contains(name, ":") {
		return fmt.Errorf("cannot export key %q: name must not contain a colon", name)
	}

	typ := "totp"
	params := []string{
		"secret=" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(k.raw),
		"issuer=" + uriEscape(name),
	}
	// The Key URI Format only allows 6 or 8 digits, but many apps accept 7,
	// and omitting it would make them generate the wrong codes.
	if k.digits != 6 {
		params = append(params, "digits="+strconv.Itoa(k.digits))
	}
	if k.offset != 0 {
		n, err := c.counter(name, k)
		if err != nil {
			return err
		}
		// code increments the counter before use, so the next code uses n+1.
		typ = "hotp"
		params = append(params, "counter="+strconv.FormatUint(n+1, 10))
	}
	label := uriEscape(name) + ":" + uriEscape(name)
	uri := "otpauth://" + typ + "/" + label + "?" + strings.Join(params, "&")
	if _, err := fmt.Fprintln(w, uri); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}
	return nil
}

// uriEscape escapes s for use in an otpauth URI label or parameter,
// percent-encoding everything except RFC 3986 unreserved characters.
func uriEscape(s string) string {
	// QueryEscape leaves only unreserved characters unescaped,
	// but encodes space as "+" rather than "%20".
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func (c *Keychain) showAll(w io.Writer) error {
	var names []string
	width := 0
	for name, k := range c.keys {
		names = append(names, name)
		width = max(width, k.digits)
	}
	sort.Strings(names)
	for _, name := range names {
		k := c.keys[name]
		code := strings.Repeat("-", k.digits)
		if k.offset == 0 {
			var err error
			if code, err = c.code(name); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%-*s\t%s\n", width, code, name); err != nil {
			return fmt.Errorf("writing codes: %w", err)
		}
	}
	return nil
}

func decodeKey(key string) ([]byte, error) {
	b, err := base32.StdEncoding.DecodeString(strings.ToUpper(key))
	if err != nil {
		return nil, fmt.Errorf("decoding key: %w", err)
	}
	return b, nil
}

func hotp(key []byte, counter uint64, digits int) int {
	h := hmac.New(sha1.New, key)
	h.Write(binary.BigEndian.AppendUint64(nil, counter))
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func totp(key []byte, t time.Time, digits int) int {
	return hotp(key, uint64(t.UnixNano())/30e9, digits)
}
