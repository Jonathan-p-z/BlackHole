# Threat model: `blackhole-cookies`

**Read this whole section before installing anything. It comes first on
purpose.**

## What this module technically does

`blackhole-cookies` runs a local HTTP/HTTPS proxy on your own machine
(bound to `127.0.0.1` only, never reachable from the network). To
inspect and modify cookies inside HTTPS traffic, it does the same thing
every HTTPS-inspecting corporate proxy, antivirus, and man-in-the-middle
attack tool does:

1. Your browser is configured to send its traffic through this local
   proxy.
2. For an HTTPS connection, the proxy terminates the TLS connection
   itself, presenting your browser with a certificate it generates
   on the fly for that site, signed by a root certificate authority
   (CA) this module generated on your machine.
3. Your browser accepts that certificate because you explicitly told it
   (via your OS or browser's certificate store) to trust this specific
   CA. This is the one manual step this module cannot do for you and
   will never do silently.
4. With TLS terminated, the proxy sees the plaintext HTTP request and
   response for that connection, on your machine, in your machine's
   memory, for as long as that one request takes.
5. It reads that plaintext only to check the destination domain against
   a known-tracker list and, for cookies belonging to a tracker domain,
   replace the cookie's value with a random one (see "How the
   randomization works" below).
6. It then re-encrypts the (possibly modified) traffic and forwards it
   to the real destination server, using a fresh, ordinary TLS
   connection your browser never sees the inside of.

At no point does any of this plaintext, or the CA's private key, leave
your machine. There is no server component, no remote logging endpoint,
and no code path that sends anything over the network except the
already-decrypted-then-re-encrypted request/response themselves, going
exactly where your browser asked them to go.

## Why this is different from spyware using the same mechanism

Everything above is also an accurate technical description of how a
malicious HTTPS-intercepting implant works. The mechanism is identical;
what makes this module trustworthy (or not) is everything around that
mechanism:

- **The code is open source and auditable.** Nothing here is obfuscated
  or compiled to hide what it does. Anyone, including you, can read
  every line that touches the decrypted traffic (`src/handler.rs` is
  the entire list of things this module does with your plaintext
  traffic: check the domain, maybe rewrite a cookie value, nothing
  else) and confirm it does only what this document says.
- **The CA and its private key are used only locally, and never leave
  this machine by any code path in this module.** They are generated
  here, stored here, and used here to sign certificates for connections
  this same local proxy is terminating. Nothing here uploads, syncs, or
  transmits them anywhere.
- **This module does not log or exfiltrate browsing data.** It does not
  write which domains you visited, which pages you loaded, or the
  content of your traffic to disk or anywhere else. The only persisted
  state is an aggregate counter (see "No browsing logs" below) and the
  CA material itself (which identifies this installation, not your
  browsing).
- **It only runs if you explicitly turn it on**, and it is never enabled
  by installing BlackHole. See "Mandatory safeguards" below for exactly
  what that means in practice.

None of this makes the underlying mechanism less powerful. It makes the
difference between a tool you control and a tool that controls you.

## What you MUST verify before installing the certificate

Installing a root CA certificate in your browser or OS trust store is a
significant decision: it means you're telling your system to trust
*any* certificate signed by that CA's private key, for *any* domain.
Before you do that for this module's CA, verify:

1. **The certificate fingerprint matches this build.** Every time
   `blackhole-cookies` generates or loads its CA, it prints the CA
   certificate's SHA-256 fingerprint (`blackhole-cookies ca-fingerprint`
   prints it on demand without starting the proxy). Compare that
   fingerprint against what you expect before trusting the certificate
   your OS/browser is about to show you when you import it. If they
   don't match, **do not install it**, and treat that machine as
   possibly having a different, unexpected CA in place, tampered
   binary, or a substituted certificate file.
2. **No other software on your machine has equivalent access to this
   CA's private key file.** The private key lives at
   `<per-user data dir>/blackhole-cookies/ca/hudsucker.key` (see
   "Where the CA lives" below for the exact path per platform) with
   the most restrictive file permissions this module can set. Anyone
   or anything that can read that file can do everything described in
   the next section. Check that no backup tool, sync client, or other
   process has a copy of that directory, and that the permissions
   actually applied (this module sets them; verify they held, e.g. no
   other user/group has read access on a shared machine).

If you cannot verify both of these, do not install the CA certificate.
The proxy itself is harmless with the CA uninstalled: it will run but
your browser will refuse every MITM'd HTTPS connection, so nothing
breaks, it simply won't intercept anything (see "Certificate pinning
and an uninstalled CA" under Limits).

## The explicit risk: this CA becomes a sensitive attack surface

This is the actual, concrete risk of running this module, stated
plainly rather than downplayed:

**Once you install this CA certificate, anyone or anything that gets
access to its private key file can decrypt (or forge) HTTPS traffic for
any site, for as long as your browser/OS still trusts that CA.** This
includes:

- Another process already running on your machine with permission to
  read that file (malware already present, a compromised application
  running as your user, or another user on a shared/multi-user machine
  if the file permissions are ever weaker than intended).
- Anyone with physical access to an unlocked or unencrypted machine.
- Anyone who gets a copy of that key file through a backup, a synced
  folder, or a stolen disk image, if full-disk encryption isn't in use.

This is not a hypothetical edge case; it is the literal, permanent
capability that installing this CA grants to whoever holds that key
file, and it does not go away when the proxy itself is stopped: the
capability lives in your browser/OS trust store and the key file on
disk, independent of whether `blackhole-cookies` is currently running.
**This is why "Uninstalling completely" (below) matters, and why this
module never installs its CA automatically.**

---

## What this protects

- **Long-term tracking via third-party cookies** set by known
  advertising/analytics trackers, specifically: a tracker cannot use a
  cookie value as a stable identifier across your randomization
  sessions (see "How the randomization works"), because the value it
  actually sees is randomized by this proxy, not the value it originally
  tried to set or the value your browser originally held.
- **Nothing about first-party cookies or the site you're actually
  visiting.** Only traffic to domains matched against the tracker list
  is touched at all; see "For everything else: pass through unchanged."

## Against what adversary

- **Third-party advertising/analytics trackers** correlating your
  activity across sites and over time via a stable cookie value, the
  same threat first-party isolation and cookie-blocking extensions
  target, approached differently here (randomize instead of block, so
  a site checking "is *some* cookie present" for a tracker's own script
  to load still works, rather than breaking outright).

## What this does NOT protect against

- **Fingerprinting that doesn't rely on cookies at all**: canvas
  fingerprinting, user-agent/header fingerprinting, screen
  resolution/timezone/font enumeration, and other passive signals a
  tracker can read regardless of cookie state. This module only ever
  touches cookie header values; it has no code path that changes any
  other part of a request or response. `blackhole-fingerprint` documents
  what this machine exposes along these lines; this module doesn't
  close that gap.
- **Sites with strict certificate pinning.** A site that pins its own
  certificate (rejecting any certificate not signed by the specific CA
  it expects, even a CA your OS trusts) will detect this proxy's
  substituted certificate and refuse the connection outright, the same
  way it would refuse any other MITM proxy or corporate inspection
  appliance. This is not a bug to fix; it's how certificate pinning is
  supposed to work, and it means some sites simply won't load while
  routed through this proxy for that specific host. There is no
  workaround that doesn't defeat the pinning check's own purpose, so
  none is attempted here.
- **First-party tracking** (a site tracking you directly via its own
  cookies, not a third party's). Explicitly out of scope: this module
  only touches domains on the third-party tracker list.
- **Anything once a tracker receives data through channels other than
  cookies** (a fingerprinting script's own network calls carrying data
  in the URL/body rather than a cookie header, e.g.). This module reads
  cookie headers specifically, nothing else in the request/response
  body.
- **A compromised machine.** See "The explicit risk" above; this module
  assumes the machine it runs on isn't already compromised, the same
  trust boundary every other BlackHole module assumes (see the root
  README).

## How the randomization works

Only domains matched against the tracker list (see "Tracker list" below)
are touched at all. For those domains:

- On an outgoing `Cookie:` request header, or an incoming `Set-Cookie:`
  response header, each cookie's **value** (never its name, and never
  any other attribute: `Path`, `Domain`, `Expires`, `Max-Age`, `Secure`,
  `HttpOnly`, `SameSite` all pass through unchanged) is looked up in an
  in-memory table keyed by `(domain, cookie name)`.
- The first time a given `(domain, cookie name)` pair is seen, in either
  direction, a new random value is generated and recorded for it.
- Every subsequent time that same pair is seen, in either direction, for
  the rest of this proxy run, the same recorded random value is used
  again.

This is deliberately **per proxy run, not per request**: a site (or the
tracker's own script) that checks a cookie's value is still the same
across several requests in one browsing session keeps working, because
it is, for as long as this proxy keeps running. What changes is that the
value a tracker ever actually sees is never the value it itself set or
the value your browser originally held; it's this module's own random
substitute, and a fresh one is generated the next time you start the
proxy (a new "session" in the sense this module means it: restarting
`blackhole-cookies` is what draws the boundary, not browser tabs or
individual page loads, which this module has no visibility into from
the network layer alone).

## For everything else: pass through unchanged

Any domain not matched against the tracker list, including the site you
are actually visiting, is proxied exactly as-is: no header is inspected
beyond checking the destination domain, no cookie is touched, nothing is
delayed or altered. The intercept-and-inspect step only happens for
connections to a tracker-list domain in the first place; connections to
every other domain still get TLS-terminated-and-reencrypted by the proxy
mechanically (that's how any MITM proxy handles every connection it
carries), but this module's own logic never reads or changes anything in
them.

## Tracker list

Domains come from a local file you provide, in a small subset of the
AdBlock/EasyList filter syntax (`||domain.tld^` lines; see
`src/tracker_list.rs`'s module doc for exactly what's supported and
what's deliberately not). This module does not invent, maintain, or
bundle its own list of tracker domains: point it at a real,
community-maintained list such as
[EasyPrivacy](https://easylist.to/easylist/easyprivacy.txt) or
[uBlock Origin's own filter lists](https://github.com/uBlockOrigin/uAssets),
downloaded and updated by you. There is no bundled default list and no
automatic download: an unconfigured tracker list means the proxy runs
in pure pass-through mode, touching nothing, until you point it at one.

This module implements only the plain-domain-blocking subset of the
EasyList filter syntax, not the full filter language (no cosmetic
filters, no regex rules, no `$` options beyond being ignored, no
exception/allowlist rules). A real EasyPrivacy file will parse with most
of its rules recognized and the rest silently skipped as
not-a-plain-domain-rule; this is a deliberate, documented scope
reduction, not a bug, since implementing the complete AdBlock filter
grammar is a separate, much larger undertaking (see
`adblock-rust`/`uBlock Origin`'s own engines for that).

## Mandatory safeguards

- **Disabled by default, always.** Installing or building BlackHole
  never enables this module. It only starts when you explicitly run
  `blackhole-cookies enable` (or, once wired into it, `blackhole cookies
  enable`), and only after you've separately installed the CA
  certificate; enabling the proxy without an installed CA means it
  simply won't intercept anything, but never opens by itself.
- **A clear, always-available off switch.** `blackhole-cookies disable`
  (or `blackhole cookies disable`) stops the proxy immediately. There is
  no mode where this module intercepts traffic without the proxy
  process actually running.
- **No browsing logs, ever, even locally.** This module never writes
  which domains you visited, which cookies existed, or any content of
  your traffic to disk, memory beyond the current request's processing,
  or anywhere else. The only thing persisted across runs is an aggregate
  daily counter (e.g. "37 cookies randomized today"; see
  `src/stats.rs`), which records a count only, never a domain, a cookie
  name, or a value. If you want to confirm this yourself: `grep` this
  crate's source for anything that writes to a file or any string
  formatting that includes a domain or cookie name outside of an
  in-memory `HashMap` key comparison; there is no logging sink in this
  module beyond `stats.rs`'s single counter file.

## Where the CA lives, and uninstalling completely

The CA certificate and private key live at your platform's per-user
data directory for `blackhole-cookies` (via the `directories` crate,
matching `blackhole-fingerprint`'s own convention for its history file):

- Linux: `~/.local/share/blackhole-cookies/ca/`
- Windows: `%APPDATA%\blackhole-cookies\ca\`

Two files: `hudsucker.cer` (the CA certificate, safe to view, this is
what you check the fingerprint of) and `hudsucker.key` (the private key;
treat this like any other private key on your system). The private key
file is created with owner-only permissions on Unix
(`std::fs::Permissions` mode `0600`) immediately after being written.

**To uninstall completely:**

1. Remove the CA from your OS/browser trust store (exact steps vary by
   platform/browser; search your browser's or OS's certificate manager
   for the certificate named in `hudsucker.cer`'s subject, and delete or
   distrust it there).
2. Stop the proxy if it's running (`blackhole-cookies disable`).
3. Delete the CA directory listed above (both files). If you skip step 1
   before doing this, your OS/browser keeps trusting the now-deleted
   CA's fingerprint until you separately remove it from the trust store;
   deleting the key file here does not retroactively revoke trust
   already granted. Do step 1 first.
4. Optionally, also remove your browser's/OS's proxy configuration
   pointing at `127.0.0.1` if you changed it to use this proxy (this
   module does not change that setting for you; see the module's own
   setup instructions for how you configured it in the first place).

After this, no trace of this module's CA remains anywhere that could be
used to decrypt anything, on this machine or any other.
