# Detection gaps: things worth catching that are easy to miss

A backlog of weaknesses that are cheap to overlook and expensive to ship. This
is a listing, not a plan: no implementation here, just "what it is" and "the
tell" a static pass could key on. Ordered roughly by how often it bites in the
wild. Items themob already covers in some form are marked (partial).

## 0. The one that prompted this: public cloud links

An app that serves user files from cloud storage through links that anyone with
the URL can open. The owner treats them as private because they are
unguessable, but an unguessable URL is a password written on the asset, not
access control.

How a static pass can flag it (it cannot prove the bucket ACL without the
network, so these are high-signal heuristics, not proof):

- Capability URLs embedded or constructed in code. Firebase Storage download
  URLs of the form `.../o/<path>?alt=media&token=<uuid>` where the token ships
  in the app or is built from an embedded value: the token is the access, so a
  shipped token is a public link.
- Presigned S3 or GCS URLs carrying `X-Amz-Signature` / `Signature` + `Expires`,
  especially a far-future or absent expiry, or the signing key present to mint
  them on device.
- Direct object URLs with no auth on the request that uses them:
  `*.s3.amazonaws.com`, `storage.googleapis.com`, `*.blob.core.windows.net`,
  `firebasestorage.googleapis.com`, `*.r2.dev`, where the fetch attaches no
  Authorization header and no per-user token.
- Bucket roots or listing URLs referenced at all (a sign the app browses a
  bucket rather than a per-user keyed API).

Verdict wording should stay honest: "references a cloud object URL that appears
to grant access by possession of the link; verify the object or bucket is not
world-readable." themob already extracts endpoints (partial), so this is mostly
a URL-shape classifier on top of what it has.

## A. Backend and cloud exposure

1. Open Firebase Realtime DB or Firestore: a `*.firebaseio.com` URL where
   appending `/.json` would dump the tree (rules left open). The URL is the tell.
2. Firebase config that enables anonymous or self sign-up, or Storage abuse
   (apiKey + projectId + appId shipped together). (partial: keys found)
3. Backend URLs pointing at dev or staging or internal hosts in a release build:
   `10.*`, `192.168.*`, `*.internal`, `*.ngrok.io`, `localhost`, raw IPs.
4. GraphQL endpoint with introspection assumed on; unauthenticated REST routes
   constructed in code.
5. Hardcoded cloud credentials beyond generic API keys: AWS access-key-id plus
   secret, GCP service-account JSON, Azure SAS tokens, Stripe or Twilio or
   SendGrid secret keys. (partial: high-entropy plus some patterns)
6. Client that trusts a self-supplied role or entitlement header
   (`X-User-Role: admin`, `isPremium=true` in the request body).
7. Google API key with no Android app restriction (billable, abusable at your
   expense). (partial: key found, restriction state not assessed)

## B. Deep links, intents, IPC (the richest seam of small-but-serious)

8. Exported activity, service, or receiver reachable by any app. (partial:
   manifest)
9. Deep-link or App-Link handler that reads a URL param and loads it into a
   WebView or an HTTP client without validation (open redirect, token theft).
10. Intent redirection, the confused deputy: an exported component that does
    `startActivity((Intent) getParcelableExtra("extra_intent"))` or forwards a
    supplied PendingIntent, launching arbitrary components with app privileges.
11. Exported ContentProvider or FileProvider with path traversal, or
    `grantUriPermissions` exposing internal files.
12. Mutable `PendingIntent` (the pre-Android-12 default) handed to another app.
13. Sensitive data sent via `sendBroadcast` with no receiver permission or
    package, readable system-wide.
14. Custom URL scheme with no verification, hijackable by another app that
    registers the same scheme; App Links `autoVerify` missing.

## C. WebView

15. `addJavascriptInterface` exposing a Java object to web content that is not
    fully trusted (script to native bridge).
16. `setJavaScriptEnabled(true)` combined with loading remote or
    intent-supplied URLs.
17. `setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs`
    or `setAllowFileAccess(true)` (local file theft, file URL XSS).
18. `onReceivedSslError` that calls `handler.proceed()` (TLS errors ignored in
    the WebView).
19. `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)`.
20. Deprecated `UIWebView`, or `WKWebView` with file access from file URLs (iOS).

## D. Transport and TLS

21. Custom `TrustManager` or `HostnameVerifier` that accepts everything (TLS
    validation disabled). A perennial top real-world bug.
22. `ALLOW_ALL_HOSTNAME_VERIFIER` or `SSLSocketFactory.ALLOW_ALL` (legacy Apache).
23. Android cleartext traffic allowed: `usesCleartextTraffic="true"`, or a
    network security config permitting `http` or adding user CAs
    (`<certificates src="user">`). (partial: iOS ATS done; Android NSC not)
24. No certificate pinning on sensitive endpoints, or pinning with a wildcard
    backup that defeats it (weaker signal).
25. Explicitly enabling SSLv3, TLS 1.0, or weak cipher suites.

## E. Crypto misuse (beyond the ECB mode it already flags)

26. Hardcoded symmetric key or IV; static or zero IV with CBC. (partial: ECB)
27. Weak key derivation: `PBEKeySpec` with low iterations or no salt; a key set
    to the MD5 or SHA-1 of a constant.
28. `java.util.Random` (not `SecureRandom`) for tokens or keys; `SecureRandom`
    seeded with a constant.
29. RSA with PKCS#1 v1.5 padding rather than OAEP; textbook RSA.
30. AES-GCM nonce reuse; a constant salt in a KDF.
31. Keys kept in SharedPreferences or files when the Keystore is available and
    unused.

## F. Local data at rest

32. Secrets or PII written to SharedPreferences, or to plaintext files on
    external storage.
33. SQLite holding sensitive data with no encryption (SQLCipher absent).
34. Logging secrets, PII, or whole authenticated request and response pairs
    (`Log.d(TAG, token)`). (partial: dataflow touches logging sinks)
35. `allowBackup="true"` with no `fullBackupContent` exclusions, so the secret
    rides into a cloud backup. (partial: flag surfaced, egress not reasoned)
36. Secret fields without `inputType=textPassword` or `textNoSuggestions` (the
    keyboard caches them); copying a secret to the clipboard.
37. Sensitive screens without `FLAG_SECURE` (recents thumbnail, screen record).
38. Tapjacking: sensitive controls without `filterTouchesWhenObscured`.

## G. Auth, session, tokens

39. JWT: `alg=none` accepted; signature unverified on the client; long-lived
    tokens with no rotation; token stored insecurely.
40. OAuth: implicit flow, or a public client with no PKCE; a redirect URI that
    is not validated (custom-scheme hijack).
41. Biometric or keyguard gate not bound to a Keystore key
    (`setUserAuthenticationRequired`), so it is a UI check a hook bypasses.
42. Hardcoded test or backdoor credentials, or a skip-login debug path shipped
    in release.

## H. Build and configuration hygiene

43. `debuggable="true"` in release (done). Plus `BuildConfig.DEBUG` branches
    that enable insecure behaviour, and leftover test endpoints behind a flag.
44. StrandHogg: `taskAffinity`, `launchMode`, or `allowTaskReparenting` enabling
    task hijacking.
45. `minSdkVersion` low enough that insecure platform defaults apply (old WebView
    file-access defaults, implicit-broadcast behaviour).
46. Native `.so` libraries with known-CVE versions baked in (OpenSSL, ffmpeg,
    sqlite, libpng). Dependency scanners miss what is statically linked.
    (partial: SBOM covers packaged deps, not embedded native versions)
47. Over-broad permissions against need: `READ_SMS`, `MANAGE_EXTERNAL_STORAGE`,
    `QUERY_ALL_PACKAGES`, background location.
48. A custom permission guarding a sensitive action declared `normal` instead of
    `signature`, so any app can request it.

## I. Native, anti-tamper, dynamic code

49. Android `.so` lacking RELRO, stack canary, or PIE. (partial: iOS Mach-O
    hardening done; Android ELF not)
50. Dynamic code loading: `DexClassLoader` or `loadDex` from external storage or
    the network (a remote code execution surface).
51. `System.loadLibrary` or `load` of a library from writable storage
    (injection).
52. `Runtime.exec` or `ProcessBuilder` with attacker-influenced input;
    reflection onto hidden or privileged APIs.

## J. Privacy and silent data egress

53. Analytics, ad, or attribution SDKs shipping PII, device IDs, or location to
    third parties the developer forgot were wired in.
54. Collection of advertising ID, Android ID, IMEI, MAC, or IMSI.
55. PII or tokens placed in URL query strings (logged by servers, proxies, CDNs).
56. Crash reporters (Crashlytics, Sentry) capturing requests that carry auth
    headers or user content.

## K. iOS-specific, where the Android path has a counterpart it lacks

57. `NSAllowsArbitraryLoads` or weakened ATS exceptions. (partial: ATS surfaced)
58. General `UIPasteboard` leaking sensitive values across apps.
59. Keychain items with `kSecAttrAccessibleAlways` rather than a ThisDeviceOnly
    accessibility class.
60. Missing Data Protection entitlement; files written without
    `NSFileProtectionComplete`.
61. Universal Links or associated-domains not validated; custom scheme hijack.
62. Jailbreak checks absent or trivially hookable (weaker signal).

---

Cross-cutting note: several of these (public links, open Firebase, intent
redirection, WebView bridges) are reachability stories, not single-line
patterns. They want the thing themob is already built around: a URL or an
exported entry point as a source, and a sink reached from it. That is where the
graph and the now-bounded dataflow pass have the most room to grow.
