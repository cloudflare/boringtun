# YAT patches to boringtun 0.7.1

Source: the published `boringtun` 0.7.1 crate, upstream
<https://github.com/cloudflare/boringtun>, BSD-3-Clause. Original copyright
headers remain in the source. Both yat-wireguard and yat-network use this copy.

Local changes:

- `src/device/mod.rs`: update existing peer routing/endpoint/keepalive in place
  instead of panicking; rebuild destination routes after replacing AllowedIPs
  to recover prefixes shadowed by legacy overlapping relay routes. Changing a
  preshared key still replaces the cryptographic session.
- `src/device/peer.rs`: update routing metadata while preserving the Tunn,
  receiver index, counters and session keys; regression test with an established
  authenticated session and AllowedIPs handoff.
- `src/noise/timers.rs`: setter for persistent keepalive, used by peer updates.
- `src/device/api.rs`: reset parser state between peer sections and emit
  `last_handshake_time_sec/nsec` as Unix time, as required by the WireGuard UAPI.
- `src/lib.rs`: crate-level `#![allow(...)]` for `deprecated`,
  `mismatched_lifetime_syntaxes`, `unused_variables`, `dead_code`, silencing
  upstream diagnostics from `ring::constant_time::verify_slices_are_equal`,
  `base64::decode`, elided lifetimes on `Iter`/`LockReadGuard`/`Packet`, and
  feature-gated helpers (`fwmark`, `set_persistent_keepalive`, `KeyBytes`).
  Keeps the vendor tree close to upstream; API migrations are tracked
  separately.

No cryptographic algorithms or packet formats are changed. The timestamp fix
must ship with YAT's corresponding UAPI stats parser change. Rebuild the Agent
and privileged helper together; old running helper processes retain old code.

Run regression tests without creating an OS tunnel:

```sh
cargo test --manifest-path vendor/boringtun/Cargo.toml --features device --lib yat_
```
