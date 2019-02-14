# WireGuard by Cloudflare

This repository contains the [WireGuard](https://www.wireguard.com/) implementation used by Cloudflare's Warp, server and apps.

This crate contains two binaries:

* The library `cloudflare_cf` that can be used to implement fast and efficient WireGuard client apps on various platforms, including iOS and Android. It implements the underlying WireGuard protocol, without the network or tunnel stacks, those can be implemented in a platform idiomatic way.
* The executable `cloudflare-cf`, a [userspace](https://www.wireguard.com/xplatform/) WireGuard implementation for Linux and macOS.

### Building

- Library only: `cargo build --lib --release --target $(TARGET_TRIPLE)`
- Executable: `cargo build --release`

By default the executable is placed in the `./target/release` folder. You can copy it to `/usr/local/bin` or modify `PATH` accordingly.

In addition the repository contains benchmarks for the cryptographic primitives used by the library. You can run them using: `cargo run --release --example benchmarks`.

### Running

The recommended way to use the library is via Warp.

If you do wish to run the executable directly the command is:

`wireguard-cf [-f/--foreground] INTERFACE-NAME`

You can then configure it using [wg](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg.8).

Alternatively you can use [wg-quick](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg-quick.8) by setting the enviroment variable `WG_QUICK_USERSPACE_IMPLEMENTATION` to `wireguard-cf`. For example:

`sudo WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-cf wg-quick up CONF-FILE`

## Supported platforms

Target triple           |Binary|Library|                 |
------------------------|:----:|:-----:|-----------------|
x86_64-unknown-linux-gnu|  ✓   |   ✓   |FFI
x86_64-apple-darwin     |  ✓   |   ✓   |FFI
aarch64-apple-ios       |      |   ✓   |FFI
aarch64-linux-android   |      |   ✓   |JNI
x86_64-pc-windows-msvc  |      |   ✓   |FFI + C# bindings

#### Linux

Both `x86-64` and `aarch64` are supported. The behaviour should be identical to that of the Linux kernel module.

#### macOS

The behaviour is similar to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/). Specifically the interface name must be `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select the lowest available. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

---