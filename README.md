![boringtun logo banner](./banner.png)

# BoringTun

[![crates.io](https://meritbadge.herokuapp.com/boringtun)](https://crates.io/crates/boringtun)

**BoringTun** is an implementation of the [WireGuard<sup>®</sup>](https://www.wireguard.com/) protocol designed for portability and speed.

**BoringTun** is successfully deployed on millions of [iOS](https://apps.apple.com/us/app/1-1-1-1-faster-internet/id1423538627) and [Android](https://play.google.com/store/apps/details?id=com.cloudflare.onedotonedotonedotone&hl=en_US) consumer devices as well as thousands of Cloudflare Linux servers. 

The project consists of two parts:

* The executable `boringtun`, a [userspace WireGuard](https://www.wireguard.com/xplatform/) implementation for Linux and macOS.
* The library `boringtun` that can be used to implement fast and efficient WireGuard client apps on various platforms, including iOS and Android. It implements the underlying WireGuard protocol, without the network or tunnel stacks, those can be implemented in a platform idiomatic way.

### Installation

You can install this project using `cargo`:

```
cargo install boringtun
```

### Building

- Library only: `cargo build --lib --no-default-features --release [--target $(TARGET_TRIPLE)]`
- Executable: `cargo build --bin boringtun --release [--target $(TARGET_TRIPLE)]`

By default the executable is placed in the `./target/release` folder. You can copy it to a desired location manually, or install it using `cargo install --bin boringtun --path .`.

### Running

As per the specification, to start a tunnel use:

`boringtun [-f/--foreground] INTERFACE-NAME`

The tunnel can then be configured using [wg](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg.8), as a regular WireGuard tunnel, or any other tool.

It is also possible to use with [wg-quick](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg-quick.8) by setting the environment variable `WG_QUICK_USERSPACE_IMPLEMENTATION` to `boringtun`. For example:

`sudo WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun WG_SUDO=1 wg-quick up CONFIGURATION`

### Testing

Testing this project has a few requirements:

- `sudo`: required to create tunnels. When you run `cargo test` you'll be prompted for your password.
- Docker: you can install it [here](https://www.docker.com/get-started). If you are on Ubuntu/Debian you can run `apt-get install docker.io`.

### Benchmarking

To benchmark this project you can run this command:

```
cargo +nightly bench
```

This command depends on the unstable `test` feature of the Rust compiler. As a result, you'll need to use the `nightly` channel of Rust when you run it.

## Supported platforms

Target triple                 |Binary|Library|                 |
------------------------------|:----:|:-----:|-----------------|
x86_64-unknown-linux-gnu      |  ✓   |   ✓   |[![Build Status](https://dev.azure.com/cloudflare-ps/wireguard-cf/_apis/build/status/cloudflare.boringtun?branchName=master&jobName=Linux%20armv7)](https://dev.azure.com/cloudflare-ps/wireguard-cf/_build/latest?definitionId=4&branchName=master)
aarch64-unknown-linux-gnu     |  ✓   |   ✓   |[![Build Status](https://dev.azure.com/cloudflare-ps/wireguard-cf/_apis/build/status/cloudflare.boringtun?branchName=master&jobName=Linux%20aarch64)](https://dev.azure.com/cloudflare-ps/wireguard-cf/_build/latest?definitionId=4&branchName=master)
armv7-unknown-linux-gnueabihf |  ✓   |   ✓   |[![Build Status](https://dev.azure.com/cloudflare-ps/wireguard-cf/_apis/build/status/cloudflare.boringtun?branchName=master&jobName=Linux%20armv7)](https://dev.azure.com/cloudflare-ps/wireguard-cf/_build/latest?definitionId=4&branchName=master)
x86_64-apple-darwin           |  ✓   |   ✓   |[![Build Status](https://dev.azure.com/cloudflare-ps/wireguard-cf/_apis/build/status/cloudflare.boringtun?branchName=master&jobName=macOS)](https://dev.azure.com/cloudflare-ps/wireguard-cf/_build/latest?definitionId=4&branchName=master)
x86_64-pc-windows-msvc        |      |   ✓   |[![Build Status](https://dev.azure.com/cloudflare-ps/wireguard-cf/_apis/build/status/cloudflare.boringtun?branchName=master&jobName=Windows)](https://dev.azure.com/cloudflare-ps/wireguard-cf/_build/latest?definitionId=4&branchName=master)
aarch64-apple-ios             |      |   ✓   |FFI bindings
armv7-apple-ios               |      |   ✓   |FFI bindings
armv7s-apple-ios              |      |   ✓   |FFI bindings
aarch64-linux-android         |      |   ✓   |JNI bindings
arm-linux-androideabi         |      |   ✓   |JNI bindings

<sub>Other platforms may be added in the future</sub>

#### Linux

`x86-64`, `aarch64` and `armv7` architectures are supported. The behaviour should be identical to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/), with the following difference:

`boringtun` will drop privileges when started. When privileges are dropped it is not possible to set `fwmark`. If `fwmark` is required, such as when using `wg-quick`, instead running with `sudo`, give the executable the `CAP_NET_ADMIN` capability using: `sudo setcap cap_net_admin+epi boringtun`. Alternatively run with `--disable-drop-privileges` or set the environment variable `WG_SUDO=1`.

#### macOS

The behaviour is similar to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/). Specifically the interface name must be `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select the lowest available. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

---

#### FFI bindings

The library exposes a set of C ABI bindings, those are defined in the `wireguard_ffi.h` header file. The C bindings can be used with C/C++, Swift (using a bridging header) or C# (using [DLLImport](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.dllimportattribute?view=netcore-2.2) with [CallingConvention](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.dllimportattribute.callingconvention?view=netcore-2.2) set to `Cdecl`).

#### JNI bindings

The library exposes a set of Java Native Interface bindings, those are defined in `src/jni.rs`.

## License

The project is licensed under the [3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the 3-Clause BSD License, shall licensed as above, without any additional terms or conditions.

If you want to contribute to this project, please read our [`CONTRIBUTING.md`].

[`CONTRIBUTING.md`]: https://github.com/cloudflare/.github/blob/master/CONTRIBUTING.md

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. BoringTun is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub></sub></sub>
