# Windows port (experimental, source only)

The Rust command-line tool (`Native/GreenBubbles`) builds for Windows. No
Windows binary is released, nothing here has been run on a Windows machine yet,
and the Swift app, key capture and send helper are macOS-only. Treat this page
as a status report for contributors, not as support.

## What is in place

- **One platform layer.** `src/platform.rs` holds every operating-system
  difference: file modes and ownership, `O_NOFOLLOW`-style opens, free disk
  space, process termination, and the home directory. On Unix each item is the
  original `std`/`libc` call, so macOS behavior is unchanged.
- **Portable locking.** Advisory `flock` calls became `File::lock`,
  `lock_shared`, `try_lock` and `unlock` from the standard library, which use
  `LockFileEx` on Windows. Windows locks are mandatory: read a locked file only
  through the handle that holds the lock.
- **Windows data directory.** The default live-source search also looks in
  `%USERPROFILE%\Documents\xwechat_files`. If WeChat stores accounts elsewhere,
  set `source.root` in `.greenbubbles\config.toml`.
- **Build features.** On Windows `rusqlite` uses
  `bundled-sqlcipher-vendored-openssl` (needs Perl and a C compiler to build
  OpenSSL), and `wx-media` is built without `audio`, so voice notes stay SILK
  because `silk-rs` fails to build with current Windows headers.

Checked by cross-compiling the library, binaries and examples for
`x86_64-pc-windows-gnu` with no warnings, and by the unchanged Linux test suite.

## What is weaker or missing on Windows

| Area | Unix behavior | Windows today |
| --- | --- | --- |
| Owner-only checks (`mode & 0o077`) | Rejects files other users can access | Always passes. Files rely on the ACL inherited from the user profile, which is private by default. The ACL is not inspected. |
| Ownership (`uid`) | Must equal the effective user | Not checked. |
| Hard links (`nlink`) | Must be 1 | Reported as 1, not checked. |
| File identity (`dev`/`ino`) | Detects replacement while reading | Approximated by creation time; `ctime` by write time. |
| `connector serve` / socket client | Unix domain socket, owner-only | Returns an error. |
| Integration tests in `tests/` | Run | Compiled out (`#![cfg(unix)]`); many assume POSIX modes and sockets. |
| Key capture (`greenbubbles-acquire`) | LLDB on a re-signed WeChat | Not ported. Supply an existing key file. |
| V2 image key | Derived from `config.ini` and the account directory | Unverified; the Windows client may need a key from process memory. |
| Voice transcoding | SILK to Ogg Opus (needs `ffmpeg`) | Disabled. |
| Send path | Locked to dry run | Not ported. |

## Suggested next steps

1. Run the CLI against a real Windows account with a key you already hold, and
   confirm the database parameters in `wx-decrypt` (`MACOS_4_1_7_31`) match.
2. Replace the three approximations above with real checks using
   `windows-sys`: owner SID and ACL via `GetSecurityInfo`, hard-link count and
   file index via `GetFileInformationByHandle`.
3. Add a Windows CI job (`cargo test` for the library) and decide how the
   integration tests should be split between Unix and Windows.
4. Decide separately whether to build key acquisition for Windows. It means
   reading another process's memory and carries legal and account-safety risks
   that the macOS tool's guide already discusses.
