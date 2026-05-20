# Signal Backup V2 Helper

This is a small Node.js helper for inspecting, validating, and merging Signal local backup v2 snapshots. It was written for the current Signal Desktop/Android backup-v2 layout, where a backup archive looks like this:

```text
SignalBackups/
  files/
    00/
    01/
    ...
  signal-backup-yyyy-mm-dd-hh-mm-ss/
    main
    metadata
    files
```

The script source is [`backup-v2-raw.mjs`](./backup-v2-raw.mjs). It is plain JavaScript using Node's ES module format; there is no build step and no npm package install.

## What It Does

- decrypts and summarizes a local backup snapshot using its passphrase
- validates that all media listed in a snapshot exists under the archive `files/` directory
- validates basic recipient/chat/media references after decrypting `main`
- optionally validates frames with Signal's native `libsignal-client` validator
- merges an older snapshot into a newer snapshot and writes a new snapshot encrypted with the newer backup passphrase

The merge keeps the newer backup's account/metadata identity, remaps old recipients and chats into the newer ID space, deduplicates exact chat items, skips references to missing media files, and copies referenced media from both inputs.

## Requirements

- Node.js 22 or newer
- for `official-validate`, an installed Signal Desktop copy is needed unless you provide a path to a compatible native `@signalapp+libsignal-client.node`

## Commands

```text
node backup-v2-raw.mjs summary <snapshotDir> <passphraseFile>
node backup-v2-raw.mjs check-files <snapshotDir>
node backup-v2-raw.mjs check-refs <snapshotDir> <passphraseFile>
node backup-v2-raw.mjs check-media-refs <snapshotDir> <passphraseFile>
node backup-v2-raw.mjs official-validate <snapshotDir> <passphraseFile> [nativeLibsignalNodePath]
node backup-v2-raw.mjs merge <oldSnapshotDir> <oldPassphraseFile> <newSnapshotDir> <newPassphraseFile> <outBaseDir>
```

All input and output paths are command-line arguments. The only built-in path is the default lookup used by `official-validate` on Windows:

```text
%LOCALAPPDATA%\Programs\signal-desktop\resources\app.asar.unpacked\node_modules\@signalapp\libsignal-client\prebuilds\win32-x64\@signalapp+libsignal-client.node
```

You can override that by passing `[nativeLibsignalNodePath]`.

## Example Merge

PowerShell:

```powershell
node backup-v2-raw.mjs merge `
  backups\old\signal-backup-2026-05-19-17-04-43 old-passphrase.txt `
  backups\new\signal-backup-2026-05-19-17-30-38 new-passphrase.txt `
  merged\SignalBackups
```

Bash:

```bash
node backup-v2-raw.mjs merge \
  backups/old/signal-backup-2026-05-19-17-04-43 old-passphrase.txt \
  backups/new/signal-backup-2026-05-19-17-30-38 new-passphrase.txt \
  merged/SignalBackups
```

The output directory should then contain:

```text
merged/
  SignalBackups/
    files/
    signal-backup-yyyy-mm-dd-hh-mm-ss/
      main
      metadata
      files
```

The generated backup uses the newer backup's passphrase, so restore it with `<newPassphraseFile>`.

## Validation

After merging, validate the generated snapshot path printed by the merge command:

```bash
node backup-v2-raw.mjs summary merged/SignalBackups/signal-backup-yyyy-mm-dd-hh-mm-ss backups/new/passphrase.txt
node backup-v2-raw.mjs check-files merged/SignalBackups/signal-backup-yyyy-mm-dd-hh-mm-ss
node backup-v2-raw.mjs check-refs merged/SignalBackups/signal-backup-yyyy-mm-dd-hh-mm-ss backups/new/passphrase.txt
node backup-v2-raw.mjs check-media-refs merged/SignalBackups/signal-backup-yyyy-mm-dd-hh-mm-ss backups/new/passphrase.txt
node backup-v2-raw.mjs official-validate merged/SignalBackups/signal-backup-yyyy-mm-dd-hh-mm-ss backups/new/passphrase.txt
```

`official-validate` prints the native library path it used and exits non-zero if Signal's validator reports frame errors.

## Android Restore Layout

When restoring on Android, make sure `files` and `signal-backup-yyyy-mm-dd-hh-mm-ss` folders are inside a folder named `SignalBackups`.

Example:

```text
Documents/
  SignalBackups/
    files/
    signal-backup-yyyy-mm-dd-hh-mm-ss/
```

Signal Android rejects the backup if the parent folder is not named `SignalBackups`.

## Current Limitations

- This is a recovery tool, not a polished CLI.
- It assumes the current Signal backup-v2 protobuf field layout.
- It does not fetch dependencies or install anything.
- It does not modify the original input backups.
- Future Signal versions may change the backup schema, so always run the validation commands before relying on output. Tested 19th of May 2026
- Could work with group chats, but it is not tested.
