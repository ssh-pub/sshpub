# SSH Pub

SSH Pub is a lightweight SSH public key management and distribution tool.

Website: https://sshpub.com

```sh
sshpub add alice
```

This downloads Alice's public keys from SSH Pub, validates them locally,
deduplicates them, and writes the missing keys to `~/.ssh/authorized_keys`.
Private keys always stay on the user's own devices.

## Install

```sh
curl -fsSL https://sshpub.com/install.sh | sh
```

By default, the installer places `sshpub` in `/usr/local/bin`.

To install somewhere else:

```sh
curl -fsSL https://sshpub.com/install.sh | \
  SSHPUB_INSTALL_DIR="$HOME/.local/bin" sh
```

## Usage

Add all default keys for a user:

```sh
sshpub add alice
```

Add selected device keys:

```sh
sshpub add alice/pc
sshpub add alice/pc,iphone
```

Add public keys from GitHub or GitLab:

```sh
sshpub add github/alice
sshpub add gitlab/alice
```

Remove SSH Pub-managed keys from local `authorized_keys`:

```sh
sshpub remove alice/pc
```

Remove prompts before changing `authorized_keys`. Use `-y` or `--yes` for
non-interactive scripts:

```sh
sshpub remove github/alice --yes
```

List keys:

```sh
sshpub list
```

Show the installed version:

```sh
sshpub version
```

Check for an available upgrade:

```sh
sshpub upgrade
```

Official SSH Pub release binaries can use `sshpub upgrade` to check for SSH Pub
release updates. External source or package builds should be upgraded using the
same method used to install them.

## How It Works

`sshpub add alice` downloads public keys from SSH Pub and prepares a safe update
to `~/.ssh/authorized_keys`.

`sshpub add github/alice` and `sshpub add gitlab/alice` download public SSH keys
from the public GitHub and GitLab APIs. These commands add missing keys only;
they do not remove local keys that are no longer present upstream.

Before writing anything, the CLI:

- Parses and validates every returned SSH public key.
- Rejects `authorized_keys` options and OpenSSH certificates.
- Verifies SSH Pub key comments.
- Ensures the server does not return keys for devices that were not requested.
- Deduplicates keys by parsed public key identity.

For SSH Pub device keys, adding the same `user/device` updates the existing
managed key when the device has rotated to a new public key. Existing local keys
with the same public key body are never duplicated or rewritten.

If any returned key is invalid, the operation fails and `authorized_keys` is left
unchanged.

## Security

SSH Pub only handles SSH public keys.

The CLI does not:

- Read, upload, or store private keys.
- Run an agent or daemon.
- Modify `sshd_config`.
- Log in to servers.
- Become a dependency in the SSH login path.
- Collect telemetry.
- Check for updates in the background or update itself automatically.

The CLI contacts SSH Pub when you run commands that need the service, such as
`sshpub add` or `sshpub upgrade`.

## Supported Platforms

Prebuilt binaries are provided for:

- Linux: amd64, arm64, armv7
- macOS: amd64, arm64

## Build From Source

```sh
git clone https://github.com/ssh-pub/sshpub.git
cd sshpub
go test ./...
go build -o sshpub .
```

## Packaging

Normal source builds default to external upgrade behavior. Distribution and
package builds can use normal `go build`. Official SSH Pub release binaries are
built with `installSource=direct`. External builds do not self-upgrade through
`sshpub upgrade`.

## License

MIT
