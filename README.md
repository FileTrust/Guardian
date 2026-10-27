# FileTrust Guardians

An independent application for **one Guardian node per installation**.
Clone this repository and install it directly. No other FileTrust repository,
developer tools, test fleet, circuit compiler or trusted-setup generator is
needed. This repository contains production runtime and installation files;
tests and release tooling are maintained separately.

Choose native installation or Docker. Both run the same Guardian software and
use the same signed proof parameters. Each installation manages one node.

The packaged ZoKrates runtime requires **Linux x86_64**. The native installer
uses apt and systemd, with Python 3.10 or newer; Ubuntu 22.04 and Debian 12 are
reference platforms. Other Linux distributions need their own dependency and
service setup, or can use Docker on a compatible Linux amd64 host. Docker
provides its own Python environment; host Python is not required for public
Docker installation. Windows/macOS Docker Desktop is not a verified server target.

## Install

Clone the repository and run the native installer:

```sh
git clone https://github.com/FileTrust/Guardian.git
cd Guardian
sudo bash install.sh
```

Public repositories and artifacts require no GitHub account or token. While
access is private, run `gh auth login` first, clone with
`gh repo clone FileTrust/Guardian`, and use the same installer.
Both older and newer GitHub CLI versions are supported. Under sudo, the
installer can use the calling user's existing login. No token export is needed.
An explicitly supplied `GH_TOKEN`/`GITHUB_TOKEN` is optional; an invalid value is
rejected without displaying it. If an earlier command put an error message
there, run `unset GH_TOKEN GITHUB_TOKEN` before retrying.

Alternatively, extract the installer ZIP from this repository's releases and
run its `install.sh`. The running node never needs the installation token.

The installer automatically installs Python dependencies, downloads the pinned
ZoKrates executable from its official upstream release, and downloads this
repository's published proof bundles. It never generates replacement setup keys.
Seven stages and per-bundle progress bars show the work. Downloads resume and
SHA-256/signature checks reject changed files. Verified files are cached.

By default, all published N/t profiles, both fixed circuits and ZoKrates are
installed. Allow about **60 GiB free** for the full artifact set including
download caches; setup checks the selected release's exact size. To install
only a selected N/t profile and the common artifacts:

```sh
sudo bash install.sh --profile 5:3
```

A subset cannot prove jobs requiring other profiles until those are installed.
Repeat `--profile` to select several profiles. Rerun the same installation
command after an interruption: verified downloads are reused, partial downloads
resume, and an existing wallet and profile selection are retained.

## Docker installation

Install [Docker Engine and the Compose plugin](https://docs.docker.com/engine/install/)
for the host distribution. From the same repository clone:

```sh
./docker.sh install --profile 5:3
```

Omit `--profile` for all published profiles. Setup displays each download's
percentage and prompts to import or create a wallet. It does not start or
register the node. Fund the displayed wallet, review its settings, then run:

```sh
./docker.sh start
./docker.sh logs
```

If Docker requires root access, use `sudo bash docker.sh` for these commands.
Setup uses an existing GitHub login only while artifacts are private. The
credential crosses stdin into temporary container memory; it is never placed
in the image, container environment metadata or node volumes.

The Linux container uses host networking for outgoing RPC/HTTPS and DNS;
it does not open an incoming Guardian port or change host firewall rules.
Image builds also use host networking; set `FILETRUST_DOCKER_BUILD_NETWORK=default`
to use Docker's bridge during builds when required by host policy.

Docker and native installations have separate identities and storage. Do not
import the same active wallet into both. Guardians use outgoing RPC connections
and require no incoming peer port. For another Docker node on the same host,
set a different `FILETRUST_DOCKER_PROJECT` name consistently for every command.

| Action | Docker command |
|---|---|
| Start / stop / restart | `./docker.sh start`, `./docker.sh stop`, `./docker.sh restart` |
| Status / live logs | `./docker.sh status`, `./docker.sh logs` |
| Verify wallet, files and network | `./docker.sh doctor` |
| Check signed application update notices | `./docker.sh check` |
| Check / apply network settings | `./docker.sh network-config check`, then stop and `./docker.sh network-config apply` |
| Claim DKG credits | `./docker.sh claim-dkg` |
| Rebuild checked-out code | `git pull --ff-only`, then `./docker.sh update` |
| Restore previous application image | `./docker.sh rollback` |
| Remove container, retain node data | `./docker.sh uninstall` |
| Also delete wallet, shares and node data | `./docker.sh uninstall --purge` (requires typing `DELETE`) |

Stop waits for current work to finish. Restart, image replacement and normal
uninstall preserve the wallet, unlock credential, shares, settings and proof
files in named Docker volumes. The default volumes are
`filetrust-guardian_state` and `filetrust-guardian_credentials`. Purge deletes
those managed volumes only; it leaves native installations, Docker itself,
source clones and build images alone. Retire network duties before purging.

Daily application and network checks provide notices; they do not install code
or change contracts automatically. Docker updates rebuild the reviewed checkout
and validate the existing node before replacing its container. Rollback restores
the previous image, not an older copy of custody data. Network or data-format
migrations still need explicit review.
While update metadata is private, use `./docker.sh check` with the host's saved
GitHub login. The background container does not retain that login; its network
settings check still runs independently. Public update metadata needs no login.

## Wallet and startup

Setup asks whether to import a wallet or create one. Imported private keys use
hidden terminal input. No private key is printed or accepted as an argument.
A repeated installation keeps the existing wallet and unlock key.

Installation enables the reboot service but does not start it immediately.
Fund the displayed wallet address and review `service_prices` in the public
configuration before starting. Registration can spend fees and required stake.

```sh
sudo systemctl start filetrust-guardian
sudo journalctl -u filetrust-guardian -f
```

Use `sudo systemctl stop filetrust-guardian`, `restart`, or `status` for the
corresponding native service controls. Restart preserves all node data. Logs
show registration and worker startup; Docker logs show the same runtime stages.

Paths: application `/opt/filetrust-guardian`, private state
`/var/lib/filetrust-guardian`, separate unlock credential
`/etc/filetrust-guardian/unlock.key`. Service user: `ftguardian`.

The service verifies the signed artifact manifest, chain ID, configured contract
addresses and exact verifier bytecode before running protocol workers. It
restarts after failures. A future chain/setup needs an approved release binding;
it never silently regenerates keys or migrates an existing identity.

## DKG duties and credits

On a network using accepted DKG duties, setup asks whether to enable automatic
acceptance. Set the maximum collateral per attempt, minimum fees, concurrency,
work/dispute windows and transaction gas-price ceiling. The node accepts only
offers within those limits and uses the exact proof files/verifiers approved
by its signed release. Reinstallation preserves these settings.

Earned fees, unused funds and compensation are escrow credits until withdrawn.
To review the amount and maximum transaction fee, then withdraw to the node's
own wallet:

```sh
sudo /opt/filetrust-guardian/.venv/bin/python /opt/filetrust-guardian/guardian.py claim-dkg
```

The command runs with the service account and private unlock credential. A lost
reply retains the signed transaction; run the same command again to recover its
confirmation. Credits do not disappear when the node or computer restarts.

Existing custody stays associated with its original deployment. Changing a
coordinator address does not move keys, shares or file history; network changes
that need a migration require a separate compatibility review.

## Protecting and recovering your node

Wallet, X25519 key and stored shares use authenticated AES-GCM encryption.
A separate random local key enables automatic startup through systemd's private
credential channel. No wallet key or share is passed in process arguments.

**Back up private state and its matching unlock key separately.** Artifacts and
download caches are replaceable; wallet-only recovery cannot restore old
X25519 keys or DKG shares. Importing an already registered wallet requires
restoring its original encryption key and shares too.

Software-only automatic unlocking does not protect against root compromise,
a compromised running node, or a complete host copy containing the unlock key.
TPM support is optional future work. Stop and disable the service before
removing it; keep custody material until the node's duties are retired.

## Uninstall

From your source clone, update it with `git pull --ff-only`, then run:

```sh
sudo python3 uninstall.py
```

This stops and disables the service and removes the installed application and
service unit. It keeps all state (including wallet, shares, artifacts and download
cache) and the separate unlock credential so you can reinstall and resume.

To also permanently delete that state and credential:

```sh
sudo python3 uninstall.py --purge
```

This requires typing `DELETE` in a terminal before anything changes. Retire the
node's network duties and make any needed backups first: wallet-only recovery
cannot recover old shares. Uninstalling does not perform on-chain withdrawal or
deregistration. Both modes keep the source clone and inactive `ftguardian` system
account, and affect only the standard paths documented above. They do not remove
system Python, GitHub CLI, or other shared packages. You can also run the installed
copy at `/opt/filetrust-guardian/uninstall.py` before application removal.

For complete removal, after `--purge` succeeds, also remove the inactive system
account and your source clone:

```sh
sudo userdel ftguardian
cd "$HOME" && rm -rf -- "$HOME/FileTrust-Guardians"
```

The last command permanently deletes that source folder; change the path if you
cloned elsewhere. Shared tools such as Python and Git remain installed because
other applications may need them.

## Licenses and credits

FileTrust code: [LICENSE](LICENSE). Third-party licenses and credits:
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) and [licenses/](licenses/).
ZoKrates is LGPL-3.0 and is downloaded directly from the official 0.8.8 release.
Python packages are installed from PyPI with their own license metadata.


## Application updates

Version 0.2.0 establishes a new installation baseline for the versioned DKG
recovery runtime. Upgrading code does not move an existing node's custody to
another coordinator. Retain its original installation/settings for existing
files; another deployment requires separate state and wallet identity. A
changed bootstrap is installed through a reviewed installer transition, not
silently replaced by the signed code updater.

The application version is recorded in `VERSION`. Background checks verify
signed TUF metadata at startup and about daily. Failed checks do not stop work.
No update is installed without the operator choosing it. The following commands
are for native installations; Docker uses the commands in its section above.

```sh
/opt/filetrust-guardian/.venv/bin/python /opt/filetrust-guardian/update.py --check
/opt/filetrust-guardian/.venv/bin/python /opt/filetrust-guardian/update.py --status
/opt/filetrust-guardian/.venv/bin/python /opt/filetrust-guardian/upgrade.py status
```

### Existing installations

Finish current work and stop the service before rerunning the installer. It
preserves the wallet, unlock key and selected profiles. Older installations may
need this installer transition before they can use the managed updater.
Only an explicitly approved compatible update can be applied; a changed
bootstrap or deployment is not an automatic custody migration. Do not combine
Git pulls and signed-code activation in the same update operation.

### Prepare and install a compatible release

```sh
/opt/filetrust-guardian/.venv/bin/python /opt/filetrust-guardian/upgrade.py prepare
/opt/filetrust-guardian/.venv/bin/python /opt/filetrust-guardian/upgrade.py apply
```

Prepare can run while the app works. It verifies the package, compiles Python
sources and installs dependencies into a separate environment. A retry reuses
the verified archive and staging environment. It never replaces the active
code, environment, wallet or shares during preparation.

Apply requires the app and its transfer/worker children to be stopped. It checks
release trust again, rejects locally modified code, journals code-file changes,
and switches the prepared Python environment. Settings, wallet/key-vault files,
keyring references, transaction records, downloaded network ABIs and proof
artifacts stay in their existing locations. Proof parameters are not regenerated
or redownloaded by a code update. New-file collisions with user files are refused.

Only compatible data-schema-1 Python/code updates are supported. A different
schema, bootstrap, proof setup or binary/protocol migration needs a separately
reviewed migration, not an automatic overwrite. Keep at least 1 GiB free for
staging, dependencies and code/environment recovery. Source ZIPs are for initial
installation; the `code-*.zip` asset is for the verified updater only.

For a managed service, use this instead of offline apply:

```sh
/opt/filetrust-guardian/.venv/bin/python /opt/filetrust-guardian/upgrade.py apply --service
```

Native Guardian service updates require sudo. The updater requires the new graceful-stop unit: no forced
kill deadline, and mixed kill mode so a prover is not directly terminated.
It waits for current work, applies offline, and restarts only if the service
was previously running. A failed readiness check restores the previous code
and environment. Enablement settings are retained. Guardian workers finish
their current protocol iteration before exiting.

If stopping takes longer than five minutes, the command leaves code unchanged
and reports that maintenance is still pending. Inspect status and retry after
work finishes; its journal remembers the original running state. To cancel
before code has changed:

```sh
/opt/filetrust-guardian/.venv/bin/python /opt/filetrust-guardian/upgrade.py cancel --service
```

Cancellation waits for a pending graceful stop and restores the old service's running state. Never force
kill a proof or transaction just to make an update proceed.

### Recovery

```sh
/opt/filetrust-guardian/.venv/bin/python /opt/filetrust-guardian/upgrade.py recover
/opt/filetrust-guardian/.venv/bin/python /opt/filetrust-guardian/upgrade.py rollback
```

Run recovery/rollback only while the app is stopped. Rollback restores previous
code and the Python environment; it never rolls user data or transaction records
back in time. Startup locks prevent a new app from importing half-applied files.
For a severe interruption where the updater itself cannot import, use the
unchanged standard-library bootstrap:

```sh
python3 /opt/filetrust-guardian/ft_update_bootstrap.py --recover
```

Use sudo for a root-owned Guardian installation. The bootstrap also supports
`--rollback` for the latest installed compatible code update. No runtime schema
migration is attempted. Keep recovery caches until the new version is healthy.

### Private access and future public repositories

While releases are private, checks need GitHub read access through the current
user's `gh auth login` or an explicit session `GH_TOKEN`. Checks never unlock a
wallet or sign a blockchain transaction. The native check and prepare commands support older GitHub CLIs and the
calling user's saved login under sudo. Do not put a token value in command
arguments or save it in source. Public releases need no login; an
expired private-testing token can fall back to anonymous public access.

A headless node may not see the desktop GitHub login. Optional
`update.py --authorize-service` asks for a repository-restricted read-only token
at a hidden prompt, unless you explicitly provide `GH_TOKEN`. It stores the
token as a private systemd credential and does not restart the service.
Authorization takes effect on the next planned restart.
Guardian authorization requires sudo because its service is system-wide.

The repository/channel defaults are in `update-source.json`; the trusted public
root is `update-root.json`. A signed `next_source` descriptor can move existing
clients to a future FileTrust organization without replacing trust keys. Do not
replace the root with a key downloaded from an untrusted source. Guardian proof
installation also uses the configured repository, so moving the repository does
not require editing the downloader code.

## Registry heartbeat

The running node sends a registry heartbeat every 30 minutes at a stable wallet/chain-specific slot. Failed sends retry after 60 seconds using the same saved signed transaction, so timeouts or restarts do not allocate another pending heartbeat. The existing account transaction lock coordinates this with normal node transactions. No new contract deployment is needed.

Explorer displays Participation (Enabled/Disabled/Suspended where supported) separately from Heartbeat (Fresh/Stale). Fresh means the registry timestamp is no older than 45 minutes. Neither a fresh heartbeat nor a Discovery announcement changes suspension, participation or admission.

## Network settings updates

Code releases and network settings are checked separately. The node checks for
network changes daily alongside code update checks. Checks only notify; they
never change contracts, ABIs, storage allocation, identities or running work.
A normal restart uses the saved settings.

```sh
python3 network-config.py check
python3 network-config.py status
```

Review the reported changes. Stop the node normally before applying:

```sh
python3 network-config.py apply
# Start the node again using its usual service or launcher command.
```

Use the installed application's Python environment and the account that owns its
settings (or sudo where required). Public Guardian and Vaultkeeper commands use
their installed state directories by default; `--home PATH` selects another node.
Application and proof-artifact compatibility checks remain mandatory. If a change
requires a new application or signed artifact release, install that release first.
To undo the last settings activation while stopped:

```sh
python3 network-config.py rollback
```

Previous settings and ABI generations are retained in the node's private
`.network-updates` directory. Wallets, transport keys, shares, pieces and capacity
state are preserved. Failed checks keep the last working settings. User-selected
Discovery peers remain unchanged; `network_config_manage_discovery: true` opts
into managing that list from the network service.
