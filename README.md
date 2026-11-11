# ShareDesk

A small web UI for managing who can reach what on a Linux file server:

- **SMB shares** — create, edit and delete Samba shares (valid users, write list, guest access, masks, hosts allow, any other parameter).
- **Users & groups** — add Samba users, change passwords, enable/disable, set group membership, create groups.
- **NFS exports** — edit clients and options (rw/ro, root squash, anonuid/anongid) in `/etc/exports` and `/etc/exports.d/*.exports`.
- **Folders** — change owner, group and mode of the folders under the share root, optionally recursively.
- **Overview** — one table showing every folder with its owner/mode, SMB access and NFS clients, with risky settings highlighted.

Every change shows the exact commands (and file diff, for NFS) before anything runs. Every applied change is logged under **Activity**.

## How it works

ShareDesk runs in a container and connects to the file server over SSH as a dedicated `sharedesk` user. That user may only run the commands ShareDesk needs, through a sudoers file. Nothing is installed on the server besides that user and that file.

- Samba config is read and written with `net conf` — the server's `smb.conf` must have `include = registry` (or `config backend = registry`) in `[global]`. Shares defined directly in `smb.conf` aren't shown.
- NFS changes edit one line in place, back the file up to `<file>.sharedesk-bak`, then run `exportfs -ra`. If `exportfs` fails, the backup is restored. New exports go into `/etc/exports.d/sharedesk.exports`.
- Deleting a share only removes it from the Samba config. Removing a user only removes the Samba account. Files and Linux accounts are kept.

## Set up

### 1. Make an SSH key for ShareDesk

On the machine that will run the container:

```sh
mkdir config
ssh-keygen -t ed25519 -N "" -C sharedesk -f config/id_ed25519
```

### 2. Prepare the server

Copy `host-setup/setup-host.sh` to the server and run it with the public key:

```sh
scp host-setup/setup-host.sh you@server:
ssh you@server 'sudo bash setup-host.sh "'"$(cat config/id_ed25519.pub)"'" /mnt/shares'
```

Then record the server's host key so ShareDesk can verify it:

```sh
ssh-keyscan -t ed25519 server-ip > config/known_hosts
```

### 3. Run it

```sh
cp .env.example .env    # set SHAREDESK_SSH_HOST and SHAREDESK_ADMIN_PASSWORD
docker compose up -d
```

Open `http://<docker-host>:8080` and log in with the admin password.

To build the image yourself instead of pulling it: `docker compose up -d --build`.

### Running on the file server itself (Podman)

Fedora ships Podman rather than Docker. Use the host network so the container can reach the server's SSH port:

```sh
sudo podman run -d --name sharedesk --network host --env-file .env \
  -v ./config:/config:ro,Z -v sharedesk-data:/data \
  ghcr.io/preswifi/sharedesk:latest
```

With `--network host`, set `SHAREDESK_SSH_HOST=127.0.0.1` and make the `known_hosts` entry for `127.0.0.1`. Open the port in firewalld if needed: `sudo firewall-cmd --permanent --add-port=8080/tcp && sudo firewall-cmd --reload`.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `SHAREDESK_SSH_HOST` | (required) | File server address |
| `SHAREDESK_SSH_PORT` | `22` | SSH port |
| `SHAREDESK_SSH_USER` | `sharedesk` | SSH user created by `setup-host.sh` |
| `SHAREDESK_SSH_KEY` | `/config/id_ed25519` | Private key inside the container |
| `SHAREDESK_KNOWN_HOSTS` | `/config/known_hosts` | Host key file |
| `SHAREDESK_INSECURE_HOSTKEY` | | `1` skips host key checks (not recommended) |
| `SHAREDESK_ADMIN_PASSWORD` | (required) | Password for the web UI |
| `SHAREDESK_SECRET` | random | Session signing key. Set it to stay logged in across restarts |
| `SHAREDESK_SHARE_ROOT` | `/mnt/shares` | New shares, exports and folder changes must be inside this |
| `SHAREDESK_DEFAULT_GROUP` | `sambashare` | Default group for new shares and users |
| `SHAREDESK_PROTECTED_USERS` | `root` | Users that can't be disabled or removed (plus root and the SSH user) |
| `SHAREDESK_SECURE_COOKIE` | | `1` when served over HTTPS |

## Security

- Treat the `sharedesk` SSH key as root on the server. The sudoers file limits which programs run, but `chown`, `chmod`, `find` and `useradd` are powerful enough that a stolen key means a compromised server.
- Keep ShareDesk on your LAN or Tailscale. Don't publish it to the internet.
- Passwords are sent to `smbpasswd` on stdin. They never appear in previews, command lines or the activity log.
- Paths are resolved on the server (`realpath`) before changes, so symlinks can't point a change outside the share root.
- With SELinux enforcing, Samba can only serve folders labelled `samba_share_t` (or with the `samba_export_all_rw` boolean on). The Folders tab shows each folder's label; ShareDesk doesn't change labels.

## Development

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt   # Windows: .venv\Scripts\...
.venv/bin/python -m pytest
```

Tests use a fake host, so they don't need a server.

## Releasing

1. Set `__version__` in `sharedesk/__init__.py` (e.g. `0.2.0`) and merge to `main`.
2. `git tag v0.2.0 && git push origin v0.2.0`

GitHub Actions runs the tests, pushes `ghcr.io/preswifi/sharedesk:0.2.0` and `:latest` (amd64 + arm64), and creates the release.

## License

MIT
