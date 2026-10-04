# pit-web

A small read-only web viewer for [pit](https://github.com/Enyytime/pit) repositories, written in Go using only the standard library.

It reads the same object store and token file that pit's HTTP push/pull server (`pit-server.py`) uses, so both can run side by side against the same data with no extra setup.

---

## Table of Contents
- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [Install](#install)
- [Running locally](#running-locally)
- [Deploying](#deploying)
- [HTTPS with Caddy](#https-with-caddy)
- [URL structure](#url-structure)
- [Security notes](#security-notes)
- [Limitations](#limitations)
- [Roadmap](#roadmap)

---

## What it does

Lets you browse pit repositories in a browser:

- list every repo on the server
- list a repo's branches
- walk a branch's commit history
- browse a commit's file tree, including subdirectories
- view a file's contents

It is read-only. Pushing, pulling, and creating repos still go through pit itself.

---

## How it works

pit objects are stored as zlib-compressed `<type> <size>\0<content>` blobs, named by their SHA-1 hash, under `<repo>/objects/<first 2 chars>/<remaining 38 chars>`. pit-web opens these files directly:

- decompresses and parses the object header to get its type (`blob`, `tree`, or `commit`)
- for a **tree**, walks its `<mode> <name>\0<20 raw hash bytes>` entries to list files and subdirectories
- for a **commit**, parses the `tree`/`parent`/`author`/`committer` header lines and the message, then follows `parent` to walk history
- for a **blob**, prints the raw content, HTML-escaped

No Git or pit binary is invoked. It is a pure reader over the same on-disk format pit writes.

---

## Install

Requires Go 1.22 or newer (for the `net/http` method+wildcard routing used in `main.go`).

```bash
git clone https://github.com/Enyytime/pit-web.git
cd pit-web
go build -o pit-web .
```

---

## Running locally

pit-web expects two things to exist, read from `$HOME`:

```
~/pit/pit-data/<repo>/objects/...
~/pit/pit-data/<repo>/refs/...
~/pit/pit-tokens.txt
```

`pit-tokens.txt` is a `name:token` file, one line per user, the same format `pit-server.py` uses:

```
alice:de91978c2ae07536033e2d02af995585
bob:93e1e81eecf9cc29c2269bc33b6844c1
```

Any line's token is accepted as the HTTP Basic Auth password; the username is ignored.

```bash
./pit-web
```

Listens on `:8081`. Visit `http://localhost:8081` and log in with any username and one of the tokens from `pit-tokens.txt`.

---

## Deploying

Build on your own machine and ship the binary; no Go install needed on the server.

```bash
# check the server's CPU architecture first
ssh user@host uname -m        # x86_64 -> amd64, aarch64 -> arm64

GOOS=linux GOARCH=amd64 go build -o pit-web .
scp pit-web user@host:~/pit/
```

Run it as a systemd service:

```bash
sudo tee /etc/systemd/system/pit-web.service <<'EOF'
[Unit]
Description=pit web viewer
After=network.target

[Service]
User=YOUR_USER
WorkingDirectory=/home/YOUR_USER/pit
ExecStart=/home/YOUR_USER/pit/pit-web
Restart=always

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now pit-web
```

Open the port in **both** firewall layers if the server has them — a cloud provider's network security group (e.g. Azure NSG) and the OS-level firewall (`ufw`/`iptables`) are separate, and both need to allow the port independently:

```bash
sudo ufw allow 8081/tcp
```

---

## HTTPS with Caddy

Basic Auth sends the token in plain text over HTTP, so put Caddy in front of pit-web and serve over HTTPS.

1. Point an A record for your domain at the server. If you use Cloudflare, set it to **DNS only** (grey cloud) so Caddy can complete the certificate challenge.
2. Open ports **80** and **443** in both the cloud network rules and the OS firewall:
   ```bash
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   ```
   Caddy needs port 80 for the certificate challenge, so nothing else (e.g. nginx) can be listening on it.
3. Install Caddy and write `/etc/caddy/Caddyfile`:
   ```
   pit.example.com {
       reverse_proxy localhost:8081
   }
   ```
4. Restart it: `sudo systemctl restart caddy`. Caddy fetches and renews the certificate automatically.

Check it with `curl -I https://pit.example.com`. A `401 Unauthorized` means HTTPS works and pit-web is asking for a token. Once Caddy is in front, you can stop exposing port 8081 publicly.

---

## URL structure

| Path | Shows |
|---|---|
| `/` | all repositories |
| `/r/<repo>` | branches in `<repo>` |
| `/r/<repo>/<branch>` | commit log for `<branch>` |
| `/r/<repo>/tree/<hash>` | a tree object's contents (files and subdirectories) |
| `/r/<repo>/blob/<hash>` | a blob's raw content |

Every request requires HTTP Basic Auth with a valid token.

---

## Security notes

- **Plain HTTP by default.** Basic Auth sends the token unencrypted. Put Caddy in front and serve over HTTPS before sharing a link outside a trusted network (see [HTTPS with Caddy](#https-with-caddy)).
- **Any valid token sees every repo.** There is no per-user or per-repo access control.
- **Repo and branch names are validated** against `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`, which rejects path traversal (`..`) and hidden-file names, before they are used to build filesystem paths.
- **File contents are HTML-escaped** before being written into the page, so a file containing `<script>` tags cannot execute in the viewer.

---

## Limitations

- Read-only: no push, pull, or repo creation
- No diffs; a commit links to its full tree, not a changeset
- Single branch view at a time; no comparing branches
- No pagination; a very long commit history is capped at 500 commits per request
- No syntax highlighting; files render as plain preformatted text

---

## Roadmap

- [ ] per-commit diffs
- [ ] syntax highlighting for common languages
- [x] HTTPS via a documented Caddy config
- [ ] pagination for long commit histories
- [ ] raw file download links
