# audit-content

Check a link or a file **before** you open it. audit-content opens it inside a throwaway microVM on your
Mac, lets four AI analysts and a set of classic scanners take it apart, and gives you a verdict in
about one to two minutes: **SAFE**, **SUSPICIOUS**, or **MALICIOUS**.

It is built for people whose laptop is worth attacking: anyone with production, cloud, finance, or
wallet access. One click on a lure is often all an attacker needs (a fake login page, a "verify you
are human" page that puts a command on your clipboard, a "coding test" repository that runs code
when you open it in your editor).

## Requirements

- A Mac with Apple silicon, macOS 26 or later.
- Claude Code installed, and a Claude subscription. Checks run `claude -p` inside the VM on your plan.
- Python 3.9 or later. The `/usr/bin/python3` that ships with macOS works. No packages are needed.

Apple [`container`](https://github.com/apple/container) is installed by `setup` if it is missing or
older than 1.6.

## Install

```sh
python3 audit-content.py setup        # installs Apple container if needed, builds the image (5-10 min, ~2.7 GB)
python3 audit-content.py auth         # runs `claude setup-token` for you; approve in the browser
```

`setup` downloads the latest signed installer from the apple/container GitHub release. Before
installing anything, it checks three things, and installs with `sudo installer` (macOS asks for your
password) only if all three pass:

1. The SHA-256 matches the one GitHub publishes for that release.
2. The package is signed with Apple's Developer ID for the Containerization team (`UPBK2H6LZM`).
3. Gatekeeper accepts it as notarized.

The package is downloaded to a temporary folder that is deleted afterwards. If `container` is
already installed but older, `setup` upgrades it. Upgrading stops the container service, so `setup`
asks first when containers are running. Checks start the service themselves if it is stopped, for
example after a reboot.

`auth` reads the token straight from `claude setup-token`'s output, even when it wraps over several
lines, and checks it with Claude before storing it in the macOS Keychain. If you already have a
token, copy it and run `pbpaste | python3 audit-content.py auth`.

Optional: `alias audit-content="python3 /path/to/audit-content.py"`.

## Use

```sh
audit-content https://example.com/invoice           # check a link
audit-content --file ~/Downloads/offer-letter.zip   # check an attachment, archive, document, or HTML file
audit-content https://... --open                    # also open the safe-view report
audit-content https://... --json                    # machine-readable verdict on stdout
```

| Flag | Meaning |
| --- | --- |
| `--report` | Write one self-contained HTML report to the system temp folder (macOS removes it after 3 days unused). |
| `--open` | Write the report and open it in your browser. |
| `--json` | Print the verdict as JSON. Progress stays on stderr. |
| `--upstream-proxy http://host:port` | Send the sandbox's internet traffic through a company or VPN proxy. |
| `--timeout 120` | Total time budget in seconds. |

Exit codes: `0` SAFE, `1` SUSPICIOUS or INCOMPLETE, `2` MALICIOUS, `3` tool error.

The report is the **safe view**: screenshots of the page (pixels only), the page text with defanged
links, every network connection, what the page tried to do (clipboard, wallet, dialogs, downloads,
where the fake credentials went), every file with hashes and scanner hits, and documents
flattened to page images. It has a strict Content-Security-Policy and contains no scripts, so it
cannot run anything from the checked page.

Other commands: `audit-content clean` removes leftovers of interrupted checks, and `audit-content uninstall`
removes the image, the leftovers, and the Keychain token. Apple `container` itself stays installed. To remove it too, run
`sudo /usr/local/bin/uninstall-container.sh -d` (`-d` also deletes its data, `-k` keeps it).

## What happens during a check

1. **A fresh microVM starts** (about 1 s). It has its own Linux kernel, a read-only root filesystem,
   RAM-only scratch space, and a new host-only network that reaches nothing but audit-content's proxy.
2. **Capture** (about 5-30 s). Chromium opens the link with a realistic desktop profile (your
   timezone and language). It scrolls, fills login forms with fake *canary* credentials, and clicks
   up to three buttons such as "Verify", "Download", or "Connect wallet" to reveal hidden stages.
   Instrumentation records every request and response body, redirects, downloads, dialogs,
   permission prompts, clipboard writes, and wallet signature requests (through a fake wallet that
   refuses to sign anything).
3. **Triage** (about 5 s). Archives are unpacked (passwords found on the page are tried). Code-hosting
   links are cloned. Every file gets a hash and a type. ClamAV and YARA-Forge scan everything.
   Auto-run traps are flagged: VS Code / Cursor `tasks.json` with `runOn: folderOpen`, npm install
   scripts, double extensions, right-to-left-override names. Domain age, DNS, and certificate
   history are fetched.
4. **Analysis** (about 30-70 s). Four `claude -p` specialists run in parallel, each on one area: web
   phishing, scripts and active behaviour, files and repositories, and infrastructure.
5. **Verdict.** The result is the worst of the deterministic indicators and the four specialists.
   Hard evidence (an antivirus hit, a ClickFix clipboard command, credentials sent to Telegram, a
   drainer signature request, an auto-run task) can never be talked down by an AI. If anything
   fails or times out, the result is at least SUSPICIOUS.

## Security model

- **Isolation.** Every check runs in its own Apple Virtualization.framework VM. Inside it, Chromium
  keeps its own sandbox and runs as an unprivileged user without capabilities (`no_new_privs`).
- **Egress.** The VM's network is host-only. The only way out is audit-content's proxy on the host. The
  proxy resolves DNS itself and refuses loopback, private, link-local, CGNAT, multicast, and
  metadata addresses, so a page cannot reach your intranet, your router, or this Mac. Inside the
  VM, nftables also limits traffic to the three proxy ports before anything untrusted runs. Mail
  ports are blocked.
- **Credentials.** The VM only ever holds a placeholder token. The proxy injects your real OAuth
  token on the LLM route, behind a per-run secret path. A prompt-injected agent can at worst lie
  about its own verdict. It cannot steal the token.
- **Untrusted output.** Everything that comes back from the VM is treated as hostile. Text is
  stripped of terminal control characters, and bidi tricks are made visible. Images are re-encoded
  only if they really are JPEGs.

## Disk and resources

- The image (about 2.7 GB) is the only lasting artifact. `setup --rebuild` replaces it, and deleting
  the old image also garbage-collects its unpacked snapshot, so disk use does not grow.
- A check writes nothing to disk. The VM runs with `--rm` and a read-only root, and all its data
  lives in VM RAM. The per-run network is deleted.
- Nothing keeps running. The VM has a hard deadline, and it also stops within a second if
  audit-content itself is killed (dead-man switch on its stdin). Leftovers from a hard crash are swept
  by the next check or by `audit-content clean`.
- A check uses up to 4 CPUs and 6 GB of RAM while it runs.

## Limits

- The sandbox visits the link from your network. The sender can see that the link was opened, and
  a one-time link (password reset, magic login) may now be used up. Use `--upstream-proxy` to exit
  elsewhere.
- Phishing kits can still cloak against automated visitors. A SAFE verdict means "nothing found",
  not "proven harmless".
- Signatures (ClamAV, YARA-Forge) are as fresh as the last `audit-content setup --rebuild`.
- If the guest itself were fully compromised (Chromium exploit plus sandbox escape), it could forge
  its own report. The proxy-side observations and the VM boundary still hold in that case.

## Development

```sh
uvx --from 'mypy==1.15.0' mypy --strict --python-version 3.9 audit-content.py   # host: macOS python3
uvx mypy --strict --python-version 3.13 sandbox.py                          # guest: Debian trixie
container build -t audit-content-sandbox:latest -f Containerfile .              # quick rebuild with cache
```

Files: `audit-content.py` (host: CLI, proxy, VM lifecycle, verdict, report), `sandbox.py` (guest:
firewall and privilege drop, Chromium over the DevTools pipe, triage, specialists), and
`Containerfile` (the image).
