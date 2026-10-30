# audit-content

Check a link or a file before you open it. audit-content opens it inside a throwaway virtual machine on your Mac, lets four AI analysts and a set of classic malware scanners pick it apart, and gives you a verdict in one to two minutes: SAFE, SUSPICIOUS, or MALICIOUS. If you want, it also gives you a safe view of the content: pictures of the page, its text, and documents turned into plain images, so you can see what is there without ever opening it yourself.

It is made for people whose laptop is worth attacking, such as anyone with access to production systems, cloud accounts, company finances, or crypto wallets. Many breaches start with one click: a fake login page, a "verify you are human" page that quietly puts a command on your clipboard, or a "coding test" from a recruiter that runs code the moment you open the folder in your editor.

## Install

```sh
python3 audit-content.py setup
python3 audit-content.py auth
```

You need a Mac with Apple silicon and macOS 26 or later, Claude Code with a Claude subscription, and Python 3.9 or later (the one that ships with macOS is fine; nothing else is installed). `setup` installs Apple's [container](https://github.com/apple/container) tool if it is missing, and only after checking that the download matches the published checksum and is signed and notarized by Apple. It then builds the sandbox image once, which takes about eight minutes and uses about 2.7 GB of disk. `auth` runs `claude setup-token` for you, checks the token with Claude, and keeps it in the macOS Keychain. The token never enters the sandbox.

## Use

```sh
python3 audit-content.py https://example.com/invoice
python3 audit-content.py --file ~/Downloads/offer-letter.zip --open
```

Pass a link, or a file with `--file` (an email attachment, an archive, a document, a saved web page). `--report` writes the safe-view report as a single HTML file in the temporary folder, `--open` also opens it in your browser, and `--json` prints the verdict for other tools. The exit code is 0 for SAFE, 1 for SUSPICIOUS, 2 for MALICIOUS, and 3 if the tool itself failed. `clean` removes leftovers of an interrupted check, and `uninstall` removes the image and the stored token.

![Terminal output of a check](docs/terminal.png)

## The report

The report starts with the verdict and the reasons behind it. Hard evidence comes first: findings from fixed checks that no AI can talk away, such as a page writing a command to your clipboard or sending a typed password to a Telegram bot. After that comes one plain sentence from each AI analyst.

![Top of the report: verdict, hard evidence, and the analysts' conclusions](docs/report-summary.png)

Further down you see what the page looked like at each step, and what it tried to do while the sandbox was poking at it. The pictures are only pixels, so nothing in the report can run or be clicked. The report also lists every network connection, every file with its fingerprint and scanner results, the page text with all links made unclickable, and a list of addresses to hand to your security team.

![What the page looks like and what it tried to do](docs/report-pages.png)

## How a check works

Every check starts a fresh virtual machine with its own Linux system, a read-only disk, and memory-only scratch space. Its network can reach nothing except a small proxy that audit-content runs on your Mac. That proxy is the only way out, and it refuses any address on your home or office network, on the Mac itself, or in cloud metadata services, so a page cannot reach anything private.

Inside the machine, a real Chrome browser opens the link the way a normal visitor would, using your time zone and language. It scrolls, fills login forms with fake "canary" credentials to see where they get sent, and presses up to three buttons such as "Verify", "Download", or "Connect wallet" to reveal what hides behind them. It records every request, download, dialog, permission prompt, clipboard write, and wallet signature request. The fake wallet never signs anything. Archives are unpacked, code repositories are cloned, and everything is scanned with ClamAV and YARA rules. The checks also look for the tricks used in fake job interviews, like editor tasks that run when a folder opens and install scripts that fetch code from the internet. Domain age, DNS, and certificate history are looked up too.

Four Claude analysts then work in parallel, each on one area: phishing and fake pages, scripts and page behaviour, files and code repositories, and domains and hosting. They can dig further with tools inside the machine, but they never run the content they inspect. The final verdict is the worst of everything found. If any analyst fails or runs out of time, the result is at least SUSPICIOUS, never SAFE.

## The network proxy

The virtual machine has no internet connection of its own. Each check creates a new host-only network that links the machine to your Mac and to nothing else, and the machine gets no DNS server. On the Mac's side of that network, audit-content starts a small proxy with three ports, and those ports are the only things the machine can reach. Every connection the sandbox makes therefore goes through code that runs outside it. That is the core of the design: the rules live where the content cannot touch them, so even content that took over the whole machine would find no other way out and no rule to change.

```
Inside the VM                    Proxy on your Mac                        Out to
----------------------------     ------------------------------------     -----------------
Chrome                       ->  browse port: public addresses only   ->  any public site
curl, git, domain lookups    ->  tools port:  public addresses only   ->  any public site
Claude analysts (fake token) ->  llm port:    swaps in your token     ->  api.anthropic.com
```

Inside the machine, a firewall drops every outgoing packet except those addressed to the three proxy ports. It is needed because a host-only network still leads to your Mac: without it, code in the machine could try other services listening on the Mac. The firewall is set up before any content is touched. The browser, the scanners, and the analysts then run as an ordinary user with every privilege removed, so they cannot change it. Getting around it would first take a Linux kernel exploit.

The browser and the tools ask the proxy for a host name, never for an address, because the machine cannot look names up. The proxy looks the name up on your Mac and checks every address that comes back. If any of them is private, the connection is refused: your home or office network, the Mac itself, link-local addresses (where cloud metadata services live), or the 100.64.0.0/10 range that VPNs such as Tailscale use. Otherwise the proxy connects to the exact address it checked, so a domain cannot pass the check with a public address and switch to a private one a moment later, a trick known as DNS rebinding. The proxy also refuses mail ports, so the sandbox cannot send spam, and cuts all traffic once the sandbox has downloaded 768 MB.

The proxy does not decrypt anything. HTTPS passes through as a sealed tunnel, the browser checks certificates as usual, and the proxy only sees the host name, the address, and how much data went each way. What the page contains is captured by the browser inside the machine. That is still enough to record every connection, and because the record is kept on your Mac, the list of connections in the report stays truthful even if the content took over the machine. The browser and the tools use separate ports so the record can tell what the page did from what the analysis did. A refusal is evidence in its own right: a page that tries to reach a private address, or probes ports on the visitor's own computer, makes the verdict at least SUSPICIOUS.

The third port is how the analysts reach Claude, and it is why your token never enters the machine. The Claude command-line tool inside the machine holds a fake token and is pointed at this port instead of at Anthropic. The port accepts only POST requests to the Messages API, under a random path that changes every check and is handed only to the analysts. For each request, the proxy removes any credentials it carries, adds your real token, and sends it to api.anthropic.com over TLS, checking Anthropic's certificate. The destination is fixed in the proxy, so nothing in the machine can send your token to another server, use it on another part of the API, or read it. The worst that hostile code in the machine could do with this port is send its own prompts to Claude on your subscription until the check ends.

With `--upstream-proxy`, the same checks run first, and the proxy then asks the other exit to connect to the address it already checked, not to the name, so the other exit cannot be led to a private address on its own network. Calls to Claude cross the other exit as an encrypted tunnel, so it never sees the token. In every mode, the proxy listens only on the Mac's address on that run's network, on random ports, and accepts connections only from that network. It reads nothing but request lines and headers and copies everything else without interpreting it. It is part of the audit-content process, so it stops when the check ends, and the network is deleted with it. To compare all this with the code, the proxy is `EgressProxy` and its request handler in `audit-content.py`, about 250 lines of standard-library Python, and the firewall is `lock_egress` in `sandbox.py`.

## Safety and disk

Because the analysts only ever hold a fake token, a page that tries to trick an analyst can at worst skew that analyst's opinion; it cannot steal your access, and it cannot remove the hard evidence. Everything that comes back from the machine is treated as hostile: text is cleaned before it reaches your terminal, and images are checked before they go into the report.

Nothing is left behind. The machine is deleted when the check ends, its data lives only in memory, and its network is removed. If audit-content itself is killed, the machine notices and stops within a second, and the next check sweeps up anything left over. The only thing that stays on disk is the image. `setup --rebuild` refreshes it and the malware signatures inside it, deletes the old copy, and removes the build cache, so disk use does not grow over time.

A few limits are worth knowing. The sandbox visits the link from your network, so the sender can see that it was opened, and one-time links such as password resets may get used up. `--upstream-proxy http://host:port` sends the traffic through another exit instead. Some phishing kits hide from automated visitors, so SAFE means nothing was found, not that the content is proven harmless. Malware signatures are as fresh as the last rebuild.

## Develop

```sh
uvx --from 'mypy==1.15.0' mypy --strict --python-version 3.9 audit-content.py
uvx mypy --strict --python-version 3.13 sandbox.py
container build -t audit-content-sandbox:latest -f Containerfile .
```

`audit-content.py` runs on your Mac: the command line, the proxy, the virtual machine's life cycle, the verdict, and the report. `sandbox.py` runs inside the machine: the firewall, the browser, the scanners, and the analysts. `Containerfile` describes the image. Both Python files use only the standard library and pass strict type checking. Planned work is tracked in the milestones: Linux and Windows versions, and an optional background mode that checks new messages a few times a day.
