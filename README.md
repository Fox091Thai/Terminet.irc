# Terminet.IRC v2.0.1 
> if it works, it's a miracle.

Terminet.IRC is a simple, lightweight just somehow worked. 
It required no email, no phone number, nothing to verify. Python, one server file, 
it supposed to have a few hundred KB, and it fits on a 1.44 MB floppy. (only system files).
This thing is **not** a Discord replacement. No voice, no bots, no federation, so if you want them you can just modify it.
It's a text-and-files chat for a small group, on a server you run yourself.
## Why

Got tired of Discord, so I made my own and because why not?

## What it does

- Servers with rooms, invite links (expiry, use limits), owner and moderators
- Replies, file and image uploads, delete messages, kick and ban
- Unread counters, sound alerts, works on a phone
- Accounts are a login code plus a password. No email, so:

> **There is no account recovery.** Lose the login code or the password and the account is gone. This is on purpose. The sign-up page makes you save the code before it lets you continue.

## Run it

```
pip install -r requirements.txt
python3 terminet_server.py
```

Then open `http://<your-ip>:8080/`.

First run creates a `data/` folder next to the script (database, a random key,
uploads). Nothing to edit in the source. Delete `data/` and everything is gone.
**Never commit `data/`.**

If anyone but you connects, use HTTPS. Over plain HTTP the passwords and the
session cookie travel in clear text.

- LAN, no domain: `python3 terminet_server.py --gen-cert 192.168.1.10`, then start again.
- Real domain: put Caddy or nginx in front and start with `TERMINET_TRUST_PROXY=1`.

For anything bigger than a group of friends, run it with gunicorn, **one worker only**
(online lists and rate limits live in memory). Details and every setting
(`TERMINET_PORT`, upload limits, session length, ...) are in the longer docs:
`docs` or the older README sections, and `SECURITY.md`.
Admin commands (run on the server, not reachable from the network):

```
python3 terminet_server.py --backup backup.db
python3 terminet_server.py --stats
python3 terminet_server.py --revoke-sessions
```

A backup does not contain the key. Keep it somewhere other than next to `data/terminet.secret`,
or it's no protection at all.

## Read this before you host it

- **The person running the server can read every message.** Messages are
  encrypted in the database, but the server holds the key. This is not
  end-to-end encryption. Only host for people who trust you, and only join
  servers run by people you trust.
- **Uploaded files are not encrypted** on disk.
- **No outside security audit.** I wrote it with a lot of AI help, tested it
  myself, and the tests are mine too. It is much safer than v1.3, but don't put
  anything on it that would really hurt you if it leaked. For that, use Signal.
- Rate limits reset when the server restarts.
- Sign-up is open to anyone who can reach the server. Keep it behind a firewall
  or VPN if you want a closed group.
- A banned person can make a new account. There is nothing to tie a person to.

## v1.3 or below is not safe

If you cloned the old version (v1.3 or earlier): **don't run it on the internet.** 
(i think no one cloned this project anyway lmao. but if you do clone the old version, i suggested you to update to v2.0 or above version.)
It had no real authentication on the sockets, served its own database and source
code as static files, and had XSS in most places. The old code is kept under the
tag `v1.3-insecure` only so the history is honest.

## History

1. The web version (v1.x).
2. The security overhaul (this one).


More about what was broken and what was fixed: [SECURITY.md](SECURITY.md).



## License

MIT. Do what you want, don't blame me.

---

*Made by Fox091Thai. "just a random guy on the internet."*