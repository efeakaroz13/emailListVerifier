## Email Verifier
I was tired of paying for email verification, so I made my own verifier. This uses simple MX and SMTP verification by faking an email connection, and learning if the inbox is deliverable from the beggining.

It uses 5 concurrent processes and you can verify your CSV leads easily by running `list_verifier.py`

## Dependencies
You need python, requests, dns, socks, socket packages to run this script. You also need to have a Tor proxy installation on your system, because this software uses `seevik2580/tor-ip-changer` on github as a proxy, which is a free and open source software relying on Tor servers.

## UI
We don't have an UI yet, it works on the CMD, but if the repo reaches 20 stars, I'm going to add a next JS UI.

