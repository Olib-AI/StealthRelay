# StealthRelay web client

Join a StealthOS pool from a browser and chat with the people in it. It joins by invitation, and the
host approves you as usual. Calls and games aren't available on the web yet: an incoming call or a
game invitation is declined, and you're told.

## Who you are trusting

Messages are encrypted on the page before they leave it, so the relay can't read them, and peers are
checked the same way the app checks them. You can compare a security code with someone from your
private chat with them (tap the lock).

The page itself is different from the app: it is code your browser fetches each time from whoever
hosts it. That host could change it to read your invitation and your messages. So:

- Use a copy hosted by someone you trust. Host it yourself if you can (`Dockerfile`), on HTTPS.
- Trust in the relay and trust in the page's host are separate. Running your own relay doesn't help
  if someone else serves the page.

The invitation's part after the `#` holds the pool's invite key. The relay never receives it. Only
paste an invitation into a page you trust.

## Requirements

A current Chrome, Edge, Firefox or Safari, over HTTPS or on localhost: it needs Ed25519 and X25519 in
Web Crypto. Other browsers are told so and don't connect. Pools with someone on StealthOS 1.4.x don't
work here: the web client only takes part in protected pools.

## Development

```bash
npm ci
npm run dev           # HTTPS, with a proxy for ws:// relays
npm run build
npm run lint
npm test              # no browser or Swift needed
npm run typecheck:test
```

See [tests/README.md](tests/README.md) for what the tests prove, and how to rerun the checks against
the Swift code.
