# Tests

`npm test` runs in Node with nothing else. `vectors/swift-vectors.json` holds test keys only.

- `interop.test.ts`: the wire protocol against output of the real Swift code.
- `negative.test.ts`: what must be refused. A refusal is only shown by what would have happened
  otherwise, so these finish the exchange and check that no frame opens.
- `inbound.test.ts`: what a peer or relay may put in front of the UI, and who may say what.

`src/transport/websocket.ts` needs a browser and is covered by the run described below, not by `npm test`.
Decisions that matter live in modules these tests import.

## Against the Swift code

Do this after any change to the wire code, and when `LocalPackages/ConnectionPool` or `PoolChat` change.

1. Copy `Package.swift` and `Sources` of both packages into a scratch folder outside the repo, as a
   snapshot, and make `KeychainItemStore` in the copy's `Security/SecureItemStore.swift` and the
   `SecItem` calls in its `Transport/RemotePoolService.swift` do nothing. **Nothing here may reach a
   real Keychain.** Check with `nm -u <binary> | grep _SecItem`, which must print nothing.
2. Make an executable depending on those copies, with `vectors/tool/main.swift.txt` as its
   `main.swift`, and build it in debug (it uses `@testable import`).
3. Generate: `<tool> tests/vectors/swift-vectors.json`, then `npm test`.
4. Verify what this client produces, in Swift:

   ```bash
   STEALTH_TS_OUTPUT=/tmp/ts-output.json npm test
   <tool> verify /tmp/ts-output.json
   ```

   Every line must say `PASS`. The test that writes the file is skipped without the variable, so a
   plain `npm test` does not prove this direction.
