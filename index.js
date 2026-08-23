/**
 * platform-host — the `platform:host` capability: its declaration, its implementation,
 * and the suite that holds one to the other.
 *
 * ## Why this is its own repository
 *
 * The capability rule is **the kernel wires capabilities; it does not implement them.** Six
 * capabilities the runtime supplies had their declarations in one file in
 * `artifact-protocol` and their implementations spread across four files in the kernel, no
 * two sharing a boundary — so a capability was two documents in two repositories with
 * nothing holding them together, and the only thing that proved either was the kernel's
 * own suite. This is the **last** of the six, and it went last on purpose: the largest
 * file, the adapter-conventions machinery, and an open ceiling.
 *
 * The name is *derived*: the contract id with the `:` turned into a `-`. There is no
 * mapping to keep in anyone's head, and it is the rule that named all six.
 *
 * ## Read `THREAT-MODEL.md` §1 before this
 *
 * This is the platform's largest authority and nothing here softens it. A holder of
 * `platform:host` has **user-level remote code execution on every device that runs the
 * artifact**: `writeCommand` lands its bytes executable in a directory on the user's
 * `PATH`, and `profileEnsure` writes unfiltered shell into a file the login shell runs.
 * The character classes make a path traversal *unspellable*, which is the one strong
 * containment claim in the whole contract, and it is a claim about *where* a file lands
 * rather than about what is in it.
 *
 * And it is **not restricted to adapters**, whatever the declaration's own prose asks of
 * authors. `artifact-planner/lib/chain.js`'s `NATIVE` maps by contract id alone, so any
 * artifact whose manifest declares the port holds this. `THREAT-MODEL.md` §1.2 is the
 * correction and `lib/declaration.js` says why the sentence stays as written.
 *
 * ## What is here and what stayed in the kernel
 *
 * Here: the declaration (`lib/declaration.js`), the implementation (`lib/host.js`) and a
 * conformance suite that drives the second against the first. That last one is the point
 * of the phase rather than a side effect — a repository that only held moved code would
 * have relocated a file and changed nothing about who can prove what, and for this
 * contract there is a specific gap it closes: fifteen operations, of which the kernel's
 * suites reach eleven.
 *
 * Stayed, and unlike the other five capabilities the reason is not a socket or a
 * hypercore — it is that these are **authority rather than mechanism**:
 *
 *   - **`READABLE_ENV`, the six-name allow-list.** It is one of the things that must not
 *     move. Letting the contained thing name what it may read is letting it write its own
 *     containment, and a capability repo naming its own list is one step nearer that
 *     mistake rather than further from it. The `env` operation is a pass-through to a
 *     reader the kernel built; see `Machine.env` in `lib/host.js`.
 *   - **the console measurement.** One `uv_tty_get_winsize` on the `bare-stdio` singleton
 *     `bin/artifact.js` holds. A realm cannot measure a terminal and it does not follow
 *     that nobody can — the party who can is the process. The *clamp* is here, because the
 *     declaration promises "a clamped column count".
 *   - **`chain.js`'s `NATIVE` table.** `@host` is minted **unscoped**, which is why one
 *     object serves every holder in a network and why nothing reaches `writeCommand`
 *     carrying the identity of who called it. `@store:<instance>` next door is per
 *     instance, and the difference between those two rows is a decision about what a valid
 *     graph may name.
 *   - **minting in `boot.js`.** Which includes resolving the signed `conventions` of the
 *     adapter for *this device's* platform, once, and holding every holder to it.
 *
 * ## It is not an artifact
 *
 * No `manifest.json`, no `build`, no ports. It is an ordinary Bare module the kernel
 * requires directly, and it sits on the far side of the boundary an artifact sees: an
 * artifact *binds* `platform:host` and can never reach this package. That distinction is
 * load-bearing for the delimiter argument in `lib/host.js` — `BEGIN`/`END` are the
 * platform's marker for its own writes and an adapter may not say either, and this
 * package is not the adapter.
 *
 * ## Types come through `platform-host/host` and `/declaration`
 *
 * There is no `@typedef` in this file. This is a `module.exports = <expression>` file,
 * which TypeScript reads as `export =`; a JSDoc typedef in such a file is not a named type
 * export of it, and re-declaring one here as an alias of the declaration it points at
 * collides with that declaration the moment a consumer compiles both packages as one
 * program — `TS2300: Duplicate identifier`, invisible in this repo's own typecheck and
 * reported only in the repo that sees both. `artifact-net/lib/lan.js` has the full
 * account; it cost a day there.
 *
 * So each type is declared once, in the module that owns it. `Machine` is the one that
 * matters: the kernel builds one, so `ArtifactPatform/lib/host.js` annotates against
 * `import('platform-host/host').Machine`.
 *
 * ## The re-export is written out rather than spread
 *
 * `{ ...require('./lib/host') }` would be shorter and would make this file stop being a
 * document. Naming each member is how a reader learns what the front door is without
 * opening two more files, and it is what makes *adding* to the surface a visible decision
 * rather than a side effect of adding an export three directories down.
 */
const declaration = require('./lib/declaration')
const implementation = require('./lib/host')

module.exports = {
  ID: declaration.ID,
  VERSION: declaration.VERSION,
  DECLARATION: declaration.DECLARATION,
  DECLARATIONS: declaration.DECLARATIONS,
  host: implementation.host,
  COMMAND: implementation.COMMAND,
  BEGIN: implementation.BEGIN,
  END: implementation.END
}
