# platform-host

The `platform:host` capability: what the machine is, the narrowest authority to act
on it, and the suite that drives the implementation against its own declared shape.

> **Read [`THREAT-MODEL.md`](https://github.com/AustinPoonia/artifact-platform/blob/main/THREAT-MODEL.md)
> §1 first.** A holder of `platform:host` has **user-level remote code execution on
> every device that runs the artifact**. `writeCommand` lands its bytes executable in
> a directory on the user's `PATH`; `profileEnsure` writes unfiltered shell into a
> file the login shell runs. Nothing in this repository softens that, and nothing in
> it is a bound on what the bytes do.

```js
const { DECLARATION, host } = require('platform-host')

const h = host('@host', machine)          // the kernel does this, not you
await h.methods.os()                      // 'darwin'
await h.methods.writeCommand('send', shim, '.cmd')   // <binDir>/send.cmd, 0755
await h.methods.profileEnsure([`export PATH="${bin}:$PATH"`])
```

## Why this is a repository

The capability split, and the rule `ArtifactPatform/scripts/all-repos.sh
--check-doors` enforces: **the kernel wires capabilities; it does not implement
them.** Six capabilities the runtime supplies had their declarations in one file in
`artifact-protocol` and their implementations spread over four files in the kernel,
no two sharing a boundary. So a capability was two documents in two repositories
with nothing holding them together.

This is the **last** of the six and it went last on purpose: the largest file, the
adapter-conventions machinery, and an open ceiling. It also had the widest gap between
what was declared and what was proved. Fifteen operations; the kernel's five host
suites reach eleven. And `AGENTS.md` §3's prose table — the only description of these
operations that existed before the declaration was written — **had already drifted and
was missing three of the fifteen**, which is the failure this repository exists to
make impossible.

The order out was [`platform-feed`](https://github.com/AustinPoonia/platform-feed)
and [`platform-blobs`](https://github.com/AustinPoonia/platform-blobs), then
[`platform-network-view`](https://github.com/AustinPoonia/platform-network-view) and
[`platform-documentation`](https://github.com/AustinPoonia/platform-documentation),
then [`platform-store`](https://github.com/AustinPoonia/platform-store), then this.
The name is *derived* — the contract id with the `:` turned into a `-` — so there was
never a mapping to remember.

## What is here, and what is deliberately not

Here:

- **`lib/declaration.js`** — the declared shape, parsed at load through
  `artifact-protocol`'s own `parseShape`. Moved verbatim rather than reworded, and
  for this contract that rule is at its sharpest: this is the text an admin is shown
  before admitting the artifact that gets a shell on every member device.
- **`lib/host.js`** — fifteen operations, the character classes that make a
  provider-named suffix safe, the delimited profile block, and the comparison against
  what an adapter signed.
- **`test/conformance.test.js`** — every declared operation driven, arguments and
  return values run through `contract.validate` against the declaration itself.

Not here, and unlike the other five capabilities the reason is **not** that it needs a
socket or a hypercore. There is no machinery left in `ArtifactPatform/lib/host.js` at
all. What is left is **authority**, which is a different reason for staying:

- **`READABLE_ENV`, the six-name allow-list** — `HOME`, `SHELL`, `TERM`, `LANG`,
  `PATH`, `ARTIFACT_COLUMNS`. It is in the short list of things that must not
  move, beside the scoping table and the minting: letting the contained thing name
  what it may read is letting it write its own containment. A capability repository is
  not an adapter, so the list would have been out of the contained thing's reach here
  too — but the list constrains whoever holds the port, and the party who gets to
  write it is the party that mints the native. So `env` below is a pass-through, and
  that is the design rather than a thinness.
- **the console measurement** — one `uv_tty_get_winsize` on the `bare-stdio`
  singleton `bin/artifact.js` holds. A realm has no `isatty` and no `ioctl`; it does
  not follow that *nobody* can, and the party who can is the process. The **clamp**
  came here, because the declaration promises "a clamped column count" and a promise
  is the promiser's to keep.
- **`chain.js`'s `NATIVE` table** — `@host` is minted **unscoped**, which is why one
  object serves every holder in a network and why nothing reaches `writeCommand`
  carrying the identity of who called it. `@store:<instance>` next door is per
  instance. `THREAT-MODEL.md` §1.3 records that no comment anywhere actually *argues*
  for the unscoping — the behaviour is pinned by an assertion in `boot.js` and the
  word "deliberately" is a claim the tables do not support — and this repo does not
  repair that by asserting it from the wrong side.
- **minting in `boot.js`** — including resolving the signed `conventions` of the
  adapter for *this device's* platform, once, and holding every holder to it.

The machine is therefore a **parameter**. `host()` takes one and `lib/host.js` writes
down the seven members it needs as a typedef, so "what a host needs from the runtime"
is a document rather than whatever the kernel happened to expose.

## What the containment is, stated with what it is not

**A path traversal cannot be spelled.** Command names go through
`/^[a-z][a-z0-9-]{0,63}$/`; suffixes, prefixes and shell names go through `SUFFIX`,
`PREFIX` and `SHELL`, imported from `artifact-protocol` because the same expressions
validate the signed `conventions` block. None can express `/`, `\`, a leading dot or
`..`. The adapter supplies a *name*, never a path component and never a directory, so
the reachable set is `<binDir>/<name><suffix>` and
`<completions>/<shell>/<prefix><name><suffix>`, one directory deep. Traversal is not
checked for; it cannot be written. That is the one strong claim in the contract.

**Two marker strings are refused, and nothing else about a line is.** A
`profileEnsure` line containing `BEGIN` or `END` used to close the platform's block
early, so `profileRemove` cut to it and left the remainder — plus an orphan
delimiter — in a file the login shell runs, while `detach` reported having left no
trace. Both are refused now, as substrings, in both the array and the string form, and
**before** the `profilePath` guard so the same bytes are refused on a device with no
startup file. The rest of the shell grammar is the capability.

**A shim under an existing name is refused, not overwritten — and that is collision
detection, not authorization.** `removeCommand` is on the same unscoped object, so a
holder determined to take a name unlinks it and then creates it. What ended is the
silent clobber and the accident. It is also not atomic, and `{ flag: 'wx' }` was
rejected for a measured reason: `bare-fs@4.7.4` builds every exclusive flag as `… |
constants.O_EXCL` and never defines `O_EXCL`, so the expression ORs `undefined`,
which is `0`. `wx` truncates and reports success.

**An affix that is not the signed one is refused, and that buys integrity rather than
containment.** `.cmd` and `.bat` are both inside `binDir`; neither is more contained.
What the comparison answers is "did this adapter write the file it told an admin it
would write".

## The conformance suite, and the exact edge of what it proves

It reads the shipped, parsed, frozen declaration, walks every operation, and does to
each what `assemble.js`'s `checkedCall` does — arguments in and answer out through
`contract.validate`. Nothing in it restates a shape.

It drives a **real filesystem**, in a temporary directory per case, and that is not a
compromise: `writeCommand`'s guarantee is a claim about a path on a disk, and a mocked
`fs` would let the suite assert its own mock's idea of `path.join` and would pass a
`..` that a real `readdir` would show landing one directory up. The other five
capability repos drive in-memory substrates because a feed, a blob index, a fold and a
b-tree are all data. A host is a disk.

**It proves** that the fifteen operations answer in the declared shape; that no
spelling of a traversal is accepted by any operation that takes a name; that the three
character classes are actually applied to every argument reaching a filename; that an
undeclared affix is refused and that absent and `null` conventions mean different
things; that a different shim under an existing name is refused while an identical one
is a no-op; that the read side recognises a form of a name a previous release wrote;
that either delimiter is refused before the profile guard and that nothing else about
a line is filtered; that the block is maintained by replacement and removal leaves the
rest of the file alone; that a width is clamped and a console beats
`ARTIFACT_COLUMNS` while an absent console does not; and that `env` asks for exactly
one name and adds no second source of its own.

**It cannot prove** that `READABLE_ENV` holds the six names it holds — that list is
`ArtifactPatform/lib/host.js`'s, so what is asserted here is the shape of the promise:
`env` is a pass-through with no fallback, and the declaration's prose still names
exactly six. Nor can it prove that `@host` is minted unscoped, that one `conventions`
is resolved per device rather than per caller, that two adapters for one platform are
refused before a device is reached, or that a refusal from `attach` reaches a person on
stderr. Those are `chain.js`'s, `boot.js`'s and `bin/artifact.js`'s, and
`ArtifactPatform/test/adapter-conventions.test.js`,
`test/signed-conventions.test.js`, `test/platform-boundary.test.js`,
`test/surface.test.js` and `test/entry.test.js` are still the only things that hold
them. All five stayed at their counts when this repo was created, because every one of
them is about a *pair* rather than about this capability.

## Development

```
npm test          # the conformance suite, under the Bare runtime
npm run typecheck
```

Plain JS with JSDoc types, checked by `tsc --checkJs --strict` over the suite as well
as the source. It is not an artifact: no `manifest.json`, no `build`, no ports — which
is load-bearing for the delimiter argument, because `BEGIN`/`END` are the platform's
marker for its own writes and an adapter may not say either, and this package is not
the adapter. Nothing here is installable or testable on its own — it is one of the
twenty-eight repos `ArtifactPatform/scripts/all-repos.sh` runs as a set, because
`artifact-protocol` arrives through `file:../artifact-protocol`.
