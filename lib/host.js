/**
 * `platform:host` — the narrowest authority to act on a machine, and the character
 * classes that are the whole of what makes it narrow.
 *
 * This was `ArtifactPatform/lib/host.js`, which is where "everything else in this
 * platform describes; this is where something finally happens" was written and where it
 * still belongs. Registering `send` as a command a person can type means writing an
 * executable file and putting it on a PATH, and no amount of declarative vocabulary
 * conjures that.
 *
 * The design question is *who* holds that authority. Putting macOS and Linux conventions
 * in the kernel would mean every new platform is a kernel release — exactly the
 * additivity violation ARCHITECTURE §8 exists to prevent. So the platform exposes
 * primitives with no conventions in them, and an **adapter artifact** holds the platform
 * knowledge:
 *
 *     platform  →  os(), shell(), a scoped bin directory, a managed profile block
 *     adapter   →  what a zsh shim looks like, where PATH goes, how completions work
 *
 * A new platform is then a new artifact, signed and shipped like any other.
 *
 * ## What this repo owns and what the kernel kept
 *
 * The capability split's fourth and last wave. The kernel wires capabilities and does not
 * implement them, and this file is the implementation. Two things stayed behind, and
 * unlike the other five capabilities the reason is not "it needs a socket or a
 * hypercore" — it is that they are **authority rather than mechanism**:
 *
 *   - **`READABLE_ENV`, the six-name allow-list.** It stays in
 *     `ArtifactPatform/lib/host.js` as a thing that was not allowed to move, because
 *     letting the contained thing name what it may read is letting it write its own
 *     containment. The `env` operation below is therefore a pass-through to a reader the
 *     kernel built, and that is the point rather than a thinness to apologise for. See
 *     `Machine.env`.
 *   - **the console measurement.** Reading `columns` off fd 1 is one
 *     `uv_tty_get_winsize` on the stream `bin/artifact.js` already holds, and it is the
 *     one thing on the path genuinely attached to a terminal. A realm has no `isatty`
 *     and no `ioctl`; it does not follow that *nobody* can, and the party who can is the
 *     process, not the capability. So `Machine.measure` is the kernel's and the
 *     *clamping* is here, because the declaration promises "a clamped column count".
 *
 * Also stayed, for the reason it stayed for every other capability: `chain.js`'s
 * `NATIVE` table, which mints `@host` **unscoped**, and minting in `boot.js`, which
 * resolves the signed `conventions` of the adapter for *this device's* platform. Both
 * are decisions about isolation and authority that the thing being isolated does not get
 * to make. `THREAT-MODEL.md` §1.3 records that no comment anywhere actually *argues* for
 * `@host` being unscoped — the behaviour is pinned by an assertion in `boot.js` and the
 * word "deliberately" is a claim the tables do not support — and this file does not
 * repair that by asserting it from the wrong side.
 *
 * ## The scoping, which is the whole security story
 *
 * `writeCommand` is not a filesystem. It takes a *name*, never a path, and that name is
 * validated against a character class that cannot express traversal, absolution, or a
 * dotfile. Contents go into one directory the platform owns. An adapter cannot write to
 * `~/.ssh` because there is no argument it could pass that would get it there.
 *
 * `profileEnsure` is the one thing that touches a file the user also owns, so it is
 * deliberately not general: it maintains a single delimited block, replaces that block
 * wholesale, and removes exactly it. An adapter cannot append arbitrary lines to a shell
 * profile, and a user can delete the block by hand without leaving the platform confused
 * about what it wrote.
 *
 * **None of that is a bound on what the bytes do.** `THREAT-MODEL.md` §1 is this
 * contract's threat model and the two operations above are user-level remote code
 * execution by design; what is closed is *where* a file can land, not what it contains.
 * A reader of this header who stops at "the whole security story" has read half a
 * sentence.
 *
 * ## The tables that used to be here, and why they were the exception this file
 * ## was written to forbid
 *
 * Three of them: an executable-suffix map keyed by a `kind`, a completion-suffix map
 * keyed by a shell, and a completion-prefix map keyed by the same. Between them they
 * hard-coded `.cmd`, `.bat`, `.bash`, `.fish`, `.ps1` and zsh's leading underscore,
 * which means elvish, nushell and a signed `.exe` launcher were each a kernel release —
 * the additivity violation the paragraph above says this file exists to prevent, sitting
 * fifteen lines below it.
 *
 * They were not an oversight. `writeCommand`'s guarantee is that traversal *cannot be
 * spelled*, not that it is checked for, and a suffix is concatenated onto a validated
 * name before the join. Hand an adapter a free string there and it can spell
 * `/../../.ssh/authorized_keys`.
 *
 * Both halves are answered rather than one traded for the other. The adapter names its
 * suffix; `artifact-protocol`'s `SUFFIX`, `PREFIX` and `SHELL` decide whether the string
 * is one, and none of the three can express a separator, a leading dot or a `..`. The
 * reachable set is still `<binDir>/<name><suffix>` and
 * `<completions>/<shell>/<prefix><name><suffix>`, still finite, still one directory
 * deep. The classes are imported rather than re-spelled here, because the same
 * expressions validate the `provides[].conventions` block an adapter signs into its
 * manifest, and a containment rule written in two places is two rules with one reader.
 *
 * That import is also the reason this repo depends on `artifact-protocol` for more than
 * a parser: the classes and the declaration's validator arrive from the same package,
 * which is the dependency direction the split forced and the only one available.
 *
 * **What the signature buys, and what it does not.** Containment is the classes, and it
 * always was: every statement in the paragraph above holds whether or not anything
 * compares a declaration with an argument. `.cmd` and `.bat` are both inside `binDir`,
 * and neither is more contained than the other.
 *
 * What the comparison adds is **integrity**, which is a different property with a
 * different reader. An admin running `network check` reads what files an adapter says it
 * will create; until `Machine.conventions` existed, that reading was the only thing
 * holding the adapter to it — the document said `.cmd`, the code could pass `.bat`, and
 * the two disagreeing was discoverable by a person and by nothing else. `boot.js` hands
 * the declaration off the manifest `mintNatives` already has in hand, and an affix that
 * is not the signed one is refused here. So the document is a promise the platform keeps
 * rather than a claim it relays.
 *
 * Three limits, because a half-checked thing believed to be wholly checked is worse than
 * an unchecked one:
 *
 *   - It is **one declaration per host**, not one per caller. `@host` is an unscoped
 *     native (`chain.js`'s `NATIVE` table) so every instance in a network that binds
 *     `platform:host` shares this object, and nothing reaches `writeCommand` carrying the
 *     identity of who called it. `boot.js` resolves the declaration of the adapter for
 *     *this device's* platform and holds every holder to it; its `hostConventions` has the
 *     argument for why that is the right asymmetry rather than a compromise.
 *   - A network with **no** adapter for this platform declares nothing, so `conventions`
 *     arrives `undefined` and nothing is compared. There is no signed statement to
 *     enforce, and inventing one would refuse writes on the grounds that nobody promised
 *     anything about them.
 *   - It says nothing about **contents**. An adapter writes the bytes of its own shim,
 *     and this file has never had an opinion about them.
 *
 * ## What stayed here rather than becoming an adapter's, and the rebuttals
 *
 * **`BEGIN`/`END` stayed, and an adapter may not say either of them.** `#` is a comment
 * in sh, zsh, fish *and* PowerShell, which
 * `ArtifactPatform/test/platform-boundary.test.js` already notes is luck rather than
 * design. That is a good reason to distrust the delimiters and a bad reason to move
 * them, because they are not a shell convention doing a shell's work: they are **the
 * platform's marker for its own writes**, and the only thing that makes `profileEnsure`
 * idempotent and `profileRemove` complete. An adapter that named them could pick a
 * delimiter that never matches what a previous release wrote, and `detach` — which
 * promises to leave no trace — would silently leave one. Two adapters on one device could
 * orphan each other's blocks. The `#` is incidental to that job; a platform whose profile
 * format has no `#` comment needs a different *mechanism*, not a different string, and
 * inventing the declaration before the platform exists would be guessing at its shape.
 *
 * That paragraph used to say "the kernel's marker" and the claim it makes is unchanged by
 * the move, because it was never about a directory: the marker belongs to whoever is not
 * the adapter, and this repo is not the adapter. It is required directly by the kernel,
 * it has no manifest, no build and no ports, and an artifact can never reach it.
 *
 * The argument above says these two lines mean "the platform wrote this", and until
 * `MARKERS` existed an adapter could say them anyway — `profileEnsure` put its caller's
 * lines between the delimiters without ever looking at them, so a line carrying `END`
 * closed the block early and left the remainder in a file the login shell runs. That is
 * the silent orphan this paragraph claims keeping the markers out of the adapter's hands
 * prevents, reachable by the callers the markers were kept from. See `MARKERS` for the
 * leak in full and for why it is a refusal.
 *
 * **`READABLE_ENV` did not stay here, and it is the sharper case.** It is a table of
 * POSIX names, and Windows' `USERPROFILE`, `PATHEXT` and `COMSPEC` are conspicuously
 * absent — so it looks like exactly the same defect as the three suffix tables. It is
 * not: an allow-list is *authority*, not convention. Letting an adapter declare which
 * variables it may read, even from a signed manifest, is letting the thing being
 * contained write its own containment; the admin admitting it would be admitting a claim
 * they cannot evaluate, since "this adapter reads `AWS_SECRET_ACCESS_KEY`" parses as
 * readily as "this adapter reads `PATHEXT`". The split this whole file rests on is that
 * adapters hold conventions and the platform holds authority, and a suffix is a
 * convention while a readable secret is not.
 *
 * That is also why the list is the one piece of this file that could not move,
 * and the argument generalises past adapters: a *capability repo* naming its own
 * allow-list is one step further from the same mistake, not further away from it. The
 * list is `ArtifactPatform/lib/host.js`'s, the ceiling it carries is registered in the
 * kernel's half of the debt ledger, and `env` below reads whatever the kernel's
 * `Machine.env` will answer.
 */
const fs = require('bare-fs')
const path = require('bare-path')
// The three character classes that make a provider-named suffix safe, from the package
// that also validates the signed declaration carrying one. Not a second dependency:
// `artifact-protocol` is already required by `lib/declaration.js`, because a capability
// parses its own shape through the same validator a manifest's goes through.
const { manifest: { SUFFIX, PREFIX, SHELL } } = require('artifact-protocol')

/**
 * A command name a person types. No dots, no slashes, no leading dash — the class is
 * narrow enough that traversal is not something to check for, it is something that
 * cannot be spelled.
 */
const COMMAND = /^[a-z][a-z0-9-]{0,63}$/

const BEGIN = '# >>> artifact platform >>>'
const END = '# <<< artifact platform <<<'

/**
 * The two lines an adapter may not say, and which of them is load-bearing.
 *
 * `profileEnsure` puts its caller's lines *between* these two, and `stripBlock` finds
 * the block by the **first** of each. So a line carrying `END` closes the block early:
 * `profileRemove` cuts to that line and everything after it — the rest of the adapter's
 * lines, and the real `END` — stays in a file the login shell runs, while `detach`
 * reports having left no trace. Reproduced before this existed: one `profileEnsure` of
 * `['export PATH=…', END, 'export EVIL=1']` followed by `profileRemove` leaves `export
 * EVIL=1` and a stray delimiter in `~/.zshrc` permanently, and nothing on the device
 * says so.
 *
 * `BEGIN` is refused too, and it is the weaker case rather than a second one:
 * `stripBlock` matches the real opener first, so a smuggled one does not defeat
 * removal — it defeats *reading*. `profileBlock` answers from the first `BEGIN` to the
 * first `END`, and a person auditing their own profile sees two openings and cannot tell
 * which of them the platform will claim. Refusing both is what makes "the delimiter pair
 * in this file is the platform's pair" true rather than merely intended, and it costs
 * nothing an adapter wanted: a PATH line has no reason to contain this platform's own
 * delimiter.
 *
 * **Refused rather than escaped, and the limit of that.** Escaping would put this file
 * in the business of knowing what a comment looks like in a shell it has never heard of,
 * which is the table this file exists to forbid. What refusing does not do is make
 * `profileEnsure` safe: the lines it accepts are still arbitrary shell the OS later runs,
 * which is `platform:host`'s authority working as designed and belongs in the threat
 * model, not here. This closes one leak in `detach`'s leave-no-trace promise, and that is
 * all it closes.
 */
const MARKERS = [BEGIN, END]

/**
 * How much of a refused line a message shows.
 *
 * A PATH line is recognisable well inside this, and a shim is not bounded at all — an
 * adapter can hand `profileEnsure` a megabyte, and a refusal that quotes all of it makes
 * the diagnostic the second problem. Same kind of number as `NARROWEST`: a fact about a
 * person reading a line, not about any platform.
 */
const SHOWN = 120

/**
 * An adapter's bytes, safe to put in a message.
 *
 * A refusal at a trust boundary has to name what was wrong without becoming the attack.
 * These bytes are the refused party's: an escape sequence can repaint the line above it,
 * and a bare newline forges a second line of output that reads as the platform's own.
 * `ArtifactPatform/bin/artifact.js` replaces the same class on every byte that executable
 * writes, and that outer belt is not the reason this one exists — an `err.message` also
 * reaches `journal.js`, a test harness, and any artifact that catches it, none of which
 * pass through it, and the `\n` that belt deliberately keeps is exactly the character
 * that forges a line here.
 *
 * `JSON.stringify` covers the C0 range, the quote and the backslash. DEL, C1 and the two
 * line separators survive it, so they are escaped after it — the class is
 * `bin/artifact.js`'s `CONTROL`, minus the range `JSON.stringify` already did.
 *
 * @param {string} text
 * @returns {string}
 */
function legible (text) {
  const safe = JSON.stringify(text.length > SHOWN ? text.slice(0, SHOWN) : text).replace(
    /[\u007f-\u009f\u2028\u2029]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`
  )
  return text.length > SHOWN ? `${safe} (the first ${SHOWN} of ${text.length} characters)` : safe
}

/**
 * The bounds a width has to be inside to be worth passing to a renderer.
 *
 * These were three byte-identical copies, one per adapter, and they were never platform
 * knowledge — 20 and 1000 are facts about arithmetic in a renderer, not about zsh or
 * PowerShell. `ARTIFACT_COLUMNS` is a string out of a user's environment, so it is not
 * merely possibly wrong, it is possibly hostile: a `text@1` renderer builds a rule per
 * framed panel, so `10000000` costs a 30MB string per command and `1000000000` throws
 * `Invalid string length` from the middle of a render, which reads as the platform being
 * broken rather than as an environment being silly. Below 20 there is nothing a frame can
 * do.
 *
 * A genuinely wider terminal than 1000 gets a 1000-column render: narrow, not broken, the
 * same kind of wrong the 80-column fallback already is.
 *
 * They are on **this** side of the split and the console measurement is on the kernel's,
 * which is the line the declaration draws rather than one this file chose: `columns` is
 * declared to answer "a clamped column count", so the clamp is part of what the contract
 * promises and the measurement is a thing only the process holding fd 1 can do.
 */
const NARROWEST = 20
const WIDEST = 1000

/**
 * A width, or null if the value is not one.
 *
 * @param {unknown} value
 * @returns {number | null}
 */
function sane (value) {
  const width = Number(value)
  if (!Number.isFinite(width) || width < NARROWEST) return null
  return Math.min(Math.floor(width), WIDEST)
}

/**
 * The command a filename in `binDir` is a form of, or null if it is not one.
 *
 * This is the inverse of `<name><suffix>`, and it has to exist because the three
 * read-side methods have to recognise a file whose suffix a *previous release* of the
 * adapter chose. A platform that knew the suffixes could only recognise the ones it had
 * been told about, which is the same closed-table problem one door along.
 *
 * The split is unambiguous rather than a guess: the command class admits no dot and
 * `SUFFIX` requires one, so the first dot is the boundary and there is exactly one way
 * to read a filename.
 *
 * @param {string} file
 * @returns {string | null}
 */
function commandOf (file) {
  const dot = file.indexOf('.')
  if (dot === -1) return COMMAND.test(file) ? file : null
  const name = file.slice(0, dot)
  return COMMAND.test(name) && SUFFIX.test(file.slice(dot)) ? name : null
}

/**
 * @param {string} id       the native target name, `@host`
 * @param {Machine} machine what the runtime knows and what it will let this read
 * @returns {NativeInstance}
 */
function host (id, machine) {
  const { binDir, profilePath, conventions } = machine

  /**
   * An affix the adapter supplied, checked against the class that makes it safe — or
   * refused. Absent means none, which is what a POSIX shim wants and what every caller
   * written before affixes existed passes.
   *
   * The check is the whole substitute for the tables that used to be here. It is
   * deliberately not a membership test against a list of suffixes the platform likes: a
   * list is what made elvish a kernel release. What it tests is the one property that is
   * actually needed, which is that the string cannot be part of a path.
   *
   * @param {unknown} value
   * @param {RegExp} shape
   * @param {string} what
   * @returns {string}
   */
  const affix = (value, shape, what) => {
    if (value === undefined || value === null || value === '') return ''
    const text = String(value)
    if (!shape.test(text)) {
      throw new Error(
        `${JSON.stringify(text)} is not ${what} — ${shape.source}. ` +
        'It is concatenated onto a validated name and then joined to a directory, so a class that could ' +
        'spell a separator would turn "a traversal cannot be written" into "a traversal is checked for"'
      )
    }
    return text
  }

  /**
   * The affix the signed declaration names for this file, or `undefined` when nothing
   * signed reached this host and there is therefore nothing to compare.
   *
   * The two absences are kept apart deliberately. `conventions === undefined` is "no
   * adapter for this platform is in the network's set"; `conventions.executable ===
   * undefined` is "an adapter is here and says it writes a bare name". The first must not
   * enforce and the second must enforce `''`, and collapsing them — the obvious
   * `conventions?.executable` — would silently turn every adapter that declares nothing
   * into an adapter nobody checks, which is exactly the two adapters in this tree that
   * need checking most cheaply.
   *
   * `null` from `boot.js` and `undefined` on the property are both the second case.
   * `boot.js` sends `null` because a `provides` entry with no `conventions` key still came
   * off a manifest an author signed, and `undefined` there would be indistinguishable from
   * the argument not being passed at all. The `Machine` typedef keeps that distinction
   * spellable — `conventions` is optional *and* nullable — which is the one place the seam
   * had to be written more carefully than the code it replaced.
   *
   * @param {string | undefined} value
   * @returns {string | undefined}
   */
  const declaredAffix = (value) => (conventions === undefined ? undefined : value ?? '')

  /**
   * Hold a class-checked affix to the one the adapter signed.
   *
   * Runs *after* `affix`, never instead of it, and the order is load-bearing in one
   * direction only: containment is the character class, so a declaration that somehow
   * named a separator would still be refused by `affix` before this ran. This adds
   * nothing to containment and is not a second line of defence for it —
   * `artifact-protocol` validates a signed `conventions` block against the same three
   * expressions, so a manifest naming `../` never parsed.
   *
   * What it is, is the answer to "did this adapter write the file it told an admin it
   * would write". A refusal names both spellings, because the repair is in one of two
   * places and this file cannot know which: the code is wrong, or the manifest is stale
   * and needs republishing.
   *
   * @param {string} value          what the adapter passed, already class-checked
   * @param {string | undefined} declared   what it signed, or undefined for nothing to compare
   * @param {string} what
   * @returns {string}
   */
  const asDeclared = (value, declared, what) => {
    if (declared === undefined || value === declared) return value
    const said = declared === '' ? 'none' : JSON.stringify(declared)
    throw new Error(
      `this adapter declared ${what} of ${said} and passed ${JSON.stringify(value)}. ` +
      'The declaration is signed into the manifest an admin admitted and is what they were shown this ' +
      'adapter would create, so the two have to agree — republish the manifest or pass what it says'
    )
  }

  /**
   * A path inside one platform-owned directory, built from a validated name and a
   * validated affix.
   *
   * The adapter supplies a *name* and, where the platform needs one, an affix narrow
   * enough that it cannot be part of a path. It never supplies a path component or a
   * directory. That is what keeps `..`, an absolute path and a dotfile unreachable — not
   * a check on the way out, but the absence of any argument that could express one.
   *
   * @param {string} dir
   * @param {string} name
   * @param {string} [suffix]
   * @param {string} [prefix]
   */
  const inside = (dir, name, suffix = '', prefix = '') => {
    const value = String(name)
    if (!COMMAND.test(value)) {
      throw new Error(`${JSON.stringify(value)} is not a command name: lowercase, digits and hyphens, starting with a letter`)
    }
    return path.join(dir, prefix + value + suffix)
  }

  /** @param {string} name @param {unknown} suffix */
  const named = (name, suffix) => inside(binDir, name, asDeclared(
    affix(suffix, SUFFIX, 'an executable suffix'),
    declaredAffix(conventions?.executable),
    'an executable suffix'
  ))

  /**
   * The directory this shell's completions live in.
   *
   * One segment, so the shell name is validated as strictly as a command name is. It used
   * to be a lookup in a four-entry table, which is why a correct elvish completion could
   * be generated and never installed.
   *
   * @param {unknown} shell
   * @returns {string | null}
   */
  const completions = (shell) => {
    const key = String(shell)
    if (!SHELL.test(key)) return null
    return path.join(path.dirname(binDir), 'completions', key)
  }

  /**
   * Every filename in `binDir` that is a form of a command, as name/path pairs.
   *
   * A missing directory is a device nothing has attached to, not an error.
   *
   * @returns {Promise<{ name: string, file: string }[]>}
   */
  const installed = async () => {
    try {
      const files = /** @type {string[]} */ (await fs.promises.readdir(binDir))
      /** @type {{ name: string, file: string }[]} */ const out = []
      for (const file of files) {
        const name = commandOf(file)
        if (name !== null) out.push({ name, file })
      }
      return out
    } catch {
      return []
    }
  }

  return {
    id,
    contract: 'platform:host',
    methods: {
      /** 'darwin', 'linux', 'win32'. An adapter switches on this and nothing else. */
      os () { return machine.platform },

      arch () { return machine.arch },

      /**
       * The login shell's basename — 'zsh', 'bash', 'fish' — or null.
       *
       * Which shell a person uses decides where a PATH line goes, and getting it wrong
       * writes into a file nobody reads.
       */
      shell () {
        const value = machine.env('SHELL')
        return value ? value.split('/').pop() : null
      },

      /**
       * A small allow-list. An adapter has no business reading the environment at large.
       *
       * A pass-through, and that is the design rather than a thinness. The list is
       * `ArtifactPatform/lib/host.js`'s `READABLE_ENV` and it could not move: an
       * allow-list is authority, and a capability repo naming its own is one step closer
       * to the contained thing writing its own containment, not further from it. What
       * this file guarantees is only that it asks for one name and does not fall back —
       * `Machine.env` answers `null` for anything off the list, so a name outside it
       * reads null rather than being refused and the caller learns nothing about whether
       * it was set.
       */
      env (name) {
        return machine.env(String(name))
      },

      /**
       * How wide the destination is, already bounded — or null when nothing knows.
       *
       * The one number an adapter could not obtain and had to be told. It is returned
       * already clamped, which is the point: the same 20/1000 bounds were open-coded
       * identically in all three adapters, each re-deriving them from a raw string, and a
       * fourth adapter would have written them a fourth time. An adapter now needs only a
       * default for `null`, which is the one part that genuinely is its own (80 on a
       * terminal, and it can say so).
       *
       * ## Measurement beats the environment, and that ordering is deliberate
       *
       * `ARTIFACT_COLUMNS` is consulted only when there is nothing to measure. It reads
       * backwards until you notice who sets it: the *shim* does, from
       * `${COLUMNS:-$(tput cols)}`, so treating it as an override would mean a shell's
       * guess — possibly a stale `COLUMNS`, possibly 80 because `tput` is not installed —
       * silently beating a live `ioctl` on the very terminal being written to. When there
       * is a console, the console is the authority. When there is not — a pipe, a file,
       * `cron` — the string is all there is, and it is honoured.
       *
       * The cost, stated with the benefit: a person who sets `ARTIFACT_COLUMNS` by hand
       * to force a width *and* is on a real terminal is now ignored. That is a real
       * regression for a real workflow, and it is the price of the ordering; the way back
       * is a distinct name that means "override" rather than one name that means both
       * "measured for you" and "I insist".
       *
       * That name has not been built, so until it is, **the workaround belongs here beside
       * the cost rather than left to be re-derived from the sentence above: redirect
       * stdout.** A pipe or a file is not a terminal, `measure()` answers null for it, and
       * the `??` falls through — so `ARTIFACT_COLUMNS=600 artifact health > wide.txt`
       * renders at 600 where the same command on a console renders at the console's width
       * and drops the variable on the floor. Nothing about that is a trick; it is the
       * "there is nothing to measure" branch, reached deliberately.
       *
       * And it is worth saying that this is not merely a preference for a roomier render,
       * because the case that needs it cannot be served by any ordering. `artifact-ui`
       * *clips* a `text` node and folds only a `paragraph`, and a view is free to put prose
       * in the former — `artifact-health`'s `limits()` rows reach 526 cells, which is
       * inside the `WIDEST` clamp above and outside every real terminal. For those rows the
       * redirect is the only way to read the output at all, on any machine, at any width;
       * reversing the precedence would not have helped, and the repair is the sending
       * artifact's node type rather than anything in this method.
       *
       * ## An absent `measure` is "there is nothing to measure"
       *
       * `Machine.measure` is optional, and the kernel omits it in exactly one case: an
       * injected environment. A test's environment is meant to be its whole world, and
       * measuring the real fd 1 underneath one would make a suite's expected width depend
       * on whether it was run from a terminal or captured to a file — a green run and a
       * red run from the same bytes, which is the exact class of measurement bug this
       * tree has been bitten by before. Before the split that was an `if (env)` inside
       * this method; after it, "is there a console" is a fact about the substrate and the
       * substrate says so by supplying or withholding the function. The behaviour is
       * identical and the question is now asked by whoever can answer it.
       */
      columns () {
        const declared = sane(machine.env('ARTIFACT_COLUMNS'))
        if (machine.measure === undefined) return declared
        return sane(machine.measure()) ?? declared
      },

      /** Where commands live, so an adapter can put it on a PATH. */
      binPath () { return binDir },

      /**
       * Where completion scripts live for one shell.
       *
       * Beside `binDir` rather than inside it, because everything in `binDir` is on a PATH
       * and a completion script is not a command.
       *
       * Null now means only that the name could not be a directory. It used to mean "a
       * shell the platform has not heard of", which is why an adapter could generate a
       * correct elvish completion and have nowhere to put it.
       */
      completionPath (shell) {
        return completions(shell)
      },

      /**
       * Install a command shim, under a name nothing else here already holds.
       *
       * The name is validated, the suffix is validated, the contents are whatever the
       * adapter decided a shim looks like on this platform, and the file lands executable
       * in one directory. That is the entire authority granted — and `THREAT-MODEL.md` §1
       * is what "that is the entire authority" costs: the file is on the user's PATH and
       * nothing here reads its bytes, so admitting an artifact that declares this port is
       * the same decision as giving its author a shell on every member device.
       *
       * `chmod 0755` is the POSIX half of "this is executable" and does nothing on
       * Windows, where `PATHEXT` decides and the suffix is the whole statement. Both are
       * done unconditionally because this file does not know which platform the adapter
       * is — and must not, which is the point of the adapter holding the suffix.
       *
       * ## First writer of a name owns it, because nothing here knows who called
       *
       * This used to be a plain `writeFile`, which is last-writer-wins. `@host` is an
       * unscoped native — one object shared by every instance in a network that binds
       * `platform:host`, and `callNative` carries no caller identity — so *any* holder
       * could hand this the name another adapter had already installed and replace the
       * bytes on a file that is on the user's PATH. Silently: the second write reported
       * the same path as the first, and nothing on the device recorded that the shim a
       * person types is not the one the adapter that claimed the name wrote.
       *
       * An identical rewrite is still accepted, and that is not a hole in it: `attach`
       * runs on every boot, a boot is every command, and the three adapters here generate
       * a shim deterministically from the command name — so the steady state is the same
       * bytes, and a write that changes nothing cannot be a clobber. What is refused is a
       * *different* shim under a name already installed.
       *
       * ## Why this is a read and not `{ flag: 'wx' }`
       *
       * Because `wx` does nothing here, and does it silently. `bare-fs@4.7.4` builds its
       * flags in `toFlags`, where every exclusive form is `… | constants.O_EXCL` — and
       * `lib/constants.js` never defines `O_EXCL`, so the expression ORs `undefined`,
       * which is `0`. `wx` therefore opens exactly like `w`: it truncates an existing file
       * and reports success. Measured, not read: a two-line probe overwrote a file through
       * `writeFile(p, bytes, { flag: 'wx' })` on this runtime. So the obvious one-word
       * version of this fix is a green test and an open leak, which is the class of bug
       * this tree has shipped three times.
       *
       * Rejected, and why it lost: writing a temp file in `binDir` and `link()`ing it onto
       * the target *is* atomic and does answer `EEXIST` here. It costs a temp name inside
       * the directory that is on the user's PATH, a hard-link capability this would then
       * be assuming of every filesystem a home directory can sit on, and cleanup on every
       * failure path — to buy atomicity against a racer who, per the limit below, can
       * simply call `removeCommand` first. A read that could be a stat is not worth that.
       *
       * ## Three limits, and what an operator sees
       *
       * This is **collision detection, not authorization.** `removeCommand` is on the same
       * unscoped object, so a holder determined to take a name can unlink it first and then
       * create it. What this ends is the silent clobber and the accident; a two-step theft
       * is still available to an artifact that has already been admitted to the network,
       * which is the authority an adapter simply has, as was measured. The same sentence is
       * why the check being a read rather than an atomic create costs nothing an attacker
       * was short of: two holders racing between the read and the write is a longer road to
       * the same place as one `removeCommand`.
       *
       * It is per **file**, not per name. `send` and `send.cmd` are two paths and both may
       * exist — deliberately, since `listCommands` dedupes and `removeCommand` clears every
       * form precisely so an adapter can change its suffix between releases. Where a signed
       * declaration exists, `asDeclared` closes that gap from the other side by holding
       * every holder to one affix; where none does, a second *form* of a name is still
       * reachable.
       *
       * **What the collision looks like.** The refusal is thrown to the adapter's `attach`,
       * so `bin/artifact.js` prints `artifact: could not register commands: …` on stderr
       * before each command and runs the command anyway. It names the file and says who has
       * to act, because nothing here can name the two claimants: the two places that *can*
       * are `boot.js`'s `classify` and `hostConventions`, which refuse two adapters for one
       * platform by name from documents, before a device ever gets here. This is the runtime
       * backstop for the case those cannot see — a second network on the same device (one
       * `binDir`, several networks), or a holder that never claimed the command line at all.
       *
       * ponytail: two ceilings, and neither is closable here. A legitimate change of shim
       * bytes — a republished adapter, or a person who edited the generated file — is refused
       * until the name is freed, because this cannot tell either from a clobber; the upgrade
       * path is caller identity, since a caller id reaching `callNative` would let this
       * record an owner per name and admit that owner's rewrite. Whether `@host` is scoped
       * is `chain.js`'s `NATIVE` table to decide and not this file's, and that stayed true
       * across the move: the table is in `artifact-planner` and a capability does not write
       * its own scope. The second ceiling is atomicity, and its upgrade path is one word: an
       * `O_EXCL` that exists makes the read below a `{ flag: 'wx' }`. The trigger for the
       * first is the first adapter whose shim changes between releases on a device that has
       * already attached; for the second, a `bare-fs` that defines the constant.
       */
      async writeCommand (name, contents, suffix) {
        const target = named(name, suffix)
        const bytes = String(contents)
        await fs.promises.mkdir(binDir, { recursive: true })

        // A file that cannot be read is a file that cannot be confirmed, so the
        // unreadable case answers `null` and falls on the refusing side of this
        // comparison rather than into a `catch` that lets the write through.
        const found = await fs.promises.readFile(target).then((/** @type {any} */ b) => b.toString(), () => null)
        if (found !== null && found !== bytes) {
          throw new Error(
            `${target} already holds a different command, and ${id} is one object shared by every holder with ` +
            'nothing carrying the identity of who called it — so this cannot tell an adapter reinstalling its ' +
            'own command from a second one taking the name, and refuses rather than overwrite a file on the ' +
            'PATH. Whoever owns the command releases the name first — `artifact detach`, or `removeCommand` — ' +
            'and the next boot installs this one'
          )
        }

        // The identical case is a no-op and not a rewrite, for `profileEnsure`'s reason:
        // `attach` runs before every command, so writing unconditionally would rewrite
        // every shim on the device several times a minute.
        if (found === null) await fs.promises.writeFile(target, bytes)

        // The chmod is not conditional, because the mode is the platform's half of "this
        // is executable" and a file some other writer left 0644 is not a command yet.
        await fs.promises.chmod(target, 0o755)
        return target
      },

      /**
       * Install a completion script for one shell.
       *
       * Mode 0644, not 0755: a completion is sourced, never executed, and a file that does
       * not need to be executable should not be.
       *
       * A malformed shell name throws rather than answering null, unlike
       * `completionPath`: asking where one goes is a question, and writing one to nowhere
       * is a mistake.
       *
       * It is still **last-writer-wins**, unlike `writeCommand`, and
       * `THREAT-MODEL.md` §1.4 records why that is left open rather than overlooked: the
       * completions directory is beside `binDir` rather than inside it, so nothing here is
       * on a PATH, and a completion is sourced rather than executed.
       */
      async writeCompletion (name, shell, contents, naming) {
        const dir = completions(shell)
        if (dir === null) {
          throw new Error(
            `${JSON.stringify(String(shell))} is not a shell name: a letter, then lowercase letters, digits and ` +
            'hyphens. It becomes one directory beside the command directory, so it is checked as strictly as a command is'
          )
        }
        const n = /** @type {Record<string, unknown>} */ (naming ?? {})
        // Per shell, and a shell the declaration does not list is held to the empty
        // affixes rather than left unchecked. An adapter that declared `bash` and then
        // wrote `_send` into `completions/zsh` named a file it never told an admin about,
        // which is the same fault as the wrong executable suffix and not a lesser one.
        const declared = String(shell) in (conventions?.completions ?? {})
          ? /** @type {Record<string, {prefix?: string, suffix?: string}>} */ (conventions?.completions)[String(shell)]
          : {}
        const target = inside(
          dir,
          name,
          asDeclared(affix(n.suffix, SUFFIX, 'a completion suffix'), declaredAffix(declared.suffix), `a ${shell} completion suffix`),
          asDeclared(affix(n.prefix, PREFIX, 'a completion prefix'), declaredAffix(declared.prefix), `a ${shell} completion prefix`)
        )
        await fs.promises.mkdir(dir, { recursive: true })
        await fs.promises.writeFile(target, String(contents))
        await fs.promises.chmod(target, 0o644)
        return target
      },

      /**
       * Take one command back off, in every form of the name that is there.
       *
       * It takes no suffix, and that is the fix rather than an omission. `detach` feeds
       * `listCommands` straight into this, so a signature that wanted a suffix would
       * require the caller to remember what a *previous release* of the adapter wrote —
       * and an adapter that changed its suffix would strand the old file while promising to
       * leave no trace.
       */
      async removeCommand (name) {
        // Validate first, so a caller passing something that is not a command name is
        // told so rather than quietly told there was nothing to remove.
        const value = String(name)
        if (!COMMAND.test(value)) {
          throw new Error(`${JSON.stringify(value)} is not a command name: lowercase, digits and hyphens, starting with a letter`)
        }

        let removed = false
        for (const { name: found, file } of await installed()) {
          if (found !== value) continue
          try {
            await fs.promises.unlink(path.join(binDir, file))
            removed = true
          } catch {
            // Removing something already gone is the desired end state, not an error —
            // and a concurrent `detach` is exactly how that happens.
          }
        }
        return removed
      },

      /**
       * Every command installed here, sorted, as **names**.
       *
       * It used to return filenames that matched the command class, which was the same
       * thing only while no suffix existed. On a device holding `send.cmd` it returned
       * nothing: `detach` fed that empty list into `removeCommand` and reported honestly
       * that it had removed nothing, from a directory full of commands. The dedupe is for a
       * device carrying two forms of one name across an adapter's suffix change.
       */
      async listCommands () {
        return [...new Set((await installed()).map(({ name }) => name))].sort()
      },

      /** Whether one command is installed, in any form. */
      async hasCommand (name) {
        const value = String(name)
        if (!COMMAND.test(value)) return false
        return (await installed()).some(({ name: found }) => found === value)
      },

      /**
       * Maintain one delimited block in the user's shell profile.
       *
       * Wholesale replacement rather than appending, so running this twice leaves one
       * block and not two — an adapter that is re-attached on every boot must not grow the
       * file each time.
       *
       * The lines themselves are **unfiltered shell**, which the login shell runs at every
       * login. That is `platform:host`'s authority working as designed and it is
       * `THREAT-MODEL.md` §1's subject; the two refusals below close a leak in `detach`'s
       * leave-no-trace promise and filter nothing else.
       *
       * ## A line may not contain a delimiter, and it is refused before the read
       *
       * `MARKERS` has the leak and the argument. What the *order* here says is that this is
       * a fact about the content and not about the device: the marker check runs before the
       * `profilePath` guard, so a line carrying a delimiter is refused on a machine with no
       * profile too. Putting it after would make the same adapter bytes throw on a zsh
       * device and answer `false` on a device whose login shell is not recognised — a fault
       * that reproduces on some of a fleet, which is how it gets found a release late by
       * whoever has the unlucky shell.
       *
       * It also throws rather than answering `false`. `false` already means something
       * here — *there was no profile to write* — and both adapters that read it treat it as
       * `onPath: false` and carry on, which is exactly the silence a refusal at a trust
       * boundary must not be. The throw reaches a person: `bin/artifact.js` catches
       * `attach`'s failure and prints `could not register commands: …` on stderr, per
       * command, without taking the command down.
       */
      async profileEnsure (lines) {
        const said = Array.isArray(lines) ? lines.map(String) : [String(lines)]
        for (let i = 0; i < said.length; i++) {
          for (const marker of MARKERS) {
            if (!said[i].includes(marker)) continue
            throw new Error(
              `line ${i + 1} of ${said.length} contains ${JSON.stringify(marker)}, which is this platform's own ` +
              `delimiter for the block it manages: ${legible(said[i])}. The block is found by the first ` +
              'delimiter of each pair, so a line carrying one ends it early and leaves the rest in a file the ' +
              'login shell runs — which `profileRemove` then cannot take back, and `detach` reports having ' +
              'left no trace. Write the line without it'
            )
          }
        }

        if (!profilePath) return false

        const block = [BEGIN, ...said, END].join('\n')
        const existing = await fs.promises.readFile(profilePath).then((/** @type {any} */ b) => b.toString(), () => '')

        const next = stripBlock(existing).trimEnd()
        const wanted = (next ? next + '\n\n' : '') + block + '\n'

        // Unchanged is a no-op, not a rewrite. `attach` runs on every boot and a boot is
        // currently every command, so writing unconditionally would touch the user's
        // shell profile several times a minute — and would race a person editing it for no
        // gain.
        if (wanted === existing) return true

        // The directory may not exist: fish keeps its config under ~/.config/fish, which a
        // machine that has never run fish does not have, and writeFile would throw ENOENT
        // rather than create it.
        await fs.promises.mkdir(path.dirname(profilePath), { recursive: true })
        await fs.promises.writeFile(profilePath, wanted)
        return true
      },

      async profileRemove () {
        if (!profilePath) return false
        const existing = await fs.promises.readFile(profilePath).then((/** @type {any} */ b) => b.toString(), () => null)
        if (existing === null) return false
        await fs.promises.writeFile(profilePath, stripBlock(existing))
        return true
      },

      /** What the platform currently has in the profile, for inspection. */
      async profileBlock () {
        if (!profilePath) return null
        const existing = await fs.promises.readFile(profilePath).then((/** @type {any} */ b) => b.toString(), () => '')
        const start = existing.indexOf(BEGIN)
        const stop = existing.indexOf(END)
        if (start === -1 || stop === -1 || stop < start) return null
        return existing.slice(start, stop + END.length)
      }
    }
  }
}

/** @param {string} text */
function stripBlock (text) {
  const start = text.indexOf(BEGIN)
  const stop = text.indexOf(END)
  if (start === -1 || stop === -1 || stop < start) return text
  return (text.slice(0, start) + text.slice(stop + END.length)).replace(/\n{3,}/g, '\n\n')
}

/**
 * What the runtime knows about this machine, and what it will let this capability read.
 *
 * Written down here rather than inferred from whatever the kernel exposes, for
 * `platform-blobs`'s reason: an interface a consumer discovered by reading its supplier
 * is an interface that changes when the supplier is refactored. Five of the seven members
 * are plain facts; the two that carry the split are the two the kernel would not give up:
 *
 *   - **`env`** is *allow-listed by the kernel*, and that is the whole of why it is a
 *     function on this object rather than a `Record<string, string>` this file could
 *     filter. `READABLE_ENV` — `HOME`, `SHELL`, `TERM`, `LANG`, `PATH`,
 *     `ARTIFACT_COLUMNS` — is `ArtifactPatform/lib/host.js`'s and it could not
 *     move, because an allow-list is authority and the contained thing does not name its
 *     own containment. A name off the list answers `null` rather than being refused, so
 *     the caller learns nothing about whether it was set.
 *   - **`measure`** is optional, and its absence *means* "there is nothing to measure".
 *     The kernel omits it when a test injected an environment, because a test's
 *     environment is meant to be its whole world; see `columns`. When present it answers
 *     the console's own column count, **unclamped** — the clamp is `sane`'s, here,
 *     because the declaration promises a clamped number.
 *
 * `conventions` is optional *and* nullable and the two absences mean different things:
 * `undefined` is "no adapter for this platform is in the network's set, so there is
 * nothing signed to hold anyone to", `null` is "an adapter is here and declared no
 * affixes, so the empty ones are the only ones it may pass". `declaredAffix` is where that
 * distinction is spent, and collapsing it would turn every adapter that declares nothing
 * into an adapter nobody checks.
 *
 * @typedef {object} Machine
 * @property {string} platform                          what the runtime reports, or a suite's override
 * @property {string} arch
 * @property {string} binDir                            the directory the platform owns for command shims
 * @property {string} [profilePath]                     the user's shell profile, if there is one
 * @property {(name: string) => string | null} env      allow-listed by the kernel; off-list reads null
 * @property {() => number | null} [measure]            the console's own width, unclamped; absent means nothing to measure
 * @property {import('artifact-protocol/manifest').Conventions | null} [conventions]
 */

/**
 * What the kernel's `assemble.js` calls a native instance.
 *
 * Declared here rather than imported, because importing it is the cycle: the kernel is
 * this package's consumer. Structurally identical on purpose — TypeScript is structural,
 * so the kernel's own type is satisfied by this without either side naming the other.
 *
 * @typedef {object} NativeInstance
 * @property {string} id
 * @property {string} contract
 * @property {Record<string, (...args: any[]) => any>} methods
 */

/**
 * `COMMAND`, `BEGIN` and `END` are on the surface and `MARKERS`, `SHOWN`, `legible`,
 * `sane` and `commandOf` are not, and the line is the one `platform-blobs` drew: a helper
 * goes on the surface when something outside needs it, and not otherwise.
 *
 * All three that are exported have consumers. `ArtifactPatform/test/entry.test.js` reads
 * `COMMAND` to check the command names `bin/artifact.js` accepts against the class that
 * decides what can be written, and `test/adapter-conventions.test.js` and
 * `test/platform-boundary.test.js` read `BEGIN` and `END` to assemble a profile by hand
 * and to prove a smuggled delimiter is refused. Those are claims about the *pair* of
 * files — the platform's marker and the kernel's own executable — so they stay in the
 * kernel and reach these through its re-export.
 *
 * The rest are observable through the fifteen operations: a clamped width, a refused
 * line quoted safely, a filename recognised across an adapter's suffix change.
 */
module.exports = { host, COMMAND, BEGIN, END }
