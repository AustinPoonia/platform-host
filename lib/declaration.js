/**
 * What `platform:host` promises, as the capability's own document.
 *
 * This was one entry in `artifact-protocol/lib/capability.js`'s `RAW` table — the
 * last of the six to leave — and the argument for moving it is not tidiness: a
 * capability whose *shape* is written in a package it does not own cannot be revised,
 * versioned or refused without a release of that package, and a capability whose shape
 * and implementation sit in two repositories is two documents that can disagree
 * silently. That was never abstract here. `AGENTS.md` §3 listed these operations in a
 * prose table and the table had **already drifted — it was missing three of the
 * fifteen**, which `artifact-protocol`'s own header records as the reason this
 * declaration was written in the first place. Here the declaration and the
 * implementation are one repository and `test/conformance.test.js` drives the second
 * against the first on every run.
 *
 * ## This is the declaration of the platform's largest authority
 *
 * `THREAT-MODEL.md` §1 is about this contract, and it is not softened anywhere in this
 * repository. Two of the operations below are, between them, **arbitrary code
 * execution as the user on every device that runs the artifact**: `writeCommand`
 * writes the holder's bytes to a directory on the user's `PATH` and `chmod`s them
 * 0755, and `profileEnsure` writes the holder's lines into the user's shell profile,
 * which the login shell runs at every login. The lines are unfiltered shell; two
 * marker strings are refused and the rest of the shell grammar is the capability.
 *
 * The description below says "**Adapters only**", and that sentence is a statement of
 * *intent rather than of mechanism* — which `THREAT-MODEL.md` §1.2 corrects in as many
 * words and this file must not un-correct. Nothing in the code restricts the contract
 * to adapters: `artifact-planner/lib/chain.js`'s `NATIVE` maps by contract id alone, so
 * **any** artifact whose manifest declares a `platform:host` port holds this authority,
 * whatever kind declares it. The gate is artifact-set membership — an admin's
 * `group.artifact.add`, made reviewable by the port being in a signed manifest they can
 * read with `network check` before signing. The sentence stays because it is what the
 * platform *asks of authors* and because it is what every device already reads through
 * `platform:documentation`; the correction stays in the threat model because that is
 * the document an operator reads before deploying.
 *
 * ## The shape is parsed, not merely written
 *
 * `parseShape` is the same validator a manifest's declaration goes through, and it runs
 * at **load** — the reason `capability.js` gave for checking its own table at load
 * applies unchanged here, and applies harder to a single-entry file: a shape that is
 * quietly malformed would surface at a call boundary on a device, mid-call, blaming the
 * kernel for a fault in this file's prose.
 *
 * Rejected: exporting the raw object and letting the kernel parse it. That puts the
 * parse at the consumer, so a second consumer either repeats it or skips it, and "skips
 * it" is the one that ships.
 *
 * ## `env`'s six names are listed here and enforced somewhere else, deliberately
 *
 * The `env` operation's description names `HOME`, `SHELL`, `TERM`, `LANG`, `PATH` and
 * `ARTIFACT_COLUMNS`. The list that actually decides is `READABLE_ENV` in
 * `ArtifactPatform/lib/host.js` and it **did not move**, because an allow-list is
 * *authority* rather than convention: letting the contained thing name what it may read
 * is letting it write its own containment. So the six words below are a *promise about*
 * a list this repo cannot change, which is an unusual arrangement and is the right one —
 * and `test/conformance.test.js` pins the two together from this side by driving a
 * substrate that enforces exactly those six and asserting the description still names
 * them. A seventh name added in the kernel and not here would be a promise the platform
 * has outgrown; a seventh named here and not in the kernel would be a promise it cannot
 * keep. Either way one of the two suites fails.
 *
 * ## The namespace check stayed, and it is not ceremony
 *
 * `capability.js` checked every member of its table for the `platform:` prefix, on the
 * argument that an unprefixed id is one an artifact may legitimately declare for
 * itself — so this file would be a second declaration of somebody's signed contract, and
 * the shape resolvers seed the platform table *first*, so this file would win and the
 * author would have no way to see why. That argument does not weaken when the table has
 * one row; it is just that the only way to break it here is to edit the literal below.
 * The check costs a line and fails at load rather than on a device.
 *
 * What it does **not** check is that this id is one the runtime actually mints. That is
 * `chain.js`'s `NATIVE` table and the kernel's `mintNatives` switch, and the kernel's
 * own suite is where the three lists are pinned to each other — this repo cannot see
 * two of them and must not pretend to.
 */
const { capability, contract } = require('artifact-protocol')

/** The contract id. The repo's name is this with the `:` turned into a `-`. */
const ID = `${capability.PLATFORM_PREFIX}host`

/**
 * `1.0.0`, and that is a statement rather than a placeholder.
 *
 * The whole shipped tree ports this at `^1.0.0` — including the three adapters, which
 * is what makes a second version of *this* contract the most expensive one in the set:
 * a device with an older runtime and a newer adapter is a device with a shim it cannot
 * write. So the day one appears this file gains a second entry in `DECLARATIONS` rather
 * than editing the first, and the interesting work is in `chain.js` — a port whose range
 * no supplied version satisfies is a graph fault nothing currently reports.
 */
const VERSION = '1.0.0'

/**
 * The declared shape, verbatim as it was in `artifact-protocol`'s table.
 *
 * Moved rather than rewritten, deliberately, and for this contract the rule is at its
 * sharpest. A split is judged on whether the thing that moved is the thing that was
 * there, and an "improved" description arriving in the same commit as a relocation makes
 * that unanswerable — every device holding a signed release of an adapter ported at
 * `^1.0.0` reads this text through `platform:documentation`, and this is the text an
 * admin is shown before admitting the artifact that gets a shell on every member
 * device. A reworded sentence here is a change to what the platform says about its
 * largest authority and belongs in its own commit.
 *
 * That includes the sentences that are *wrong in the direction of understating the
 * risk*. "**Adapters only**" is intent and not mechanism — the header says so, and
 * `THREAT-MODEL.md` §1.2 is where the correction lives, because the correction is for
 * an operator rather than for an author. Editing it here as part of a relocation would
 * be the worst of both: a claim quietly changed in the commit nobody reviews for claims.
 */
const SHAPE = {
  description:
    'What the machine is, and a narrow authority to act on it. **Adapters only** — an ordinary artifact must ' +
    'never declare a port on this, and the reason is the second half of the sentence: nothing else in the ' +
    'platform lets an artifact write a file a person will later execute. The authority is narrowed by taking ' +
    'names rather than paths. writeCommand takes a command name, validates it against a character class that ' +
    'cannot spell a traversal, and puts the file in one directory the kernel chose; the adapter ' +
    'never names a path and so cannot name the wrong one. The suffix and the shell directory an adapter does ' +
    'get to name are each validated against a class from artifact-protocol that admits no separator, no ' +
    'leading dot and no ".." — so the reachable filename set is still one directory deep and the strong claim ' +
    '("a traversal cannot be written") survives the kernel giving up its table of which suffix each platform ' +
    'wanted. The same classes validate the conventions block a surface adapter signs into its manifest. ' +
    'profileEnsure is the one thing that touches a file ' +
    'the user also owns, and it maintains a single delimited block by replacing it rather than appending, so ' +
    'a device that has booted four hundred times has one block and not four hundred. There is no console ' +
    'here and there is not going to be one soon: nothing below reads a line, and the future capability that ' +
    'would is named rather than smuggled in.',
  operations: [
    {
      name: 'os',
      description: 'The platform tag, spelled the way the runtime spells it. An adapter switches on this and nothing else.',
      params: [],
      returns: { type: 'string', description: 'darwin, linux, win32 and whatever else the runtime reports. Deliberately not an enum: the set belongs to the runtime, and a platform gaining an adapter must not be a change to this contract.' }
    },
    {
      name: 'arch',
      description: 'The CPU architecture, as the runtime reports it.',
      params: [],
      returns: { type: 'string', description: 'arm64, x64 and so on. Not an enum, for the reason os is not one.' }
    },
    {
      name: 'shell',
      description: 'The login shell\'s basename. Which shell a person uses decides where a PATH line goes, and getting it wrong writes into a file nobody reads.',
      params: [],
      returns: { type: 'string', nullable: true, description: 'zsh, bash, fish — or null where the device reports no SHELL, which Windows outside an msys environment does not. A device answering null is stating a fact rather than failing.' }
    },
    {
      name: 'env',
      description: 'One environment variable, from a small allow-list. An adapter has no business reading the environment at large, so a name outside the list reads null rather than being refused — the caller learns nothing about whether it was set.',
      params: [
        { name: 'name', type: 'string', description: 'The variable name. HOME, SHELL, TERM, LANG, PATH and ARTIFACT_COLUMNS are the list; anything else answers null.' }
      ],
      returns: { type: 'string', nullable: true, description: 'The value, or null when it is unset or off the list.' }
    },
    {
      name: 'columns',
      description: 'How wide the destination is, already clamped — or null when nothing knows. The one number an adapter could not obtain and had to be told, and it arrives bounded because the same 20/1000 bounds were open-coded identically in three adapters and a fourth would have written them a fourth time.',
      params: [],
      returns: { type: 'number', nullable: true, description: 'A clamped column count, or null when there is neither a console to measure nor an ARTIFACT_COLUMNS to read. An adapter supplies its own default for null — 80 on a terminal — which is the one part of this that genuinely is its own.' }
    },
    {
      name: 'binPath',
      description: 'Where commands live, so an adapter can put it on a PATH.',
      params: [],
      returns: { type: 'string', description: 'An absolute directory path. Readable, not writable by name: writeCommand is the only thing that puts a file there.' }
    },
    {
      name: 'completionPath',
      description: 'Where completion scripts go for one shell. Beside binPath rather than inside it, because everything in binPath is on a PATH and a completion script is not a command. The shell is validated as a path segment rather than looked up in a table the kernel keeps, so a shell nobody has written an adapter for yet is a directory name and not a refusal.',
      params: [
        { name: 'shell', type: 'string', description: 'The shell name, as shell() spells it: a letter, then lowercase letters, digits and hyphens. It becomes one path segment, which is why it is validated as strictly as a command name.' }
      ],
      returns: { type: 'string', nullable: true, description: 'An absolute directory path, or null where the name is not one a directory could be called. Null is a refusal rather than a failure — an adapter that asked with a malformed name has learned that here rather than by a write failing. It is no longer null merely because the kernel had not heard of the shell; that table is gone.' }
    },
    {
      name: 'writeCommand',
      description: 'Install a command shim. The name is validated, the contents are whatever the adapter decided a shim looks like on this platform, and the file lands executable in one directory. That is the entire authority granted.',
      params: [
        { name: 'name', type: 'string', description: 'The command name: lowercase, digits and hyphens, starting with a letter. The class is what makes a path traversal unspellable rather than merely unmatched.' },
        { name: 'contents', type: 'string', description: 'The shim\'s bytes, as text. The kernel does not read them — what a shim looks like is the one thing genuinely platform knowledge.' },
        { name: 'suffix', type: 'string', optional: true, description: 'What the executable is called beyond its name — ".cmd" on Windows, which will not execute an extensionless file, and absent everywhere a shim is extensionless. The adapter names it because which suffix a platform needs is the adapter\'s knowledge and was never the kernel\'s; the kernel validates it against a class that admits a dot and up to eight lowercase letters or digits and nothing else, so the concatenation cannot produce a separator, a leading dot, or a "..". The same value belongs in the provider\'s signed manifest under provides[].conventions.executable, where an admin can read what an adapter will write before admitting it.' }
      ],
      returns: { type: 'string', description: 'The absolute path written. Returned so a receipt can name it; the adapter could not have computed it, which is the point.' }
    },
    {
      name: 'writeCompletion',
      description: 'Install a completion script for one shell. Mode 0644, not 0755: a completion is sourced, never executed, and a file that does not need to be executable should not be.',
      params: [
        { name: 'name', type: 'string', description: 'The command the completion is for, in the same class writeCommand validates. It carries no prefix and no suffix, because the class refuses both — those come from the affix below.' },
        { name: 'shell', type: 'string', description: 'The shell whose mechanism this script is written in, validated as a path segment. A malformed name is refused here rather than answered with null, unlike completionPath: asking where one goes is a question, and writing one to nowhere is a mistake.' },
        { name: 'contents', type: 'string', description: 'The script\'s bytes, as text.' },
        {
          name: 'affix',
          type: 'object',
          optional: true,
          description: 'How this shell names a completion file, beyond the command\'s own name — zsh looks for _send, bash for send.bash. It used to be two tables in the kernel, which meant adding elvish was a kernel release for the sake of two strings. Absent means the file is called exactly the command name. Each part is validated against the same class the signed manifest\'s provides[].conventions.completions is, so neither can express a path.',
          fields: {
            prefix: { type: 'string', optional: true, description: 'One to eight lowercase letters or underscores, applied after the name is validated. zsh\'s fpath convention is the reason this exists: it wants a leading underscore, which is exactly what the name class refuses.' },
            suffix: { type: 'string', optional: true, description: 'A dot and one to eight lowercase letters or digits.' }
          }
        }
      ],
      returns: { type: 'string', description: 'The absolute path written.' }
    },
    {
      name: 'removeCommand',
      description: 'Take one command back off, in every form of the name the directory holds. It takes no suffix, and that is deliberate: detach feeds listCommands straight back into this, so a caller would have to remember what a *previous release* of the adapter wrote in order to remove it, and an adapter that changed its suffix would strand the old file while promising to leave no trace.',
      params: [
        { name: 'name', type: 'string', description: 'The command name, in the class writeCommand validates — the name, never a filename.' }
      ],
      returns: { type: 'boolean', description: 'Whether something was there to remove. False is not a failure — removing something already gone is the desired end state — so an adapter reporting what it removed reports what was true rather than what it asked for.' }
    },
    {
      name: 'listCommands',
      description: 'Every command this device currently has installed, sorted. Names, not filenames: this used to return whatever matched the name class in the directory, so a Windows device holding send.cmd reported nothing installed and detach — which feeds this straight into removeCommand — silently removed nothing.',
      params: [],
      returns: {
        type: 'array',
        description: 'The command names, deduplicated. Empty where the directory does not exist, which is a device nothing has attached to rather than an error.',
        of: { type: 'string', description: 'One command name, with any suffix taken back off.' }
      }
    },
    {
      name: 'hasCommand',
      description: 'Whether one command is installed, in any form.',
      params: [
        { name: 'name', type: 'string', description: 'The command name.' }
      ],
      returns: { type: 'boolean', description: 'Whether a file for it is there, whatever it is suffixed with.' }
    },
    {
      name: 'profileEnsure',
      description: 'Maintain one delimited block in the user\'s shell profile, by replacement rather than by appending. Unchanged is a no-op and not a rewrite: attach runs on every boot and a boot is currently every command, so writing unconditionally would touch a file the person is editing several times a minute for no gain.',
      params: [
        {
          name: 'lines',
          type: 'array',
          description: 'The lines of the block, joined with newlines by the kernel. Declared as a list because that is what every adapter in the tree passes and what the block is; the implementation also tolerates a bare string, and that tolerance is deliberately not declared — a contract that admitted both would have to say which one a checker holds a caller to.',
          of: { type: 'string', description: 'One line of the managed block.' }
        }
      ],
      returns: { type: 'boolean', description: 'Whether there is a profile at all. False means the device reported no file to manage, which is a platform fact and not a failure; an adapter reads it as "not on the PATH by my doing" and says so in its receipt.' }
    },
    {
      name: 'profileRemove',
      description: 'Take the managed block back out, leaving the rest of the file exactly as it was.',
      params: [],
      returns: { type: 'boolean', description: 'Whether a profile existed to edit. False for a device with no profile, and true for one whose profile had no block — the end state is the same and only the first is a fact about the device.' }
    },
    {
      name: 'profileBlock',
      description: 'What the platform currently has in the profile, for inspection.',
      params: [],
      returns: { type: 'string', nullable: true, description: 'The block including its delimiters, or null when there is no profile or no block in it. Read-only: an adapter that wants to change it calls profileEnsure with the whole thing.' }
    }
  ]
}

if (!capability.isPlatformContract(ID)) {
  throw new Error(
    `platform-host: ${JSON.stringify(ID)} is outside the ${capability.PLATFORM_PREFIX} namespace; ` +
    'an id without the prefix is one an artifact may declare for itself, and the shape resolvers seed the ' +
    'platform table before they read a manifest — so this entry would silently override a signed declaration'
  )
}

/**
 * The declaration, shaped exactly like `manifest.contracts[i]` holds one, so a consumer
 * needs no translation step and cannot drift from the manifest vocabulary it is standing
 * in for.
 *
 * @type {Declaration}
 */
const DECLARATION = Object.freeze({
  id: ID,
  version: VERSION,
  shape: contract.parseShape(SHAPE, `platform declaration ${ID}.shape`)
})

/**
 * Every version of this capability this package knows, as a list.
 *
 * One entry today. The list rather than the entry because `chain.js`'s `visible` feeds a
 * substitution rule that picks a baseline out of the versions in range, and
 * `assemble.js` filters these by the port's range — a consumer that had to know the
 * count is a consumer that breaks on the day there are two.
 *
 * @type {readonly Declaration[]}
 */
const DECLARATIONS = Object.freeze([DECLARATION])

/**
 * One platform capability declaration.
 *
 * Declared here rather than aliased from `artifact-protocol`: this file is
 * `module.exports = <expression>`, which TypeScript reads as `export =`, and a typedef
 * in such a file is not a named type export of it — so re-declaring one as an alias of
 * the protocol's `Declaration` collides with that declaration in whichever repository
 * compiles both packages as one program, invisibly here. `artifact-net/lib/lan.js` has
 * the full account; it cost a day there.
 *
 * @typedef {object} Declaration
 * @property {string} id
 * @property {string} version
 * @property {import('artifact-protocol/contract').Shape} shape
 */

module.exports = { ID, VERSION, DECLARATION, DECLARATIONS }
