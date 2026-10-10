# The signature pack (750)

Code 750 is "this file matches a known exploit or malware signature". What it
matches is a **pack**: a versioned list of signatures, held as data, that ships
with `lua-doctor` and is matched against every file it analyzes.

    src/luadoctor/registry/stds/signatures.lua   the pack: the signatures
    yara/lua_doctor_signatures.yar                 the same signatures as yara rules
    src/luadoctor/rules/payloads.lua             the detector that matches them
    test/spec/signatures_spec.lua              the drift check between the two

Current pack version: **2026.09.1**

## What a finding says

Every 750 carries the id of the signature that matched and the version of the
pack it matched from, so a report never says "this looks bad" without saying
which list of known bad things it is talking about:

| Field | Meaning |
| --- | --- |
| `signature` | the signature's `id`, e.g. `mirai-default-credentials` |
| `pack_version` | the pack that matched, e.g. `2026.09.1` |
| `description` | one line saying what the signature is |
| `reference` | where the string comes from, so it can be checked |
| `name` | the signature id, for `--ignore 750:<id>` and for a stable match |

## How a signature is written

```lua
{
   id = "mirai-default-credentials",
   description = "Mirai scanner default credential from the botnet's credential table",
   pattern = "vizxv|xc3511|Zte521|hi3518|juantech|jvbzd|anko|7ujMko0admin|xmhdipc",
   reference = "Mirai source, scanner/scanner.c TABLE_SCAN_CREDENTIALS",
},
```

`id`, `description` and `pattern` are required; `reference` is optional. The
pack is a declaration and nothing else: adding a signature is a data change,
and so is retiring one.

**The pattern language is: literal substrings, separated by `|`.** There is no
pattern syntax, deliberately. Every alternative is matched with
`string.find(text, alternative, 1, true)` - a plain search - because a pack is
data that a stranger may edit, and a Lua pattern matched against a file's bytes
is a way to spend a reader's CPU. A `pattern` may not contain `"` or `\`, so
that every alternative can be written verbatim in a yara rule; the spec fails
if one does.

Matching is **case sensitive**, in the Lua pack and in the yara ruleset alike.
Two matchers that disagree about case are two matchers that disagree about
whether a file is infected.

## How a file is matched

Every signature is matched against the file twice over, and the two passes
cannot report the same hit twice:

1. **the string literals**, in source order. This is where a payload keeps its
   configuration, and a finding here has an exact line and column.
2. **the rest of the file's text**: its comments, and the names it binds its
   variables to. A file is literals, comments, names, numbers and punctuation,
   so a signature that holds a letter cannot hide in the last two. A payload
   does not have to put its string in a string: a comment is what whoever
   deployed it left behind, and `local vizxv_password = ...` names the
   credential table's own finding.

A signature is reported **once per file, at its first match**. A file with the
same password in four places is one file with one problem, and four findings
saying so helps nobody.

## The yara ruleset

`yara/lua_doctor_signatures.yar` is the same pack in yara syntax, one rule per
signature, so the same question can be asked of a whole firmware image rather
than of a file `lua-doctor` parsed:

```
yara -r yara/lua_doctor_signatures.yar firmware/
```

Each rule is named `lua_doctor_sig_<id with dashes as underscores>` and carries the
signature in `meta`:

```yara
rule lua_doctor_sig_mirai_default_credentials
{
   meta:
      id = "mirai-default-credentials"
      pack_version = "2026.09.1"
      description = "Mirai scanner default credential from the botnet's credential table"
      reference = "Mirai source, scanner/scanner.c TABLE_SCAN_CREDENTIALS"

   strings:
      $s1 = "vizxv"
      $s2 = "xc3511"
      ...

   condition:
      any of them
}
```

`any of them` is the `|` of the pack's `pattern`: the alternatives are the same
list, matched the same way.

### The two cannot drift

`test/spec/signatures_spec.lua` reads both files and asserts that they list the
same signature ids **and the same alternatives for each id**. Add a signature
to the Lua pack and forget the yara rule, and the suite fails on the missing
rule. Change an alternative in one and not the other, and it fails on the
mismatch. The same spec compiles the ruleset with `yara -w` when `yara` is
installed on the machine, and is a no-op when it is not.

## What the pack covers today

| Signature | What it is |
| --- | --- |
| `mirai-default-credentials` | password entries from the Mirai credential table |
| `mirai-user-agent` | the User-Agent every Mirai scan request carries |
| `mirai-loader-paths` | the file names Mirai variants install themselves under |
| `shellshock-cgi-environment` | the CGI request form of CVE-2014-6271 |
| `cve-2017-17215-huawei-hg532` | the DeviceUpgrade endpoint of the HG532 RCE |
| `cve-2018-10561-dlink-gpon` | the SOAPAction of the D-Link and GPON RCE |
| `dvr-cgi-path-traversal` | the DVR CGI traversal the Zollard worm was written for |
| `miner-stratum-pool` | a mining pool endpoint, as a coin miner is configured |
| `cobalt-strike-default-uri` | the stock Cobalt Strike beacon URI |

**This is a starting set, not a curated feed.** Every entry is a published
string that identifies a family or a CVE, and each is recorded with where it
comes from so a reader can judge it. It is nine signatures, not nine thousand,
and a pack nobody trusts is worth more than a pack that cries wolf. Adding to it
is cheap; the cost of a bad entry is a false positive on every device that
carries the string, which is why the entries here are ones with a published
source and not strings that merely look unusual.

## Adding a signature

1. Add it to `signatures.lua` with an `id`, a `description`, a `pattern` and a
   `reference`.
2. Add its rule to `yara/lua_doctor_signatures.yar`: the same id in `meta`, one
   `$sN` per alternative of the pattern, `any of them`.
3. Add a firing fixture under `test/fixtures/signatures/` and a silent one, and
   a spec that asserts both - the silent one matters as much, because a pack
   that matches everything reports nothing.
4. `make test`. The drift spec will tell you if you missed step 2.

Bump `version` when the pack changes, and the new version is what every 750
reports. The version is what makes a report dated today readable next to one
from last quarter: the two may disagree about the same file, and the pack
version says which list each answer came from.

## What this does not do

- **It does not decompile, and it does not follow anything.** A signature is
  matched against the text of the file and the names in it. A payload that
  builds its string at runtime from byte values is not what this pack is for;
  that is 746, which reads the bytes a file spells out.
- **It does not know the pack is complete.** Nine signatures catch nine things.
  Everything else needs a new entry.
- **A comment silences it, as it silences every other code.** The pack file
  itself carries `-- lua-doctor: ignore 750`, because every string in it is a
  signature and a finding there is not news. That is the same escape hatch
  `-- lua-doctor: ignore` gives a developer everywhere else, and it is there on
  purpose: a suppression a reader can see in the file beats a detector with a
  special case for one path.
