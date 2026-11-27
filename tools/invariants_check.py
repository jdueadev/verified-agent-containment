#!/usr/bin/env python3
"""Check the rules that must hold on every commit.

The `sabotage` feature is never reachable from the host's default features, the
host's build conditions are a closed list, each controller handler builds only its
channel's kernel events, and the kernel stays pure: no_std, no unsafe, `core` only,
no build-time reads.

Usage: invariants_check.py [ROOT]
"""
import posixpath
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rust_tokens  # noqa: E402

HOST_MANIFEST = "crates/containment-host/Cargo.toml"
KERNEL_SRC = "crates/containment-kernel/src"


def sabotage_default_errors(manifest_text):
    """`sabotage` must never be reachable from the default features."""
    features = tomllib.loads(manifest_text).get("features", {})
    seen, todo = set(), list(features.get("default", []))
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        todo.extend(features.get(name, []))
    return [f"{HOST_MANIFEST}: `sabotage` is enabled by the default features"] if "sabotage" in seen else []


# The kernel is lane B, but it is compiled into the host binary. Its laws, mutants
# and the differential test check its decisions, not its side effects, so the
# attributes that keep it pure are checked here on every commit (#83). Tokens, not
# text: a comment or a string that names `std` is not code.
KERNEL_ROOT_ATTRIBUTES = (("no_std",), ("forbid", "(", "unsafe_code", ")"))
# Identifiers the kernel may not contain at all, in any position: a call, an import,
# an alias, a path or an attribute argument (including inside cfg_attr). The kernel
# uses none of them, so refusing the name outright cannot be dodged by renaming
# (`use core::include as load`) or by moving it (`#[cfg_attr(all(), path = ..)]`).
KERNEL_FORBIDDEN_IDENTS = {
    # crates beyond core, and foreign code
    "std": "depends on more than `core`",
    "alloc": "depends on more than `core`",
    "extern": "declares foreign code or another crate",
    # build-time reads of files or the environment
    "include": "reads a file at build time",
    "include_str": "reads a file at build time",
    "include_bytes": "reads a file at build time",
    "env": "reads the environment at build time",
    "option_env": "reads the environment at build time",
    # source from elsewhere, and code that bypasses forbid(unsafe_code)
    "path": "loads source from elsewhere (`#[path]`)",
    "global_asm": "injects machine code without `unsafe`",
    "asm": "injects machine code",
    "naked_asm": "injects machine code",
    "link": "links foreign code",
    "link_section": "places data in a chosen link section",
    "no_mangle": "exports a symbol",
    "export_name": "exports a symbol",
    "used": "keeps a symbol for the linker",
    "linkage": "sets symbol linkage",
    "feature": "enables unstable features",
}


def _ident(kind, text):
    """A raw identifier (`r#include`) means the same name as `include`."""
    return text[2:] if kind == "ident" and text.startswith("r#") else text


def _leading_inner_attributes(toks):
    """The token lists of the `#![...]` attributes that open the file, which are the
    ones that apply to the whole crate. One inside `mod m { ... }` applies to `m` only."""
    attrs, i = [], 0
    while toks[i:i + 3] == ["#", "!", "["]:
        depth, j = 0, i + 2
        while j < len(toks):
            depth += toks[j] == "["
            depth -= toks[j] == "]"
            if depth == 0:
                break
            j += 1
        if j >= len(toks):
            break
        attrs.append(toks[i + 3:j])
        i = j + 1
    return attrs


def kernel_purity_errors(files):
    """`files` maps each kernel source path to its text; `lib.rs` is the crate root."""
    out = []
    root = f"{KERNEL_SRC}/lib.rs"
    if root not in files:
        return [f"{root}: missing, so the kernel's purity cannot be checked"]
    for path, text in sorted(files.items()):
        try:
            toks = [_ident(kind, tok) for kind, tok in rust_tokens.code_tokens(text) if kind != "doc"]
        except rust_tokens.LexError as error:
            out.append(f"{path}: cannot be read ({error}), so the kernel's purity cannot be checked")
            continue
        if path == root:
            leading = _leading_inner_attributes(toks)
            for attr in KERNEL_ROOT_ATTRIBUTES:
                if list(attr) not in leading:
                    out.append(f"{path}: the crate attribute #![{''.join(attr)}] is missing from the top of the file")
        for tok in sorted(set(toks) & set(KERNEL_FORBIDDEN_IDENTS)):
            out.append(f"{path}: uses `{tok}`, which {KERNEL_FORBIDDEN_IDENTS[tok]}")
    return out


HOST_CRATE = "crates/containment-host"
HOST_SRC = f"{HOST_CRATE}/src"
# Build conditions are a closed list in the host (#121). `sabotage_default_errors`
# keeps the defects out of the default build, but only for defects behind a
# `weak.x()` gate on the zero-sized `Weakness`. A new `#[cfg(feature = "sabotage")]`
# block elsewhere is a defect with no `weaknesses!` entry and so no control; a
# `cfg(debug_assertions)` defect is live in every test build; another feature or a
# `cfg_attr(.., path = ..)` swaps code in unseen. This is a tripwire on the
# conditions only: it cannot see a defect written as ungated code.
HOST_CFG_NAMES = {"test", "kani"}  # kani: formal/kani proofs, declared in the workspace check-cfg
HOST_CFG_KEYS = {"target_arch"}
HOST_CFG_OPERATORS = {"any", "all", "not"}
HOST_SABOTAGE_FILES = {f"{HOST_SRC}/controller/weakness.rs", f"{HOST_SRC}/common.rs"}
HOST_CFG_FIX = "add the defect to `weaknesses!` in `controller/weakness.rs`"
HOST_FEATURES = {"default": [], "sabotage": []}


def _cfg_string(text):
    """The value of a plain (`"x"`) or raw (`r"x"`, `r#"x"#`) string with no escapes, else None."""
    raw = re.fullmatch(r'r(#*)"(.*)"\1', text, re.DOTALL)
    if raw:
        return raw.group(2)
    plain = re.fullmatch(r'"([^"\\]*)"', text)
    return plain.group(1) if plain else None


def _close(toks, i):
    """Index of the delimiter closing the one at toks[i], or None."""
    depth = 0
    for j in range(i, len(toks)):
        depth += toks[j].text in "([{" and toks[j].kind == "punct"
        depth -= toks[j].text in ")]}" and toks[j].kind == "punct"
        if depth == 0:
            return j
    return None


def _split_commas(toks):
    """toks split at top-level commas, empty parts (a trailing comma) dropped."""
    parts, current, depth = [], [], 0
    for tok in toks:
        if tok.kind == "punct" and tok.text in "([{":
            depth += 1
        elif tok.kind == "punct" and tok.text in ")]}":
            depth -= 1
        elif tok.kind == "punct" and tok.text == "," and depth == 0:
            parts.append(current)
            current = []
            continue
        current.append(tok)
    return [p for p in parts + [current] if p]


def _test_item_tokens(toks):
    """Indexes of the tokens inside the attributes of an item that also carries `#[test]`.
    Such an item is compiled only under cfg(test), so it cannot carry a defect into a binary."""
    attrs, i = [], 0
    while i < len(toks):
        if toks[i].text == "#" and i + 1 < len(toks) and toks[i + 1].text == "[":
            end = _close(toks, i + 1)
            if end is None:
                break
            attrs.append((i, end))
            i = end + 1
        else:
            i += 1
    inside, stack = set(), []
    for k, (lo, hi) in enumerate(attrs):
        stack.append((lo, hi))
        if k + 1 < len(attrs) and attrs[k + 1][0] == hi + 1:
            continue
        if any([t.text for t in toks[a + 2:b]] == ["test"] for a, b in stack):
            for a, b in stack:
                inside.update(range(a, b + 1))
        stack = []
    return inside


def _predicate_errors(pred, path, test_item):
    """Why the cfg predicate `pred` (a token list) is outside the closed list, if it is."""
    shown = " ".join(t.text for t in pred)
    if len(pred) == 1 and pred[0].kind == "ident" and pred[0].text in HOST_CFG_NAMES:
        return []
    if len(pred) >= 3 and pred[0].kind == "ident" and pred[0].text in HOST_CFG_OPERATORS \
            and pred[1].text == "(" and _close(pred, 1) == len(pred) - 1:
        return [e for part in _split_commas(pred[2:-1]) for e in _predicate_errors(part, path, test_item)]
    if len(pred) == 3 and pred[0].kind == "ident" and pred[1].text == "=" and pred[2].kind == "str":
        key, value = pred[0].text, _cfg_string(pred[2].text)
        if value is None:
            return [f"`{shown}` has a value the check cannot read (escapes or a byte string); write it as a plain string"]
        if key in HOST_CFG_KEYS:
            return []
        if key == "feature" and value == "sabotage":
            if path in HOST_SABOTAGE_FILES or test_item:
                return []
            return [f"`feature = \"sabotage\"` is allowed only in controller/weakness.rs, common.rs "
                    f"and on #[test] items, so a defect here has no control; {HOST_CFG_FIX}"]
        return [f"`{key} = \"{value}\"` is not an allowed build condition; {HOST_CFG_FIX}"]
    return [f"`{shown}` is not an allowed build condition (allowed: test, kani, target_arch = .., "
            f"feature = \"sabotage\" in the registry, and any/all/not of those); {HOST_CFG_FIX}"]


def host_cfg_errors(files):
    """`files` maps each host source path to its text. Every `cfg`, `cfg!` and `cfg_attr`
    predicate must be on the closed list above. Tokens, not text: comments, doc
    comments and strings do not count; raw identifiers and raw strings are normalised;
    every `cfg`/`cfg_attr` token is visited, so nesting inside any/all or cfg_attr cannot hide one."""
    out = []
    for path, text in sorted(files.items()):
        try:
            toks = [t._replace(text=_ident(t.kind, t.text)) for t in rust_tokens.tokenize(text)
                    if t.kind not in ("comment", "doc")]
        except rust_tokens.LexError as error:
            out.append(f"{path}: cannot be read ({error}), so its build conditions cannot be checked")
            continue
        test_items = _test_item_tokens(toks)
        for i, tok in enumerate(toks):
            if tok.kind != "ident" or tok.text not in ("cfg", "cfg_attr"):
                continue
            where = f"{path}:{text.count(chr(10), 0, tok.start) + 1}"
            bang = i + 1 < len(toks) and toks[i + 1].text == "!" and tok.text == "cfg"
            open_at = i + 2 if bang else i + 1
            end = _close(toks, open_at) if open_at < len(toks) and toks[open_at].text == "(" else None
            if end is None:
                out.append(f"{where}: `{tok.text}` is used in a form the check cannot read; {HOST_CFG_FIX}")
                continue
            args = _split_commas(toks[open_at + 1:end])
            if tok.text == "cfg_attr":
                if len(args) < 2:
                    out.append(f"{where}: `cfg_attr` without a predicate and an attribute cannot be read")
                    continue
                for attr in args[1:]:
                    if attr[0].text == "path":
                        out.append(f"{where}: `cfg_attr(.., path = ..)` swaps in other source under a build condition; {HOST_CFG_FIX}")
                args = args[:1]
            if len(args) != 1:
                out.append(f"{where}: `{tok.text}` must hold exactly one predicate")
                continue
            out.extend(f"{where}: {e}" for e in _predicate_errors(args[0], path, i in test_items))
    return out


# Each controller channel builds only its own kernel events (#120: INV-6, "the channel
# decides the event", and the host side of INV-4). Every host function that names an
# `Event` variant is listed with the variants it may name; a variant named anywhere
# else fails, as does any way of naming one the token scan cannot follow: a glob or
# group import of the variants, an alias of `Event`, `#[path]` into an unread file,
# `include!`. A message body may still choose among its own channel's variants, so the
# table holds sets. `X{..}` is a match pattern (`Event::X { .. }`), which cannot build
# an event. This is a tripwire against mistakes, not a proof: a function in another
# crate that returns an `Event` is beyond it, and the lab stays the evidence.
EVENT_VARIANTS = ("Tick", "Renew", "Classifier", "HardRule", "AgentRequest", "Reset")
CONTROLLER = f"{HOST_SRC}/controller"
EVENT_TABLE = {
    (f"{CONTROLLER}/reset.rs", "monitor_handler"): {"Renew"},
    (f"{CONTROLLER}/reset.rs", "control_handler"): {"HardRule", "Tick"},
    (f"{CONTROLLER}/reset.rs", "reset_handler"): {"Reset"},
    (f"{CONTROLLER}/classifier.rs", "apply_classifier"): {"Classifier"},
    (f"{CONTROLLER}/gateway.rs", "gateway_decide"): {"AgentRequest"},
    (f"{CONTROLLER}/gateway.rs", "live_infer"): {"HardRule"},
    (f"{CONTROLLER}/gate.rs", "Shared::admit"): {"HardRule"},
    # The clock-regression freeze, and the check that a reset restored authority.
    (f"{HOST_SRC}/controller.rs", "Shared::apply"): {"HardRule", "Reset{..}"},
    (f"{HOST_SRC}/controller.rs", "event_name"): {f"{v}{{..}}" for v in EVENT_VARIANTS},
    # The lease clock thread.
    (f"{HOST_SRC}/controller.rs", "run"): {"Tick"},
    # Random events for the Rust-to-Bend differential, which never reach a controller.
    (f"{HOST_SRC}/differential.rs", "event"): set(EVENT_VARIANTS),
}
# Functions that may name every variant, but only as a match-arm pattern: right after
# the `{`, `,`, `|` or `}` that starts an arm, and followed (after its fields) by `=>`
# or `|`. A value built there, a guard, or a closure body is refused. The controller
# calls kernel_trace.rs to log each committed step, so it may read events, not build them.
EVENT_PATTERNS = {
    (f"{HOST_SRC}/kernel_trace.rs", "encode"): set(EVENT_VARIANTS),
}
# The two sabotage controls (INV-9) that let the classifier's channel build a hard
# rule. Each is pinned to its exact tokens, gate included: allowing "any weak-gated
# block" would itself be a bypass.
EVENT_SABOTAGE = (
    {"control": "classifier_uncapped", "file": f"{CONTROLLER}/classifier.rs", "function": "apply_classifier",
     "binding": "let uncapped = shared . weak . classifier_uncapped ( ) ;", "gate": "uncapped",
     "branch": "if uncapped { Event :: HardRule { now_ms , level } }"},
    {"control": "shared_control_socket", "file": f"{CONTROLLER}/classifier.rs", "function": "read_verdicts",
     "binding": None, "gate": None,
     "branch": 'if shared . weak . shared_control_socket ( ) && v [ "op" ] == "hard" { shared . apply ( '
               'Some ( "system_one_hard" ) , now , | now_ms | Event :: HardRule { now_ms , level } ) ; }'},
)
# The classifier's side may not name another channel's variants at all, in any position.
EVENT_BANNED = {f"{CONTROLLER}/classifier.rs": {"Renew", "Reset", "Tick", "AgentRequest"},
                f"{HOST_SRC}/system_one.rs": {"Renew", "Reset", "Tick", "AgentRequest"}}
# Host enums with a variant of the same name as one of `Event`'s.
EVENT_LOOKALIKES = {(f"{HOST_SRC}/run_live.rs", "CtlAction"): {"Reset"}}
# Which socket feeds which handler. Each sequence appears exactly once in controller.rs.
EVENT_BINDINGS = (
    'let monitor_socket = private_dir . join ( "monitor.sock" ) ;',
    'let control_socket = private_dir . join ( "control.sock" ) ;',
    'let reset_socket = private_dir . join ( "reset.sock" ) ;',
    "let monitor_listener = listener ( & monitor_socket ,",
    "let control_listener = listener ( & control_socket ,",
    "let reset_listener = listener ( & reset_socket ,",
    "let gateway_listener = listener ( & gateway ,",
    "serve ( monitor_listener , shared , PeerRule :: Monitor , monitor_handler )",
    "serve ( control_listener , shared , rule , control_handler )",
    "serve ( reset_listener , shared , rule , reset_handler )",
    "serve_gateway ( gateway_listener , shared )",
    "supervise_system_one ( shared , spec )",
)
# Names that appear exactly twice in the host (or in the one file given): where they
# are defined and where they are bound or called. So a handler cannot be called from
# another channel's handler or bound to a second socket, and a listener cannot be rebound.
EVENT_SINGLE_USE = {
    "monitor_handler": None, "control_handler": None, "reset_handler": None, "serve_gateway": None,
    "supervise_system_one": None, "read_verdicts": None, "gateway_decide": None, "live_infer": None,
    "monitor_listener": f"{HOST_SRC}/controller.rs", "control_listener": f"{HOST_SRC}/controller.rs",
    "reset_listener": f"{HOST_SRC}/controller.rs", "gateway_listener": f"{HOST_SRC}/controller.rs",
}
EVENT_REBIND = ("monitor_socket", "control_socket", "reset_socket")
# Helpers that build events, and the files of the controller module that may name them.
# Code outside the controller module cannot reach `Shared`.
EVENT_CALLERS = {
    "apply_classifier": {f"{HOST_SRC}/controller.rs", f"{CONTROLLER}/classifier.rs", f"{CONTROLLER}/gateway.rs"},
    "admit": {f"{CONTROLLER}/gate.rs", f"{CONTROLLER}/gateway.rs", "formal/kani/gate_proofs.rs"},
}
# differential.rs builds every variant, so the controller may not reach it: main.rs
# names the module exactly here, and no other file names it.
EVENT_DIFFERENTIAL = (f"{HOST_SRC}/main.rs", ("mod differential ;", "differential :: run ("))


def _event_tokens(text):
    """Code tokens with raw identifiers normalised and layout commas dropped."""
    toks = [t._replace(text=_ident(t.kind, t.text)) for t in rust_tokens.tokenize(text)
            if t.kind not in ("comment", "doc")]
    return rust_tokens.drop_layout_commas(toks)


def _find(toks, seq, lo=0, hi=None):
    """Start indexes of the token texts `seq` (space-separated) in toks[lo:hi]."""
    want, hi = seq.split(), len(toks) if hi is None else hi
    return [i for i in range(lo, hi - len(want) + 1) if [t.text for t in toks[i:i + len(want)]] == want]


def _items(toks, partner):
    """(open, close, name, kind) of every mod, impl, trait and fn with a body."""
    items = []
    for i, tok in enumerate(toks):
        if tok.kind != "ident" or tok.text not in ("mod", "impl", "trait", "fn") or i + 1 >= len(toks):
            continue
        if tok.text == "impl":
            if i and toks[i - 1].text not in ("}", ";", "]", "{", "unsafe", "default"):
                continue  # `impl Trait` in a type
        elif toks[i + 1].kind != "ident":
            continue  # a `fn(..)` pointer type
        j, depth, head = i + 1, 0, []
        while j < len(toks):
            t = toks[j]
            if t.kind == "punct" and t.text in ("(", "["):
                depth += 1
            elif t.kind == "punct" and t.text in (")", "]"):
                depth -= 1
            elif depth == 0 and t.text in ("{", ";"):
                break
            head.append(t)
            j += 1
        if j >= len(toks) or toks[j].text != "{" or j not in partner:
            continue
        if tok.text == "impl":
            texts = [t.text for t in head]
            if "for" in texts:
                head = head[texts.index("for") + 1:]
            elif head and head[0].text == "<":
                depth = 0
                for k, t in enumerate(head):
                    depth += {"<": 1, "<<": 2, ">": -1, ">>": -2}.get(t.text, 0)
                    if depth <= 0:
                        head = head[k + 1:]
                        break
            name = next((t.text for t in head if t.kind == "ident" and t.text not in ("dyn", "mut")), "?")
        else:
            name = toks[i + 1].text
        items.append((j, partner[j], name, tok.text))
    return items


def _qualname(items, k):
    return "::".join(name for lo, hi, name, _ in sorted(items) if lo < k < hi)


def _path_attrs(toks, items):
    """(index, value, inside an inline mod) of every `#[path = "..."]`."""
    found = []
    for i in range(len(toks) - 4):
        if [t.text for t in toks[i:i + 4]] == ["#", "[", "path", "="] and toks[i + 4].kind == "str":
            inline = any(kind == "mod" and lo < i < hi for lo, hi, _, kind in items)
            found.append((i, _cfg_string(toks[i + 4].text), inline))
    return found


def _path_target(path, value):
    return None if value is None else posixpath.normpath(posixpath.join(posixpath.dirname(path), value))


def event_path_targets(files):
    """Repository paths that `#[path]` attributes in `files` load."""
    out = set()
    for path, text in files.items():
        try:
            toks = _event_tokens(text)
        except rust_tokens.LexError:
            continue  # host_event_errors reports it
        out.update(_path_target(path, value) for _, value, _ in _path_attrs(toks, []) if value is not None)
    return out


def host_event_errors(files):
    """`files` maps each host source path, and every file a `#[path]` there loads, to
    its text. See EVENT_TABLE."""
    out, parsed = [], {}
    for path, text in sorted(files.items()):
        try:
            toks = _event_tokens(text)
        except rust_tokens.LexError as error:
            out.append(f"{path}: cannot be read ({error}), so the events it builds cannot be checked")
            continue
        partner = rust_tokens._partners(toks)
        if 2 * len(partner) != sum(t.kind == "punct" and t.text in "()[]{}" for t in toks):
            out.append(f"{path}: has unbalanced delimiters, so the events it builds cannot be checked")
            continue
        parsed[path] = (text, toks, partner, _items(toks, partner))

    def where(path, k):
        text, toks = parsed[path][0], parsed[path][1]
        return f"{path}:{text.count(chr(10), 0, toks[k].start) + 1}"

    functions = {}
    for path, (_, toks, partner, items) in parsed.items():
        for lo, hi, name, kind in items:
            if kind == "fn":
                outer = _qualname(items, lo)
                functions.setdefault((path, f"{outer}::{name}" if outer else name), []).append((lo, hi))
    for key in sorted(EVENT_TABLE):
        if len(functions.get(key, [])) != 1:
            out.append(f"{key[0]}: the event table lists `{key[1]}`, which is not exactly one function here")
    for key in sorted(EVENT_PATTERNS):
        if len(functions.get(key, [])) != 1:
            out.append(f"{key[0]}: the pattern table lists `{key[1]}`, which is not exactly one function here")

    exempt = set()
    for pin in EVENT_SABOTAGE:
        spans = functions.get((pin["file"], pin["function"]), [])
        toks = parsed[pin["file"]][1] if pin["file"] in parsed else []
        branch = _find(toks, pin["branch"], *spans[0]) if len(spans) == 1 else []
        ok = len(branch) == 1
        if ok and pin["binding"]:
            lo, hi = spans[0]
            binding = _find(toks, pin["binding"], lo, hi)
            uses = [k for k in range(lo, hi) if toks[k].kind == "ident" and toks[k].text == pin["gate"]]
            ok = len(binding) == 1 and binding[0] < branch[0] and len(uses) == 2
        if ok:
            exempt.add((pin["file"], branch[0] + pin["branch"].split().index("HardRule")))
        else:
            out.append(f"{pin['file']}: the sabotage control `{pin['control']}` in `{pin['function']}` "
                       f"is no longer its pinned gated branch, so its `HardRule` is not exempt")

    idents = {}
    for path, (_, toks, partner, items) in sorted(parsed.items()):
        lookalikes = {}
        for (file, enum), names in EVENT_LOOKALIKES.items():
            if file == path:
                for i in _find(toks, f"enum {enum} {{"):
                    lookalikes.update({k: names for k in range(i + 3, partner[i + 2])})
                for i in _find(toks, f"{enum} ::"):
                    lookalikes[i + 2] = names
        for k, tok in enumerate(toks):
            if tok.kind == "ident":
                idents.setdefault(tok.text, []).append((path, k))
            nxt = toks[k + 1].text if k + 1 < len(toks) else ""
            if tok.kind == "ident" and tok.text == "Event" and nxt == "::":
                after = toks[k + 2].text if k + 2 < len(toks) else ""
                if after in ("*", "{"):
                    out.append(f"{where(path, k)}: imports `Event`'s variants by glob or group; name each as `Event::X`")
                elif after not in EVENT_VARIANTS:
                    out.append(f"{where(path, k)}: `Event::{after}` is not a variant the check can follow")
            elif tok.kind == "ident" and tok.text == "Event" and nxt == "as":
                out.append(f"{where(path, k)}: renames `Event`, which hides the variants it builds")
            elif tok.kind == "ident" and tok.text == "type":
                end = next((j for j in range(k, len(toks)) if toks[j].text == ";"), len(toks))
                if any(t.kind == "ident" and t.text == "Event" for t in toks[k:end]):
                    out.append(f"{where(path, k)}: aliases `Event`, which hides the variants it builds")
            elif tok.kind == "ident" and tok.text == "include" and nxt == "!":
                out.append(f"{where(path, k)}: `include!` brings in source the event check cannot see")
            if tok.kind != "ident" or tok.text not in EVENT_VARIANTS or tok.text in lookalikes.get(k, ()):
                continue
            close = partner.get(k + 1) if nxt == "{" else None
            form = f"{tok.text}{{..}}" if close and toks[close - 1].text == ".." else tok.text
            qual = _qualname(items, k)
            if tok.text in EVENT_BANNED.get(path, ()):
                out.append(f"{where(path, k)}: names `{tok.text}`, which the classifier's side may never name")
                continue
            patterns = EVENT_PATTERNS.get((path, qual))
            if patterns is not None and tok.text in patterns:
                end = close if close else k
                arm_start = k >= 3 and toks[k - 1].text == "::" and toks[k - 2].text == "Event" \
                    and toks[k - 3].text in ("{", ",", "|", "}")
                arm_end = end + 1 < len(toks) and toks[end + 1].text in ("=>", "|")
                if not (arm_start and arm_end):
                    out.append(f"{where(path, k)}: `{qual}` may name `Event::{tok.text}` only as a match-arm pattern")
                continue
            allowed = EVENT_TABLE.get((path, qual))
            if (path, k) in exempt or (allowed is not None and (form in allowed or tok.text in allowed)):
                continue
            if allowed is None:
                out.append(f"{where(path, k)}: names `Event::{form}` in `{qual or '(no function)'}`, "
                           f"which the event table does not list")
            else:
                out.append(f"{where(path, k)}: `{qual}` may name only {', '.join(sorted(allowed))}, "
                           f"not `Event::{form}`")
        for k, value, inline in _path_attrs(toks, items):
            if inline or _path_target(path, value) not in files:
                out.append(f"{where(path, k)}: `#[path]` loads source the event check has not read")

    controller = parsed.get(f"{HOST_SRC}/controller.rs")
    if controller is None:
        out.append(f"{HOST_SRC}/controller.rs: missing, so the socket bindings cannot be checked")
    else:
        for seq in EVENT_BINDINGS:
            if len(_find(controller[1], seq)) != 1:
                out.append(f"{HOST_SRC}/controller.rs: the binding `{seq}` must appear exactly once")
        for name in EVENT_REBIND:
            if len(_find(controller[1], f"let {name}")) + len(_find(controller[1], f"let mut {name}")) != 1:
                out.append(f"{HOST_SRC}/controller.rs: `{name}` must be bound exactly once")
    for name, only in EVENT_SINGLE_USE.items():
        places = [(p, k) for p, k in idents.get(name, []) if only is None or p == only]
        if len(places) != 2:
            out.append(f"`{name}` appears {len(places)} times; it may appear only where it is defined and where it is bound")
    for name, allowed in EVENT_CALLERS.items():
        for p, k in idents.get(name, []):
            in_controller = p == f"{HOST_SRC}/controller.rs" or p.startswith(f"{CONTROLLER}/") or p.startswith("formal/")
            if in_controller and p not in allowed:
                out.append(f"{where(p, k)}: names `{name}`, which builds events for another channel")
    main, sequences = EVENT_DIFFERENTIAL
    for p, k in idents.get("differential", []):
        if p != main:
            out.append(f"{where(p, k)}: names `differential`, whose events never reach a controller")
    if main not in parsed or len([1 for p, _ in idents.get("differential", []) if p == main]) != len(sequences) \
            or any(len(_find(parsed[main][1], s)) != 1 for s in sequences):
        out.append(f"{main}: `differential` may appear only as {' and '.join(f'`{s}`' for s in sequences)}")
    return out


def host_manifest_errors(manifest_text, has_build_script):
    """The host's features are exactly `default = []` and `sabotage = []`, and it has no build script."""
    data = tomllib.loads(manifest_text)
    out = []
    if data.get("features", {}) != HOST_FEATURES:
        out.append(f"{HOST_MANIFEST}: the features must be exactly `default = []` and `sabotage = []`; {HOST_CFG_FIX}")
    if has_build_script or data.get("package", {}).get("build", False) is not False:
        out.append(f"{HOST_CRATE}: has a build script, which can set build conditions the source check cannot see")
    return out


def errors(root):
    """Every violation under `root`, a checkout or a seeded case's tree."""
    root = Path(root)
    manifest = root / HOST_MANIFEST
    out = sabotage_default_errors(manifest.read_text(encoding="utf-8")) if manifest.exists() else [f"{HOST_MANIFEST}: missing"]
    if manifest.exists():
        out += host_manifest_errors(manifest.read_text(encoding="utf-8"), (root / HOST_CRATE / "build.rs").exists())
    base = root / KERNEL_SRC
    files = {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8") for p in sorted(base.rglob("*.rs"))}
    out += kernel_purity_errors(files)
    host = root / HOST_SRC
    if not host.is_dir():
        return out + [f"{HOST_SRC}: missing, so the host's build conditions cannot be checked"]
    host_files = {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8") for p in sorted(host.rglob("*.rs"))}
    out += host_cfg_errors(host_files)
    # Add the files a `#[path]` loads (the Kani proofs), so that what they build is read too.
    loaded = dict(host_files)
    todo = event_path_targets(loaded) - set(loaded)
    while todo:
        target = todo.pop()
        file = root / target
        if file.is_file() and file.resolve().is_relative_to(root.resolve()):
            loaded[target] = file.read_text(encoding="utf-8")
            todo |= event_path_targets({target: loaded[target]}) - set(loaded)
    return out + host_event_errors(loaded)


def main(argv):
    found = errors(argv[1] if len(argv) > 1 else Path(__file__).resolve().parent.parent)
    for line in found:
        print(f"invariants: {line}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
