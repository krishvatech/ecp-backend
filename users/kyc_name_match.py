"""
Name handling for KYC (Didit) verification.

- ``repair_mojibake`` undoes UTF-8 text that was mis-decoded as Latin-1 /
  cp1252 somewhere upstream (e.g. "çŽ‹ä½©æ´" -> "王佩洁").
- ``best_linkedin_match`` compares profile names with ID-document names and
  understands non-Latin scripts (Chinese, Japanese, Korean, Vietnamese, ...).
"""
import re
import unicodedata

_STOP_TOKENS = {
    "mr", "mrs", "ms", "dr", "prof",
    "jr", "sr", "ii", "iii", "iv",
}

# Latin letters that NFKD cannot reduce to ASCII (Vietnamese đ, Polish ł, ...).
_LATIN_FOLD = str.maketrans({
    "đ": "d", "Đ": "d", "ð": "d", "Ð": "d",
    "ł": "l", "Ł": "l",
    "ø": "o", "Ø": "o",
    "æ": "ae", "Æ": "ae",
    "œ": "oe", "Œ": "oe",
    "ß": "ss", "ẞ": "ss",
    "þ": "th", "Þ": "th",
    "ı": "i",
    "ħ": "h", "Ħ": "h",
})

# Apostrophes are dropped so "O'Brien" and "OBRIEN" compare equal.
_APOSTROPHES = str.maketrans("", "", "'’ʼ`´")

# A UTF-8 lead byte (Â..ô) followed by a continuation byte, both rendered as
# Latin-1 / cp1252 characters: the fingerprint of mojibake.
_MOJIBAKE_RE = re.compile(
    "[Â-ô]"
    "[\u0080-¿ŒœŠšŸŽžƒ"
    "ˆ˜–—‘-„†-•…‰"
    "‹›€™]"
)

_TOKEN_RE = re.compile(r"[a-z]+|[^\sa-z]+")


def _mojibake_bytes(text: str):
    out = bytearray()
    for ch in text:
        if ord(ch) < 0x100:
            out.append(ord(ch))
            continue
        try:
            out += ch.encode("cp1252")
        except UnicodeEncodeError:
            return None
    return bytes(out)


def repair_mojibake(text):
    """Return ``text`` with UTF-8-read-as-Latin-1/cp1252 damage undone.

    Only rewrites when the bytes decode as strict UTF-8, so genuine accented
    names such as "José Müller" are never touched.
    """
    if not text or not isinstance(text, str) or text.isascii():
        return text
    for _ in range(2):  # handles text that was double-encoded
        if not _MOJIBAKE_RE.search(text):
            break
        raw = _mojibake_bytes(text)
        if raw is None:
            break
        try:
            fixed = raw.decode("utf-8")
        except UnicodeDecodeError:
            break
        if fixed == text:
            break
        text = fixed
    return text


def looks_like_mojibake(text) -> bool:
    return bool(text) and bool(_MOJIBAKE_RE.search(text))


def _normalize(name: str) -> str:
    name = unicodedata.normalize("NFKC", name)  # full-width -> normal width
    name = name.translate(_APOSTROPHES).translate(_LATIN_FOLD)
    # Strip accents from Latin letters only; keeps Japanese dakuten etc. intact.
    out = []
    prev_ascii = False
    for ch in unicodedata.normalize("NFKD", name):
        if unicodedata.combining(ch):
            if not prev_ascii:
                out.append(ch)
            continue
        out.append(ch)
        prev_ascii = ch.isascii()
    return unicodedata.normalize("NFC", "".join(out)).casefold()


def name_parts(name: str) -> tuple[list[str], list[str]]:
    """Split a name into (latin_tokens, native_script_tokens)."""
    if not name:
        return [], []
    name = _normalize(repair_mojibake(name))
    # Anything that is not a letter (digits, punctuation, symbols) separates tokens.
    name = "".join(ch if unicodedata.category(ch).startswith("L") else " " for ch in name)
    latin, native = [], []
    for tok in _TOKEN_RE.findall(name):
        if tok.isascii():
            if tok not in _STOP_TOKENS:
                latin.append(tok)
        else:
            native.append(tok)
    return latin, native


def _name_tokens(name: str) -> list[str]:
    return name_parts(name)[0]


def _token_matches(pt: str, id_tokens: list[str]) -> bool:
    """Match token with exact / initial / prefix rules."""
    if not pt:
        return False

    # exact
    if pt in id_tokens:
        return True

    # initial: "r" matches "rahul"
    if len(pt) == 1:
        return any(t.startswith(pt) for t in id_tokens)

    # allow prefix match for short-form vs full-form (alex vs alexander)
    # keep it conservative: only if token length >= 3
    if len(pt) >= 3:
        return any(t.startswith(pt) or pt.startswith(t) for t in id_tokens if len(t) >= 3)

    return False


def _native_matches(p_native: list[str], d_native: list[str]) -> bool:
    # CJK names are often written without spaces, so compare both ways.
    return "".join(p_native) == "".join(d_native) or sorted(p_native) == sorted(d_native)


def linkedin_style_name_match(profile_display_name: str, id_full_name: str) -> tuple[bool, dict]:
    """
    LinkedIn-like: require PROFILE FIRST token + PROFILE LAST token to match ID tokens.
    Order doesn't matter. Middle names can be extra/missing.
    Native-script names (王佩洁, 山田 太郎, 김 민수) pass when both sides are identical.
    """
    p, p_native = name_parts(profile_display_name)
    d, d_native = name_parts(id_full_name)

    debug = {
        "profile_tokens": p,
        "id_tokens": d,
        "profile_native_tokens": p_native,
        "id_native_tokens": d_native,
        "matched_profile_tokens": [],
        "missing_profile_tokens": [],
        "non_latin_script": bool(p_native or d_native),
        "suspected_mojibake": looks_like_mojibake(repair_mojibake(profile_display_name or ""))
        or looks_like_mojibake(repair_mojibake(id_full_name or "")),
        "reason": "",
    }

    if p_native and d_native and _native_matches(p_native, d_native):
        debug["reason"] = "pass_native_script"
        return True, debug

    # Single-word legal names (common in Indonesia/Myanmar) must match exactly.
    if len(p) == 1 and len(d) == 1:
        if p[0] == d[0]:
            debug["matched_profile_tokens"] = p
            debug["reason"] = "pass_mononym"
            return True, debug
        debug["missing_profile_tokens"] = p
        debug["reason"] = "name_mismatch"
        return False, debug

    if len(p) < 2 or len(d) < 2:
        debug["reason"] = "insufficient_tokens"
        return False, debug

    p_first = p[0]
    p_last = p[-1]

    first_ok = _token_matches(p_first, d)
    last_ok = _token_matches(p_last, d)

    for tok in p:
        if _token_matches(tok, d):
            debug["matched_profile_tokens"].append(tok)
        else:
            debug["missing_profile_tokens"].append(tok)

    if first_ok and last_ok:
        debug["reason"] = "pass"
        return True, debug

    debug["reason"] = "name_mismatch"
    return False, debug


def best_linkedin_match(profile_candidates: list[str], id_candidates: list[str]) -> tuple[bool, dict]:
    """
    Try multiple variants (normal + swapped), return best pass or best debug.

    On failure, ``debug["needs_review"]`` is True when a non-Latin script or
    garbled text was involved: an automated decline is unreliable there, so
    a human should decide.
    """
    best_debug = None
    needs_review = False
    for p in profile_candidates:
        for i in id_candidates:
            ok, dbg = linkedin_style_name_match(p, i)
            dbg["profile_candidate"] = p
            dbg["id_candidate"] = i
            if ok:
                return True, dbg
            needs_review = needs_review or dbg["non_latin_script"] or dbg["suspected_mojibake"]
            if not best_debug or len(dbg.get("matched_profile_tokens", [])) > len(best_debug.get("matched_profile_tokens", [])):
                best_debug = dbg
    best_debug = best_debug or {"reason": "no_candidates"}
    best_debug["needs_review"] = needs_review
    return False, best_debug
