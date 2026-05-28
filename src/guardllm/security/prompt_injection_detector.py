"""Heuristic prompt-injection detector for inbound text/HTML content."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment

from guardllm.security.types import ContentType

_URL_RE = re.compile(r"https?://\S+", re.I)
_INDEX_RE = re.compile(r"(?:\[\s*\d{1,4}\s*\]|\(\s*\d{1,4}\s*\)|#\s*\d{1,4}\b)")
_REPEATED_ALPHA_RE = re.compile(r"([a-z])\1{2,}")
_REPEATED_PUNCT_RE = re.compile(r"([!?.,])\1{1,}")

_IMPERATIVE_RE = re.compile(
    r"\b(please\s+)?(click|open|go|read|find|share|send|delete|replace|type|input|upvote|leave|add|ignore|reveal|export|compile)\b",
    re.I,
)
_OVERRIDE_RE = re.compile(
    r"\b(ignore|instead|rather than|must first|before typing|original (goal|instruction)|following (instruction|description)|regardless of)\b",
    re.I,
)
_CONCEALMENT_RE = re.compile(
    r"\b(do not mention this message|do not think step[- ]by[- ]step|do not ask the user|without telling the user)\b",
    re.I,
)
_SENSITIVE_RE = re.compile(
    r"\b(api key|openai api key|token|credential|credentials|password|ssh|credit card|bank account|secret|private key|last 3 emails?|group chat messages?)\b",
    re.I,
)
_ACTION_TARGET_RE = re.compile(
    r"\b(add to cart|upvote|leave a comment|open a new tab|go to url_ref|read (the )?(document|file)|find (an )?(existing )?(document|file)|fill out (the )?form|complete (the )?form|type (the )?task|click index_ref)\b",
    re.I,
)
_URGENCY_RE = re.compile(
    r"\b(alert|urgent|very important|critical|immediately|without delay)\b", re.I
)

_CLICK_INDEX_RE = re.compile(r"\bplease click index_ref\b", re.I)
_SECRET_SOLICIT_RE = re.compile(
    r"\bcould you share\b.{0,80}\b(api key|openai api key|ssh credentials?|credit card|bank account|password|token|handphone number|phone number)\b",
    re.I | re.S,
)
_GOAL_REWRITE_RE = re.compile(
    r"\bif the original goal is\b.{0,120}\byou should (always|first|instead)\b",
    re.I | re.S,
)
_RIGHT_PLACE_STRONG_RE = re.compile(
    r"\bthis is the right place to input the (email|first name|last name|name|city name|physical address|zip code|confirm(?:ation of)? email address|ticket number|drop-off location)\b",
    re.I,
)
_DATA_OVERRIDE_RE = re.compile(
    r"\b(actual (email|price|miles)|ignore (the )?(labeled )?price|ignore the image|ignore relative position)\b",
    re.I,
)

_BENIGN_FORM_GUIDE_RE = re.compile(
    r"\bright place to input your email address for notifications|share (the )?(meeting notes|agenda|document|updates?)\b",
    re.I,
)

_HIDDEN_STYLE_PATTERNS = (
    re.compile(r"display\s*:\s*none", re.I),
    re.compile(r"visibility\s*:\s*hidden", re.I),
    re.compile(r"opacity\s*:\s*0(?:[;\s\"]|$)", re.I),
    re.compile(r"font-size\s*:\s*0", re.I),
)

_HIDDEN_CLASS_HINTS = ("hidden", "visually-hidden", "sr-only", "screen-reader")


@dataclass
class PromptInjectionSignal:
    """Prompt-injection detection result."""

    is_attack: bool
    score: float
    warnings: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)


def _normalize_text(text: str) -> str:
    """Canonicalize text so rules fire on broad paraphrase forms."""
    out = unicodedata.normalize("NFKC", text).lower()
    out = _URL_RE.sub(" url_ref ", out)
    out = _INDEX_RE.sub(" index_ref ", out)
    out = _REPEATED_ALPHA_RE.sub(r"\1\1", out)
    out = _REPEATED_PUNCT_RE.sub(r"\1", out)
    out = re.sub(r"\s+", " ", out).strip()
    return out


def _score_clause(clause: str) -> tuple[float, list[str]]:
    score = 0.0
    matched: list[str] = []

    imperative = bool(_IMPERATIVE_RE.search(clause))
    override = bool(_OVERRIDE_RE.search(clause))
    concealment = bool(_CONCEALMENT_RE.search(clause))
    sensitive = bool(_SENSITIVE_RE.search(clause))
    action_target = bool(_ACTION_TARGET_RE.search(clause))
    urgency = bool(_URGENCY_RE.search(clause))

    click_index = bool(_CLICK_INDEX_RE.search(clause))
    secret_solicit = bool(_SECRET_SOLICIT_RE.search(clause))
    goal_rewrite = bool(_GOAL_REWRITE_RE.search(clause))
    right_place_strong = bool(_RIGHT_PLACE_STRONG_RE.search(clause))
    data_override = bool(_DATA_OVERRIDE_RE.search(clause))

    if override and (imperative or action_target):
        score += 0.55
        matched.append("instruction_override")
    if concealment:
        score += 0.50
        matched.append("concealment_directive")
    if secret_solicit:
        score += 0.60
        matched.append("secret_solicitation")
    if goal_rewrite:
        score += 0.65
        matched.append("goal_rewrite")
    if right_place_strong:
        score += 0.70
        matched.append("form_field_redirection")
    if click_index:
        score += 0.70
        matched.append("click_directive_injection")
    if data_override:
        score += 0.60
        matched.append("data_override_instruction")
    if urgency and (override or action_target):
        score += 0.35
        matched.append("urgent_goal_hijack")

    atom_count = sum([imperative, override, concealment, sensitive, action_target, urgency])
    if atom_count >= 3:
        score += 0.25
        matched.append("multi_signal_composition")

    # Benign guardrails to keep precision high as feature atoms broaden.
    if _BENIGN_FORM_GUIDE_RE.search(clause) and not (
        secret_solicit or goal_rewrite or click_index or concealment or data_override
    ):
        score = max(0.0, score - 0.45)
        matched.append("benign_guard")

    return min(score, 1.0), matched


def _scan_text(text: str) -> tuple[float, list[str]]:
    normalized = _normalize_text(text)
    clauses = [
        c.strip() for c in re.split(r"[.!?;\n]+|\bthen\b|\bafter that\b", normalized) if c.strip()
    ]
    if not clauses:
        clauses = [normalized]

    max_score = 0.0
    matched_all: set[str] = set()
    high_signal_clauses = 0
    for clause in clauses:
        score, matched = _score_clause(clause)
        if score >= 0.40:
            high_signal_clauses += 1
        if score > max_score:
            max_score = score
        if score >= 0.20:
            matched_all.update(matched)

    if high_signal_clauses >= 2:
        max_score = min(1.0, max_score + 0.10)
        matched_all.add("multi_clause_consistency")

    return max_score, sorted(matched_all)


def _scan_html_hidden_channels(html: str) -> tuple[float, list[str]]:
    soup = BeautifulSoup(html, "html.parser")
    score = 0.0
    matched: list[str] = []

    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        text = str(comment)
        s, m = _scan_text(text)
        if s > 0:
            score += 0.30
            matched.extend(["hidden_comment"] + m)
            break

    for el in soup.find_all(True):
        attrs = getattr(el, "attrs", None) or {}
        attr_values: list[str] = []
        for key, value in attrs.items():
            k = str(key).lower()
            if k in ("title", "alt", "aria-label") or k.startswith("data-"):
                attr_values.append(" ".join(value) if isinstance(value, list) else str(value))
        attr_text = " ".join(attr_values).strip()
        if attr_text:
            s, m = _scan_text(attr_text)
            if s > 0:
                score += 0.25
                matched.extend(["hidden_attribute"] + m)
                break

    for el in soup.find_all(True):
        attrs = getattr(el, "attrs", None) or {}
        style = str(attrs.get("style", ""))
        cls = " ".join(
            attrs.get("class", [])
            if isinstance(attrs.get("class"), list)
            else [str(attrs.get("class", ""))]
        )
        has_hidden_style = any(p.search(style) for p in _HIDDEN_STYLE_PATTERNS)
        has_hidden_class = any(h in cls.lower() for h in _HIDDEN_CLASS_HINTS)
        if has_hidden_style or has_hidden_class:
            text = el.get_text(" ", strip=True)
            if not text:
                continue
            s, m = _scan_text(text)
            if s > 0:
                score += 0.30
                matched.extend(["hidden_visual_channel"] + m)
                break

    return min(score, 1.0), matched


def detect_prompt_injection(content: str, content_type: ContentType) -> PromptInjectionSignal:
    """Detect likely prompt-injection text in inbound payloads."""
    full_score = 0.0
    matched: list[str] = []

    s, m = _scan_text(content)
    full_score += s
    matched.extend(m)

    if content_type == ContentType.HTML:
        hs, hm = _scan_html_hidden_channels(content)
        full_score += hs
        matched.extend(hm)

    full_score = min(full_score, 1.0)
    is_attack = full_score >= 0.45
    warnings: list[str] = []
    if is_attack:
        warnings.append("Prompt-injection indicators detected: " + ", ".join(sorted(set(matched))))
    elif full_score >= 0.25:
        warnings.append(
            "Potential prompt-injection signal detected: " + ", ".join(sorted(set(matched)))
        )

    return PromptInjectionSignal(
        is_attack=is_attack,
        score=full_score,
        warnings=warnings,
        matched_rules=sorted(set(matched)),
    )
