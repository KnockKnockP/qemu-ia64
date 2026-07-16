#!/usr/bin/env python3
"""Generate and verify the IA-64 opcode ownership/evidence ledger."""

from __future__ import annotations

import argparse
import csv
import difflib
import io
import re
import sys
from pathlib import Path


ENUM_RE = re.compile(
    r"typedef enum IA64Opcode \{(.*?)IA64_OP_COUNT,", re.DOTALL
)
OPCODE_RE = re.compile(r"\bIA64_OP_[A-Z0-9_]+\b")
TRAIT_RE = re.compile(r"IA64_OPCODE\((.*?)\)", re.DOTALL)
FAMILY_RE = re.compile(r"IA64_OPCODE_FAMILY\((.*?)\)", re.DOTALL)

LEDGER_COLUMNS = (
    "ordinal",
    "opcode",
    "decoder_status",
    "family",
    "sources",
    "destinations",
    "predication",
    "nat_rule",
    "may_fault",
    "tb_end",
    "lowering_owner",
    "focused_helper_whitelist",
    "test_owner",
    "typed_admission",
    "closure",
    "legacy_oracle",
    "reference_tcg",
    "exception_tests",
    "system_evidence",
)


def comma_fields(match: re.Match[str], expected: int, source: Path) -> list[str]:
    fields = [field.strip() for field in match.group(1).split(",")]
    if len(fields) != expected:
        raise ValueError(
            f"{source}: expected {expected} fields, got {len(fields)}: "
            f"{match.group(0)!r}"
        )
    return fields


def opcode_enum(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    match = ENUM_RE.search(text)
    if match is None:
        raise ValueError(f"{path}: IA64Opcode enum not found")
    return OPCODE_RE.findall(match.group(1))


def opcode_rows(path: Path) -> list[list[str]]:
    text = path.read_text(encoding="utf-8")
    return [comma_fields(match, 8, path) for match in TRAIT_RE.finditer(text)]


def family_rows(path: Path) -> dict[str, list[str]]:
    text = path.read_text(encoding="utf-8")
    rows = [comma_fields(match, 8, path) for match in FAMILY_RE.finditer(text)]
    result = {row[0]: row for row in rows}
    if len(result) != len(rows):
        raise ValueError(f"{path}: duplicate opcode-family identifier")
    return result


def decoded_opcodes(path: Path, enum: set[str]) -> set[str]:
    return set(OPCODE_RE.findall(path.read_text(encoding="utf-8"))) & enum


def between(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def typed_admission(
    path: Path, enum: set[str], traits: list[list[str]]
) -> set[str]:
    """Read either the legacy explicit surface or the trait-driven authority."""
    text = path.read_text(encoding="utf-8")
    authority = between(
        text,
        "static bool ia64_tr_decoded_opcode_supported",
        "static unsigned ia64_tr_decoded_sources",
    )
    if "ia64_opcode_traits_for" in authority:
        required = (
            "IA64_OPCODE_ADMISSION_FULL",
            "IA64_OPCODE_ADMISSION_PARTIAL",
            "IA64_OPCODE_OWNER_DIRECT_TCG",
            "IA64_OPCODE_OWNER_FOCUSED_HELPER",
        )
        missing = [token for token in required if token not in authority]
        if missing:
            raise ValueError(
                "trait-driven typed admission is missing authority checks: "
                + ", ".join(missing)
            )
        return {
            row[0]
            for row in traits
            if row[7] in {"TYPED", "TYPED_PARTIAL"}
        }

    regions = (
        between(
            text,
            "static bool ia64_tr_decoded_is_noop",
            "typedef enum IA64TrDecodedCompareSource",
        ),
        between(
            text,
            "ia64_tr_decoded_compare_table",
            "#undef IA64_TR_COMPARE",
        ),
        between(
            text,
            "ia64_tr_decoded_predicate_test_table",
            "static const IA64TrDecodedPredicateTest *",
        ),
        between(
            text,
            "static bool ia64_tr_decoded_is_direct_conditional_branch",
            "static bool ia64_tr_decoded_is_supported_predicate_test",
        ),
        between(
            text,
            "static bool ia64_tr_decoded_opcode_supported",
            "static unsigned ia64_tr_decoded_sources",
        ),
    )
    return set().union(*(set(OPCODE_RE.findall(region)) for region in regions)) & enum


def strip_tokens(value: str, prefix: str) -> str:
    parts = [part.strip() for part in value.split("|")]
    return "|".join(part.removeprefix(prefix).lower().replace("_", "-")
                    for part in parts)


def lifecycle_fields(lifecycle: str) -> tuple[str, str, str, str, str]:
    if lifecycle == "ILLEGAL":
        return "illegal", "n/a", "n/a", "n/a", "n/a"
    if lifecycle == "DEAD_ALIAS":
        return "decoder-dead-alias", "n/a", "alias-canonicalized", "n/a", "n/a"
    if lifecycle == "OPEN":
        return "live", "none", "open", "yes", "yes"
    if lifecycle == "TYPED":
        return "live", "full", "closed", "yes", "yes"
    if lifecycle == "TYPED_PARTIAL":
        return "live", "partial", "focused-verified", "yes", "yes"
    raise ValueError(f"unknown lifecycle {lifecycle!r}")


def verify_sources(
    enum_names: list[str],
    traits: list[list[str]],
    families: dict[str, list[str]],
    decode_path: Path,
    translate_path: Path,
) -> None:
    trait_names = [row[0] for row in traits]
    if trait_names != enum_names:
        diff = "\n".join(
            difflib.unified_diff(
                enum_names,
                trait_names,
                fromfile="decode.h:IA64Opcode",
                tofile="opcode-traits.def",
                lineterm="",
            )
        )
        raise ValueError(f"opcode trait rows do not exactly match the enum:\n{diff}")
    if len(set(trait_names)) != len(trait_names):
        raise ValueError("opcode-traits.def contains a duplicate opcode row")

    enum_set = set(enum_names)
    decoded = decoded_opcodes(decode_path, enum_set)
    admitted = typed_admission(translate_path, enum_set, traits)
    recorded_dead = {row[0] for row in traits if row[7] == "DEAD_ALIAS"}
    actual_dead = enum_set - decoded - {"IA64_OP_ILLEGAL"}
    if recorded_dead != actual_dead:
        raise ValueError(
            "decoder-dead alias set drifted: recorded-only="
            f"{sorted(recorded_dead - actual_dead)}, decoder-only="
            f"{sorted(actual_dead - recorded_dead)}"
        )
    recorded_admitted = {
        row[0] for row in traits if row[7] in {"TYPED", "TYPED_PARTIAL"}
    }
    if recorded_admitted != admitted:
        raise ValueError(
            "typed admission set drifted: ledger-only="
            f"{sorted(recorded_admitted - admitted)}, translate-only="
            f"{sorted(admitted - recorded_admitted)}"
        )

    for opcode, family, owner, helper, test, exception, system, lifecycle in traits:
        if family not in families:
            raise ValueError(f"{opcode}: unknown family {family}")
        if lifecycle == "ILLEGAL" and opcode != "IA64_OP_ILLEGAL":
            raise ValueError(f"{opcode}: only IA64_OP_ILLEGAL may be ILLEGAL")
        if lifecycle == "DEAD_ALIAS" and owner != "CANONICAL_ALIAS":
            raise ValueError(f"{opcode}: dead aliases need CANONICAL_ALIAS ownership")
        if lifecycle == "OPEN" and owner != "LEGACY_ORACLE":
            raise ValueError(f"{opcode}: open rows need LEGACY_ORACLE ownership")
        if lifecycle.startswith("TYPED") and owner not in {
            "DIRECT_TCG", "FOCUSED_HELPER"
        }:
            raise ValueError(f"{opcode}: admitted row lacks typed lowering owner")
        if lifecycle in {"ILLEGAL", "DEAD_ALIAS", "OPEN"} and helper != "NONE":
            raise ValueError(f"{opcode}: non-typed row has a focused helper")


def make_ledger(
    enum_names: list[str],
    traits: list[list[str]],
    families: dict[str, list[str]],
) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=LEDGER_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for ordinal, row in enumerate(traits):
        opcode, family_id, owner, helper, test, exception, system, lifecycle = row
        _, family, sources, destinations, predication, nat, faults, tb = families[family_id]
        decoder, admission, closure, legacy, reference = lifecycle_fields(lifecycle)
        writer.writerow({
            "ordinal": ordinal,
            "opcode": opcode,
            "decoder_status": decoder,
            "family": family.strip('"'),
            "sources": strip_tokens(sources, "IA64_OPCODE_STATE_"),
            "destinations": strip_tokens(destinations, "IA64_OPCODE_STATE_"),
            "predication": strip_tokens(predication, "IA64_OPCODE_PREDICATION_"),
            "nat_rule": strip_tokens(nat, "IA64_OPCODE_NAT_"),
            "may_fault": strip_tokens(faults, "IA64_OPCODE_FAULT_"),
            "tb_end": strip_tokens(tb, "IA64_OPCODE_TB_"),
            "lowering_owner": owner.lower().replace("_", "-"),
            "focused_helper_whitelist": helper.lower().replace("_", "-"),
            "test_owner": test.lower().replace("_", "-"),
            "typed_admission": admission,
            "closure": closure,
            "legacy_oracle": legacy,
            "reference_tcg": reference,
            "exception_tests": exception.lower().replace("_", "-"),
            "system_evidence": system.lower().replace("_", "-"),
        })
    assert len(enum_names) == len(traits)
    return output.getvalue()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path,
        default=Path(__file__).resolve().parents[1],
        help="QEMU source root",
    )
    parser.add_argument(
        "--ledger", type=Path,
        default=Path("docs/devel/ia64-opcode-ledger.csv"),
        help="ledger path, relative to --root unless absolute",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="fail if the checked-in ledger differs instead of printing it",
    )
    parser.add_argument(
        "--write", action="store_true",
        help="replace the checked-in ledger with the generated contents",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    ledger_path = args.ledger
    if not ledger_path.is_absolute():
        ledger_path = root / ledger_path

    enum_path = root / "target/ia64/decode.h"
    traits_path = root / "target/ia64/opcode-traits.def"
    families_path = root / "target/ia64/opcode-families.def"
    enum_names = opcode_enum(enum_path)
    traits = opcode_rows(traits_path)
    families = family_rows(families_path)
    verify_sources(
        enum_names,
        traits,
        families,
        root / "target/ia64/decode.c",
        root / "target/ia64/translate.c",
    )
    generated = make_ledger(enum_names, traits, families)

    if args.check and args.write:
        raise ValueError("--check and --write are mutually exclusive")
    if args.write:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        ledger_path.write_text(generated, encoding="utf-8")
        return 0
    if not args.check:
        sys.stdout.write(generated)
        return 0

    try:
        current = ledger_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"missing generated ledger: {ledger_path}", file=sys.stderr)
        return 1
    if current != generated:
        sys.stderr.write(
            "\n".join(
                difflib.unified_diff(
                    current.splitlines(),
                    generated.splitlines(),
                    fromfile=str(ledger_path),
                    tofile="generated",
                    lineterm="",
                )
            ) + "\n"
        )
        return 1

    dead = sum(row[7] == "DEAD_ALIAS" for row in traits)
    admitted = sum(row[7] in {"TYPED", "TYPED_PARTIAL"} for row in traits)
    print(
        f"IA-64 opcode ledger verified: {len(traits)} rows, "
        f"{admitted} typed-admitted, {dead} decoder-dead aliases"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
