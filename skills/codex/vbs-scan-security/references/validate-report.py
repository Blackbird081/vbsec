#!/usr/bin/env python3
"""Kiểm tra JSON summary cuối report vbsec có đúng schema không.

Usage: python3 <skill-dir>/references/validate-report.py vbsec-reports/scan-<timestamp>.md

Exit 0 = hợp lệ. Exit 1 = in danh sách lỗi, agent phải sửa report rồi chạy lại.
Chỉ dùng thư viện chuẩn Python 3.
"""
import glob
import json
import os
import re
import sys

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
VERDICTS = {"PASS", "WARN", "FAIL"}
REQUIRED_TOP = ["verdict", "summary", "scope", "files_reviewed", "primary_language",
                "specialized_rules_used", "mode", "date", "findings"]
REQUIRED_FINDING = ["file", "line", "rule_id", "severity", "issue_summary", "fix_summary"]
ALIASES = {"id": "rule_id", "rule": "rule_id", "note": "issue_summary", "summary": "issue_summary",
           "issue": "issue_summary", "fix": "fix_summary", "path": "file"}
# Finding mà chính issue_summary thừa nhận là không khai thác được, hoặc thú nhận đã gán rule gần nhất
# cho vấn đề ngoài 21 rule → không phải finding, phải chuyển sang hardening_notes. Ngoại lệ: rule
# dependency (20, 22) — "CVE không reachable với code hiện tại" ở đó là lý do hạ severity, vẫn là finding.
DEPENDENCY_RULES = {"OUTDATED-DEPENDENCY", "VULNERABLE-DEPENDENCY"}
SELF_NEGATING = re.compile(
    r"\b(not|isn't|is not|aren't|are not|cannot be|can't be|no longer|never)\s+"
    r"(currently\s+|directly\s+|actually\s+)?(reachable|exploitable|exploited|triggerable|affected|vulnerable|attacker[- ]controlled)\b"
    r"|\b(un)?reachable by current code\b|\bnone (of (them|these) )?(is|are)? ?reachable\b"
    r"|\bno (concrete |direct |known )?(exploit|attack) (path|vector)\b"
    r"|\b(is|are|remains?|looks?|seems?|appears?) (already |currently )?safe\b"
    r"|\bsafe (as[- ]is|by default|in practice)\b"
    r"|\b(defense[- ]in[- ]depth|hardening|best[- ]practice) (only|suggestion|note)\b"
    r"|\bmapped to (the )?(closest|nearest)\b|\b(closest|nearest) (canonical )?rule\b"
    r"|\bno security impact\b|\btheoretical only\b"
    r"|không khai thác được|không tới được|không có đường khai thác|chỉ là (gợi ý|phòng thủ|hardening)"
    r"|(?<!không )(?<!chưa )\ban toàn( với| trong| ở)? (hiện tại|thực tế|mặc định)\b|\bđã an toàn\b"
    r"|gán (vào |cho )?rule gần nhất|rule gần nhất",
    re.I)


def canonical_rule_ids():
    ids = set()
    for path in glob.glob(os.path.join(SKILL_DIR, "rules", "generic", "*.md")):
        m = re.search(r"^id:\s*(\S+)", open(path, encoding="utf-8").read(), re.M)
        if m:
            ids.add(m.group(1))
    return ids


def validate(report_path):
    text = open(report_path, encoding="utf-8").read()
    blocks = re.findall(r"```json\s*\n(.*?)\n```", text, re.S)
    if not blocks:
        return ["không có block ```json ở cuối report"]
    try:
        data = json.loads(blocks[-1])
    except json.JSONDecodeError as e:
        return [f"JSON không parse được: {e}"]

    errors = []
    rule_ids = canonical_rule_ids()
    for key in REQUIRED_TOP:
        if key not in data:
            errors.append(f"thiếu field top-level `{key}`")
    if data.get("verdict") not in VERDICTS:
        errors.append(f"`verdict` phải là PASS/WARN/FAIL, đang là {data.get('verdict')!r}")

    findings = data.get("findings", [])
    if not isinstance(findings, list):
        return errors + ["`findings` phải là array"]

    for i, f in enumerate(findings):
        where = f"findings[{i}] ({f.get('file', '?')}:{f.get('line', '?')})"
        for alias, proper in ALIASES.items():
            if alias in f and proper not in f:
                errors.append(f"{where}: dùng key `{alias}`, phải đổi thành `{proper}`")
        for key in REQUIRED_FINDING:
            if key not in f and not any(a in f and p == key for a, p in ALIASES.items()):
                errors.append(f"{where}: thiếu `{key}`")
        rid = f.get("rule_id")
        if rid is not None and rid not in rule_ids:
            errors.append(f"{where}: rule_id `{rid}` không thuộc danh sách rule canonical. "
                          f"KHÔNG gán sang rule gần nhất: nếu có đường khai thác cụ thể thì chọn đúng rule mô tả nó, "
                          f"còn không thì chuyển sang `hardening_notes`")
        issue_text = " ".join(str(f.get(k, "")) for k in ("issue_summary", "issue", "note", "summary"))
        m = SELF_NEGATING.search(issue_text)
        if m and rid not in DEPENDENCY_RULES:
            errors.append(f"{where}: issue_summary tự phủ định (\"{m.group(0)}\"). Chọn 1 trong 2: "
                          f"(a) có đường khai thác thật → viết lại issue_summary nêu attacker làm gì, lấy được gì, bỏ cụm phủ định; "
                          f"(b) không nêu được → xoá khỏi `findings[]`, ghi vào `hardening_notes[]` (không rule_id), "
                          f"cập nhật `summary` và verdict")
        sev = f.get("severity")
        if sev is not None and sev not in SEVERITIES:
            errors.append(f"{where}: severity phải viết hoa CRITICAL/HIGH/MEDIUM/LOW, đang là {sev!r}")
        line = f.get("line")
        if line is not None and not (isinstance(line, int) and line >= 1):
            errors.append(f"{where}: `line` phải là số nguyên >= 1 (dòng bắt đầu), đang là {line!r}")

    seen = {}
    for i, f in enumerate(findings):
        key = (str(f.get("file", "")).lstrip("./"), f.get("line"), f.get("rule_id"))
        if key in seen:
            errors.append(f"findings[{i}] trùng findings[{seen[key]}] (cùng file:line:rule_id) — gộp lại, giữ severity cao nhất")
        else:
            seen[key] = i

    summary = data.get("summary", {})
    for sev in SEVERITIES:
        want = sum(1 for f in findings if f.get("severity") == sev)
        got = summary.get(sev.lower())
        if got != want:
            errors.append(f"summary.{sev.lower()} = {got!r} nhưng findings có {want} mục {sev}")

    notes = data.get("hardening_notes", [])
    if not isinstance(notes, list) or any(not isinstance(n, dict) or "note" not in n for n in notes):
        errors.append("`hardening_notes` (nếu có) phải là array các object có field `note`")
    return errors


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    errors = validate(sys.argv[1])
    if errors:
        print(f"JSON summary KHÔNG hợp lệ ({len(errors)} lỗi):")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    print("JSON summary hợp lệ")


if __name__ == "__main__":
    main()
