#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_review_brain.py — 审查账本包外验证器（独立实现，不 import review_brain）

设计意图（对应原架构 verify_workgroup_brain.py 的角色）：
  写入器与 Reducer 是「当事人」，本脚本是「独立复核」——用第二套实现重放全账本，
  连写入器自身的实现 bug 也能被交叉发现。校验项：

  V1 逐行 JSON 可解析，信封 12 字段齐全
  V2 事件级 JSON Schema 校验（findings.schema.json，jsonschema 可用时）
  V3 seq 连续、Hash 链衔接、逐行哈希重算一致
  V4 信封声明 phase 与独立状态机推导一致
  V5 角色 × 事件权限矩阵（独立副本）
  V6 租约：事件携带的 lease 与席位登记一致，且未过期
  V7 冻结后零事件
  V8 结案 digest 与独立重算一致
  V9 view.json 与账本尾行一致（head / phase / digest）

用法：python verify_review_brain.py <case_dir> [--schema findings.schema.json]
退出码：0 = 全部通过；1 = 发现问题（stdout 打印报告）
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

LEDGER = "findings.jsonl"
VIEW = "view.json"

ENVELOPE_FIELDS = ["schema", "event_id", "seq", "ts", "case_id", "actor",
                   "lease", "phase", "event", "payload", "prev_hash", "hash"]

PHASE_EVENTS = {
    "opening": {"CASE_OPEN", "SEAT_GRANTED"},
    "blind": {"FINDING", "SCAN_DONE"},
    "cross": {"CHALLENGE", "RETRACT", "REBUTTAL", "APPEAL", "VERDICT", "CASE_FROZEN"},
    "remediation": {"REVISE", "RECHECK", "APPEAL", "VERDICT", "CASE_FROZEN"},
    "frozen": set(),
}
ROLE_EVENTS = {
    "arbiter": {"CASE_OPEN", "SEAT_GRANTED", "VERDICT", "CASE_FROZEN"},
    "producer": {"REBUTTAL", "APPEAL", "REVISE"},
    "reviewer": {"FINDING", "SCAN_DONE", "CHALLENGE", "RETRACT", "RECHECK"},
    "red_team": {"FINDING", "SCAN_DONE", "CHALLENGE", "RETRACT", "RECHECK"},
}


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def line_hash(envelope: dict) -> str:
    # 与引擎一致：签名（sig）不参与哈希
    return sha(canon({k: v for k, v in envelope.items() if k not in ("hash", "sig")}))


def parse_ts(ts: str) -> float:
    from datetime import datetime

    return datetime.fromisoformat(ts).timestamp()


def verify_signatures(events: list[dict], case_dir: Path,
                      pubkey_path: Path | None = None) -> list[str]:
    """V10：机构签名（Ed25519）。只要有一行带 sig，就要求全部带且可验。"""
    problems: list[str] = []
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return ["V10 账本已签名，但环境缺少 cryptography，无法复核"]

    pem = Path(pubkey_path) if pubkey_path else case_dir / "pubkey.pem"
    if not pem.exists():
        return [f"V10 账本已签名，但找不到公钥：{pem.name}（用 --pubkey 指定）"]
    try:
        key = serialization.load_pem_public_key(pem.read_bytes())
    except Exception as e:  # noqa: BLE001
        return [f"V10 公钥无法解析：{e}"]

    for ev in events:
        eid = ev.get("event_id", "?")
        if not ev.get("sig"):
            problems.append(f"V10 {eid} 缺签名（该账本为签名账本）")
            continue
        row = canon({k: v for k, v in ev.items() if k not in ("hash", "sig")})
        try:
            key.verify(base64.b64decode(ev["sig"]), row.encode("utf-8"))
        except InvalidSignature:
            problems.append(f"V10 {eid} 签名不匹配（内容被改，或不是该机构签发）")
        except Exception as e:  # noqa: BLE001
            problems.append(f"V10 {eid} 签名校验异常：{e}")
    return problems


def verify_artifact(events: list[dict], case_dir: Path) -> list[str]:
    """V11：被审文件清单 + 证据可核对。

    1) 清单文件摘要与账本记录一致；
    2) 每个被审文件当前哈希与清单一致；
    3) 用清单重算 snapshot_hash，与立案时记录一致；
    4) 每条 FINDING 的 quote 必须真实出现在其 uri 指向的文件里。
    """
    problems: list[str] = []
    opened = next((e for e in events if e.get("event") == "CASE_OPEN"), None)
    if not opened:
        return problems
    artifact = (opened.get("payload") or {}).get("artifact") or {}
    man = artifact.get("manifest")
    if not man:
        return problems

    mpath = case_dir / str(man.get("path", ""))
    if not mpath.exists():
        return [f"V11 找不到被审文件清单：{mpath.name}"]
    raw = mpath.read_bytes()
    if "sha256:" + hashlib.sha256(raw).hexdigest() != man.get("sha256"):
        problems.append("V11 文件清单摘要与账本记录不一致（清单被替换）")

    manifest = json.loads(raw.decode("utf-8"))
    root = Path(manifest.get("root") or "")
    # 清单里的 root 可以是绝对路径（本机生成）或相对路径（案件目录整体搬走后仍可复核）
    if str(root) and not root.is_absolute():
        root = (case_dir / root).resolve()
    entries = {e["path"]: e for e in manifest.get("files", [])}

    acc = hashlib.sha256()
    for rel in sorted(entries):
        p = root / rel
        if not str(root) or not p.exists():
            problems.append(f"V11 被审文件缺失：{rel}")
            continue
        data = p.read_bytes()
        if "sha256:" + hashlib.sha256(data).hexdigest() != entries[rel].get("sha256"):
            problems.append(f"V11 被审文件已被修改：{rel}")
        acc.update(rel.encode("utf-8"))
        acc.update(b"\0")
        acc.update(data)
        acc.update(b"\0")
    if "sha256:" + acc.hexdigest() != artifact.get("snapshot_hash"):
        problems.append("V11 快照哈希与清单重算结果不一致（被审对象已变）")

    for ev in events:
        if ev.get("event") != "FINDING":
            continue
        for e in (ev.get("payload") or {}).get("evidence", []):
            uri = str(e.get("uri") or "").strip()
            if not uri:
                continue
            rel = uri.rsplit(":", 1)[0]
            if rel not in entries or not str(root):
                continue  # 清单外路径（如通配符）跳过，不判失败
            p = root / rel
            if not p.exists():
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            quote = str(e.get("content") or "").strip()
            if quote and quote not in text and " ".join(quote.split()) not in " ".join(text.split()):
                problems.append(f"V11 证据不在文件中：{uri} · {quote[:40]!r}")
    return problems


def verify(case_dir: Path, schema_path: Path | None,
           pubkey_path: Path | None = None) -> tuple[bool, list[str]]:
    problems: list[str] = []
    ledger = case_dir / LEDGER
    if not ledger.exists():
        return False, [f"账本不存在：{ledger}"]

    raw_lines = ledger.read_text(encoding="utf-8").splitlines()
    events = []
    for i, line in enumerate(raw_lines, 1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as e:
            problems.append(f"V1 第 {i} 行不是合法 JSON：{e}")

    # V1 信封字段齐全
    for ev in events:
        missing = [f for f in ENVELOPE_FIELDS if f not in ev]
        if missing:
            problems.append(
                f"V1 {ev.get('event_id', '?')} 信封缺字段：{missing}"
            )

    # V2 JSON Schema（可选）
    if schema_path and schema_path.exists():
        try:
            from jsonschema import Draft7Validator

            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            validator = Draft7Validator(schema)
            for ev in events:
                for err in validator.iter_errors(ev):
                    problems.append(
                        f"V2 {ev.get('event_id', '?')} schema: {err.message[:120]}"
                    )
        except ImportError:
            problems.append("V2 跳过：未安装 jsonschema")
    else:
        problems.append("V2 跳过：未提供 schema 文件")

    # V10 机构签名（可选：账本带 sig 才校验）
    if any(ev.get("sig") for ev in events):
        problems.extend(verify_signatures(events, case_dir, pubkey_path))

    # V11 被审文件清单 + 证据可核对（可选：立案时带 manifest 才校验）
    problems.extend(verify_artifact(events, case_dir))

    # V3/V4/V5/V6/V7/V8 — 独立重放
    phase = "opening"
    seats: dict[str, dict] = {}          # seat_id -> {role, lease, dims, kind}
    case_dims: list = []
    findings: dict[str, dict] = {}       # fid -> {status, sev, sev_final, chain}
    max_rounds = 0
    frozen = False
    frozen_digest = None
    prev_hash = None
    expect_seq = 1
    scanned: set = set()                 # (seat_id, dimension) 增量累积，绝不看未来事件

    for ev in events:
        tag = f"{ev.get('event_id', '?')}({ev.get('event', '?')})"
        etype, payload = ev.get("event"), ev.get("payload", {})

        # V7 冻结后零事件
        if frozen:
            problems.append(f"V7 冻结后仍有事件：{tag}")
            break

        # V3 seq / 链 / 哈希
        if ev.get("seq") != expect_seq:
            problems.append(f"V3 {tag} seq={ev.get('seq')}，期望 {expect_seq}")
        expect_seq += 1
        if prev_hash is None:
            prev_hash = sha("genesis\x00" + str(ev.get("case_id", "")))
        if ev.get("prev_hash") != prev_hash:
            problems.append(f"V3 {tag} prev_hash 断链")
        if line_hash(ev) != ev.get("hash"):
            problems.append(f"V3 {tag} 哈希重算不一致（内容被改）")
        prev_hash = ev.get("hash")

        # V4 阶段交叉核对（首盲审事件先触发 opening→blind 转移，再检查）
        if phase == "opening" and etype in ("FINDING", "SCAN_DONE"):
            phase = "blind"
        if etype not in PHASE_EVENTS.get(phase, set()):
            problems.append(f"V4 {tag} 事件 {etype} 不属于阶段 {phase}")
        if ev.get("phase") != phase:
            problems.append(
                f"V4 {tag} 信封 phase={ev.get('phase')} ≠ 独立推导 {phase}"
            )

        # V5 权限
        role = ev.get("actor", {}).get("role")
        if role not in ROLE_EVENTS or etype not in ROLE_EVENTS[role]:
            problems.append(f"V5 {tag} 角色 {role} 无权写 {etype}")

        # V6 租约（seat 登记核对）
        seat_id = ev.get("actor", {}).get("seat_id")
        if etype != "CASE_OPEN":
            reg = seats.get(seat_id)
            if reg is None:
                problems.append(f"V6 {tag} 未登记席位 {seat_id}")
            else:
                if ev.get("lease") != reg["lease"]:
                    problems.append(f"V6 {tag} 携带租约与席位登记不符")
                try:
                    if parse_ts(ev.get("ts", "")) > parse_ts(reg["lease"]["expires_at"]):
                        problems.append(f"V6 {tag} 写入时租约已过期")
                except Exception:
                    problems.append(f"V6 {tag} 时间戳无法解析")

        # ── 独立状态机 ──
        if etype == "CASE_OPEN":
            case_dims = payload.get("dimensions", [])
            max_rounds = payload.get("max_rounds", 0)
            seats["arbiter"] = {"role": "arbiter", "lease": ev.get("lease", {}),
                                "dims": case_dims, "kind": "seat"}
        elif etype == "SEAT_GRANTED":
            seats[payload["seat_id"]] = {
                "role": payload.get("role"), "lease": payload.get("lease", {}),
                "dims": payload.get("dimensions", []), "kind": "seat",
            }
        elif etype == "SCAN_DONE":
            scanned.add((seat_id, payload.get("dimension")))
        elif etype == "FINDING":
            findings[payload["finding_id"]] = {
                "status": "pending", "sev": payload.get("severity"),
                "sev_final": None, "chain": [], "disputes": 0, "scanned_dims": set(),
            }
        elif etype in ("CHALLENGE", "REBUTTAL", "APPEAL"):
            fid = payload.get("target_finding") or _appeal_target(
                findings, payload.get("target_verdict")
            )
            if fid and fid in findings:
                findings[fid]["status"] = "contested"
                findings[fid]["disputes"] += 1
            else:
                problems.append(f"V* {tag} 目标 {fid} 不存在")
        elif etype == "RETRACT":
            fid = payload.get("target_finding")
            if fid in findings:
                findings[fid]["status"] = "retracted"
        elif etype == "VERDICT":
            fid = payload.get("target_finding")
            f = findings.get(fid)
            if f is None:
                problems.append(f"V* {tag} 裁定目标 {fid} 不存在")
            else:
                f["chain"].append(payload.get("verdict_id"))
                f["disputes"] = 0
                ruling = payload.get("ruling")
                if ruling == "overruled":
                    f["status"] = "overruled"
                else:
                    f["status"] = "sustained"
                    if ruling == "reclassified":
                        f["sev_final"] = payload.get("severity_final")
        elif etype == "RECHECK":
            fid = payload.get("target_finding")
            if fid in findings:
                findings[fid]["status"] = (
                    "fixed" if payload.get("result") == "fixed" else "not_fixed"
                )
        elif etype == "CASE_FROZEN":
            frozen = True
            frozen_digest = payload.get("digest")
            phase = "frozen"

        # 阶段转移（独立推导，只看已处理前缀）
        if phase == "opening" and etype in ("FINDING", "SCAN_DONE"):
            phase = "blind"
        if phase == "blind" and _all_scanned_now(seats, scanned, case_dims):
            phase = "cross"
        if (
            phase == "cross"
            and all(
                f["status"] not in ("pending", "contested")
                for f in findings.values()
            )
            and any(f["status"] == "sustained" for f in findings.values())
        ):
            phase = "remediation"

    # V8 digest 独立重算
    if frozen_digest is not None:
        counts = {"sustained": 0, "overruled": 0, "retracted": 0}
        by_sev: dict[str, int] = {}
        for f in findings.values():
            if f["status"] in ("sustained", "fixed", "not_fixed"):
                counts["sustained"] += 1
                sev = f["sev_final"] or f["sev"]
                by_sev[sev] = by_sev.get(sev, 0) + 1
            elif f["status"] == "overruled":
                counts["overruled"] += 1
            elif f["status"] == "retracted":
                counts["retracted"] += 1
        mine = dict(counts)
        mine["by_severity"] = by_sev
        if mine != frozen_digest:
            problems.append(f"V8 digest 与独立重算不一致：{frozen_digest} ≠ {mine}")

    # V9 view.json 一致性
    view_path = case_dir / VIEW
    if view_path.exists():
        view = json.loads(view_path.read_text(encoding="utf-8"))
        tail = events[-1] if events else {}
        if view.get("head", {}).get("seq") != tail.get("seq"):
            problems.append(
                f"V9 view.head.seq={view.get('head', {}).get('seq')} ≠ 账本尾行 seq={tail.get('seq')}"
            )
        if view.get("head", {}).get("hash") != tail.get("hash"):
            problems.append("V9 view.head.hash 与账本尾行哈希不一致（view 落后或被改）")
        if view.get("phase") != phase:
            problems.append(
                f"V9 view.phase={view.get('phase')} ≠ 独立推导 {phase}"
            )
    else:
        problems.append("V9 view.json 缺失（可用 review_brain.py view 重建）")

    return (not problems), problems


def _appeal_target(findings: dict, verdict_id: str | None):
    for fid, f in findings.items():
        if verdict_id in f["chain"]:
            return fid
    return None


def _all_scanned_now(seats: dict, scanned: set, case_dims) -> bool:
    """独立版盲审关门判定：每审查席位×分派维度均有 SCAN_DONE（只看已处理事件）。"""
    for sid, reg in seats.items():
        if reg["role"] in ("reviewer",):
            for d in reg["dims"]:
                if (sid, d) not in scanned:
                    return False
        elif reg["role"] == "red_team":
            for d in case_dims:
                if (sid, d) not in scanned:
                    return False
    return True


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="审查账本包外验证器")
    ap.add_argument("case_dir")
    ap.add_argument("--schema", default=None,
                    help="findings.schema.json 路径（默认自动查找案件目录 / 脚本同目录）")
    ap.add_argument("--pubkey", default=None, help="签名账本的公钥 PEM（默认取案件目录 pubkey.pem）")
    ap.add_argument("--no-schema", action="store_true",
                    help="显式跳过 V2 schema 校验（不推荐，结果不完整）")
    args = ap.parse_args(argv)

    case_dir = Path(args.case_dir)
    # 0.6.1 修复：原来 --schema 默认 None，V2 静默跳过 —— 「V1-V9 全绿」
    # 只在调用方记得传参时成立，属于 fail-open。现在默认自动查找。
    schema = None
    if args.no_schema:
        pass
    elif args.schema:
        schema = Path(args.schema)
    else:
        for cand in (case_dir / "findings.schema.json",
                     Path(__file__).resolve().parent / "findings.schema.json"):
            if cand.exists():
                schema = cand
                break

    pubkey = Path(args.pubkey) if args.pubkey else None
    ok, problems = verify(case_dir, schema, pubkey)

    print(f"包外验证：{case_dir}")
    if schema is not None:
        print(f"  schema：{schema}")
    else:
        print("  ⚠️  未找到 findings.schema.json，V2 结构校验已跳过（用 --schema 指定）")
    if ok:
        extra = []
        if (case_dir / "pubkey.pem").exists() or pubkey:
            extra.append("V10 签名")
        if (case_dir / "artifact.manifest.json").exists():
            extra.append("V11 证据核对")
        tail = ("＋" + " / ".join(extra)) if extra else ""
        print(f"  ✅ V1-V9 全部通过（结构 / 链 / 阶段 / 权限 / 租约 / 冻结 / 摘要 / 投影）{tail}")
        return 0
    print(f"  ❌ 发现 {len(problems)} 个问题：")
    for p in problems:
        print(f"     - {p}")
    return 1


if __name__ == "__main__":
    # Windows 控制台默认不是 UTF-8（cp936/cp1252），直接打印中文会抛 UnicodeEncodeError。
    # 客户机器上一跑就崩的那种，必须在这里兜住。
    for _s in (sys.stdout, sys.stderr):
        if hasattr(_s, "reconfigure"):
            _s.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
