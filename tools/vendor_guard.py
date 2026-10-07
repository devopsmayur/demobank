#!/usr/bin/env python3
"""vendor_guard - deterministic third-party ICT gate for CI (complements CodeRabbit).

Checks code and dependency manifests against governance/approved-vendors.yaml.
Every finding carries the regulatory references it supports, so the output doubles as audit evidence.

Known limits (by design, say so in the demo): static analysis only. Endpoints built at runtime
are caught by the runtime egress guard + network egress allowlist, not by this tool.
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import fnmatch
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

OUTS = "EBA/GL/2019/02 (Outsourcing)"
ICT = "EBA/GL/2019/04 (ICT & security risk)"
DORA = "DORA Reg. (EU) 2022/2554"

RULES = {
    "VG-001": ("Endpoint not approved for declared vendor",
               [f"{OUTS} s.12 pre-outsourcing analysis & due diligence", f"{DORA} Art.28(4)"]),
    "VG-002": ("Unapproved external SDK / dependency",
               [f"{ICT} s.3.6.2 ICT systems acquisition & development", f"{OUTS} s.12", f"{DORA} Art.28(4)"]),
    "VG-003": ("Network call bypasses guarded egress or uses dynamic endpoint",
               [f"{ICT} s.3.4 information security (network/logical security)", f"{DORA} Art.9"]),
    "VG-004": ("External endpoint used without @third_party declaration",
               [f"{OUTS} s.11 documentation / register of arrangements", f"{DORA} Art.28(3) register of information"]),
    "VG-005": ("Data class not approved for vendor",
               [f"{ICT} s.3.4 data classification & protection", f"{OUTS} s.12 risk assessment (data protection)"]),
    "VG-006": ("Vendor register entry incomplete or review expired",
               [f"{OUTS} s.11 / s.14 oversight / s.15 exit strategies", f"{DORA} Art.28(3), Art.28(8)"]),
}

HTTP_MODULES = {"requests", "httpx", "aiohttp", "urllib3", "http.client", "urllib.request",
                "socket", "smtplib", "ftplib", "websockets"}
URL_RE = re.compile(r"^(?:https?|wss?|ftp)://([^/\s:?#]+)", re.I)
REQUIRED_EXTERNAL = ["service", "hosts", "criticality", "data_classes", "dora_register_id",
                     "assessment_ticket", "next_review", "exit_plan"]


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    message: str
    refs: list = field(default_factory=list)


def norm(pkg: str) -> str:
    return re.sub(r"[-_.]+", "-", pkg).lower()


def host_ok(host: str, patterns) -> bool:
    return any(fnmatch.fnmatch(host.lower(), p.lower()) for p in patterns)


class Register:
    def __init__(self, data: dict):
        self.vendors = {v["id"]: v for v in data["vendors"]}
        self.packages, self.imports = set(), set()
        for lib in data.get("libraries", []):
            self.packages.add(norm(lib["package"]))
            self.imports.add(lib["import"])
        for v in self.vendors.values():
            if v.get("sdk"):
                self.packages.add(norm(v["sdk"]["package"]))
                self.imports.add(v["sdk"]["import"])

    def vendor_for_host(self, host: str):
        return next((v for v in self.vendors.values() if host_ok(host, v.get("hosts", []))), None)


class Guard:
    def __init__(self, reg: Register, egress_module: str, local_pkgs: set[str]):
        self.reg, self.egress_module, self.local_pkgs = reg, egress_module, local_pkgs
        self.findings: list[Finding] = []

    def add(self, rule, file, line, msg, severity="error"):
        self.findings.append(Finding(rule, severity, file, line, msg, RULES[rule][1]))

    # ---------- Python source ----------
    def scan_python(self, path: Path, rel: str):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
        is_egress = rel == self.egress_module
        http_alias: dict[str, str] = {}

        def func_of(node):
            while node in parents:
                node = parents[node]
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return node
            return None

        # 1) imports
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [(a.name, a.asname or a.name.split(".")[0]) for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [(node.module, None)]
            for mod, alias in names:
                top = mod.split(".")[0]
                if any(mod == m or mod.startswith(m + ".") for m in HTTP_MODULES):
                    if alias:
                        http_alias[alias] = mod
                    if not is_egress:
                        self.add("VG-003", rel, node.lineno,
                                 f"imports '{mod}' directly; outbound calls must go through payment_service.egress")
                elif top in sys.stdlib_module_names or top in self.local_pkgs:
                    continue
                elif top not in self.reg.imports:
                    self.add("VG-002", rel, node.lineno,
                             f"imports '{top}' which is not an approved library or vendor SDK")

        # 2) @third_party declarations
        decls: dict = {}
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            for d in fn.decorator_list:
                if isinstance(d, ast.Call) and getattr(d.func, "id", getattr(d.func, "attr", "")) == "third_party":
                    vid = d.args[0].value if d.args and isinstance(d.args[0], ast.Constant) else None
                    classes = set()
                    if len(d.args) > 1 and isinstance(d.args[1], (ast.List, ast.Tuple)):
                        classes = {e.value for e in d.args[1].elts if isinstance(e, ast.Constant)}
                    decls[fn] = (vid, classes)
                    vendor = self.reg.vendors.get(vid)
                    if vendor is None:
                        self.add("VG-001", rel, d.lineno, f"declared vendor '{vid}' is not in the register")
                    else:
                        extra = classes - set(vendor["data_classes"])
                        if extra:
                            self.add("VG-005", rel, d.lineno,
                                     f"{vid} ({vendor['name']}) is not approved for data classes {sorted(extra)}")

        # 3) literal endpoints
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if isinstance(parents.get(node), ast.Expr):
                    continue  # docstring
                m = URL_RE.match(node.value)
                if not m:
                    continue
                host = m.group(1).lower()
                known = self.reg.vendor_for_host(host)
                decl = decls.get(func_of(node))
                if known is None:
                    self.add("VG-001", rel, node.lineno, f"host '{host}' is not in the approved-vendor register")
                if decl is None:
                    self.add("VG-004", rel, node.lineno,
                             f"endpoint '{host}' used outside a @third_party-declared function")
                elif known and known["id"] != decl[0]:
                    self.add("VG-001", rel, node.lineno,
                             f"host '{host}' belongs to {known['id']} but function declares {decl[0]}")

        # 4) dynamic endpoints on direct HTTP clients
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id in http_alias
                    and node.args and not isinstance(node.args[0], ast.Constant)):
                self.add("VG-003", rel, node.lineno,
                         "dynamic (non-literal) endpoint passed to an HTTP client; cannot be verified statically")

    # ---------- manifests ----------
    def scan_requirements(self, path: Path, rel: str):
        for i, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            s = raw.split("#")[0].strip()
            if not s or s.startswith("-"):
                continue
            name = norm(re.split(r"[<>=!~\[; ]", s, maxsplit=1)[0])
            if name not in self.reg.packages:
                self.add("VG-002", rel, i, f"dependency '{name}' is not an approved library or vendor SDK")

    # ---------- register hygiene ----------
    def check_register(self, repo_root: Path, as_of: dt.date, reg_rel: str):
        for v in self.reg.vendors.values():
            if v.get("type") != "external":
                continue
            missing = [k for k in REQUIRED_EXTERNAL if not v.get(k)]
            if missing:
                self.add("VG-006", reg_rel, 0, f"{v['id']} missing required fields: {missing}")
            nr = v.get("next_review")
            if isinstance(nr, dt.date) and nr < as_of:
                self.add("VG-006", reg_rel, 0, f"{v['id']} due diligence review expired on {nr} (as of {as_of})")
            if v.get("criticality") == "critical_or_important" and v.get("exit_plan"):
                if not (repo_root / v["exit_plan"]).exists():
                    self.add("VG-006", reg_rel, 0, f"{v['id']} exit plan file '{v['exit_plan']}' does not exist")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--register", default="governance/approved-vendors.yaml")
    ap.add_argument("--root", action="append", default=[], help="source root(s) to scan")
    ap.add_argument("--requirements", action="append", default=[])
    ap.add_argument("--egress-module", default="payment_service/egress.py")
    ap.add_argument("--as-of", default=dt.date.today().isoformat())
    ap.add_argument("--json", help="write JSON report (audit evidence)")
    a = ap.parse_args(argv)

    cwd = Path.cwd()
    reg = Register(yaml.safe_load(Path(a.register).read_text(encoding="utf-8")))
    roots = [Path(r) for r in (a.root or ["payment_service"])]
    local = {r.name for r in roots if (r / "__init__.py").exists()}
    g = Guard(reg, a.egress_module, local)

    def rel(p: Path) -> str:
        try:
            return p.resolve().relative_to(cwd.resolve()).as_posix()
        except ValueError:
            return p.as_posix()

    for r in roots:
        for f in sorted(r.rglob("*.py")):
            g.scan_python(f, rel(f).replace("demo/bad_pr/", ""))  # overlay maps onto real path
    for req in a.requirements or ["requirements.txt"]:
        g.scan_requirements(Path(req), rel(Path(req)))
    g.check_register(cwd, dt.date.fromisoformat(a.as_of), a.register)

    errors = [f for f in g.findings if f.severity == "error"]
    for f in g.findings:
        print(f"[{f.severity.upper()}] {f.rule} {f.file}:{f.line}  {f.message}")
        print(f"        {RULES[f.rule][0]} | refs: {'; '.join(f.refs)}")
    print(f"\nvendor_guard: {len(errors)} error(s), {len(g.findings) - len(errors)} warning(s)")
    if a.json:
        Path(a.json).write_text(json.dumps([asdict(f) for f in g.findings], indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
