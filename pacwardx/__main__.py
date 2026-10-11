"""Command line entry point. Run `pacwardx --help` for the commands."""
import argparse
import json
import os
import sys

# Exit codes for `pacwardx scan`, so scripts and cron jobs can react to the result.
EXIT_BY_WORST = {None: 0, "ok": 0, "info": 0, "low": 1, "medium": 2, "high": 3}


def _backend():
    """The running background service if there is one, else run in this process."""
    from .client import DaemonClient, LocalBackend
    d = DaemonClient()
    return d if d.available() else LocalBackend()


def _cmd_scan(args) -> int:
    from . import __version__, engine
    from .findings import CATEGORIES, CATEGORY_LABELS, SEV_RANK, score, worst
    cats = args.category or list(engine.QUICK)
    unknown = [c for c in cats if c not in CATEGORIES]
    if unknown:
        print(f"Unknown category: {', '.join(unknown)}. Choose from: {', '.join(CATEGORIES)}", file=sys.stderr)
        return 4
    state = engine.run_categories(cats)
    findings = sorted(engine.all_findings(state, include_ignored=True), key=lambda f: -SEV_RANK[f["severity"]])
    findings = [f for f in findings if f["category"] in cats]
    # Results for just the categories scanned now, not older results of the others.
    counted = [f for f in findings if not f.get("ignored")]
    w = worst(counted) if counted else None
    counts = {sev: sum(f["severity"] == sev for f in counted) for sev in SEV_RANK}
    if args.json:
        print(json.dumps({"version": __version__, "categories": cats, "worst": w, "score": score(counted),
                          "counts": counts, "last_run": state.get("last_run"), "findings": findings}, indent=2))
    else:
        print(f"PacWardX: overall {w or 'ok'}, score {score(counted)}/100")
        for f in findings:
            tag = "ignored" if f.get("ignored") else f["severity"]
            print(f"[{tag:7}] {CATEGORY_LABELS[f['category']]:15} {f['title']}  ({f['id']})")
            if f["fix"] and f["severity"] not in ("ok", "info") and not f.get("ignored"):
                print(f"          fix: {f['fix']}")
    return EXIT_BY_WORST.get(w, 0)


def _cmd_accept(_args) -> int:
    r = _backend().call({"cmd": "accept_changes"}, timeout=120)
    print("Baseline updated." if r.get("ok") else f"Failed: {r.get('error')}")
    return 0 if r.get("ok") else 4


def _cmd_ignore(args) -> int:
    r = _backend().call({"cmd": "ignore", "id": args.id, "note": " ".join(args.note)})
    print(f"Ignoring {args.id}." if r.get("ok") else f"Failed: {r.get('error')}")
    return 0 if r.get("ok") else 4


def _cmd_unignore(args) -> int:
    r = _backend().call({"cmd": "unignore", "id": args.id})
    print(f"No longer ignoring {args.id}." if r.get("ok") else f"Failed: {r.get('error')}")
    return 0 if r.get("ok") else 4


def _cmd_ignored(_args) -> int:
    ignored = _backend().call({"cmd": "config"}).get("config", {}).get("ignored") or {}
    if not ignored:
        print("Nothing is ignored.")
    for fid, info in sorted(ignored.items(), key=lambda kv: kv[1].get("ts", "")):
        note = f"  ({info['note']})" if info.get("note") else ""
        print(f"{fid}  {info.get('title', '')}{note}")
    return 0


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse exits 2 on a usage error, which `pacwardx scan` uses for "medium". Use the error code.
        self.print_usage(sys.stderr)
        self.exit(4, f"{self.prog}: error: {message}\n")


def _parser() -> argparse.ArgumentParser:
    p = _Parser(prog="pacwardx", description="Security monitor for Arch Linux. "
                                "With no command, opens the window.")
    from . import __version__
    p.add_argument("--version", action="version", version=f"pacwardx {__version__}")
    p.add_argument("--tray", action="store_true", help="start the window minimised to the tray")
    sub = p.add_subparsers(dest="command", metavar="command")
    sub.add_parser("daemon", help="run the background service (used by systemd)")
    sc = sub.add_parser("scan", help="run the checks now and print the results",
                        description="Exit code: 0 nothing to fix, 1 low, 2 medium, 3 high, 4 error.")
    sc.add_argument("--json", action="store_true", help="print machine-readable JSON")
    sc.add_argument("--category", action="append", metavar="NAME",
                    help="only this category (repeatable): packages, network, system, files, changes, opsec")
    rp = sub.add_parser("report", help="print the last results as Markdown, ready to share")
    rp.add_argument("--full", action="store_true", help="include every line of every finding")
    sub.add_parser("accept", help="accept everything under Changes as the new normal")
    ig = sub.add_parser("ignore", help="ignore a finding by its id (shown by `pacwardx scan`)")
    ig.add_argument("id")
    ig.add_argument("note", nargs="*", help="optional note, e.g. why it's fine")
    un = sub.add_parser("unignore", help="stop ignoring a finding")
    un.add_argument("id")
    sub.add_parser("ignored", help="list ignored findings")
    return p


def main(argv: list[str] | None = None) -> int:
    # Everything PacWardX writes (findings, baselines, settings, the socket) is for this user only.
    os.umask(0o077)
    from . import config
    config.ensure_dirs()
    args = _parser().parse_args(argv)
    if args.command == "daemon":
        from .daemon import main as daemon_main
        daemon_main()
        return 0
    if args.command == "report":
        from .report import main as report_main
        report_main(["--full"] if args.full else [])
        return 0
    handlers = {"scan": _cmd_scan, "accept": _cmd_accept, "ignore": _cmd_ignore,
                "unignore": _cmd_unignore, "ignored": _cmd_ignored}
    if args.command in handlers:
        return handlers[args.command](args)
    from .ui.app import main as ui_main
    ui_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
