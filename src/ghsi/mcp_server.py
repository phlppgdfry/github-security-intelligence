"""Local, read-only MCP server for bug bounty work (`ghsi-mcp`, stdio).

Tools: scope guard, live HackerOne scope, own reports, GitHub program rules, report template + lint.
There is deliberately no tool that submits, comments on or changes anything on HackerOne.
"""
from __future__ import annotations

import dataclasses

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import bounty_github as rules
from . import h1

mcp = MCPServer("ghsi-bounty")


def _scope(program: str, refresh: bool = False):
    try:
        return h1.load_scope(program, refresh=refresh)
    except h1.H1Error as e:
        raise ToolError(str(e)) from e


@mcp.tool()
def check_scope(targets: list[str], program: str = rules.PROGRAM_HANDLE) -> list[dict]:
    """Before sending ANY request to a host, check it here. status 'in-scope' is the only green light;
    'unknown' and 'out-of-scope' mean do not test. Accepts URLs, hostnames or product names."""
    entries, src = _scope(program)
    out = []
    for t in targets:
        v = h1.check_target(t, entries)
        out.append({"target": t, "status": v.status, "reason": v.reason, "scope_source": src,
                    "instruction": (v.entry.instruction if v.entry else None)})
    return out


@mcp.tool()
def program_scope(program: str = rules.PROGRAM_HANDLE, bounty_only: bool = False, refresh: bool = False) -> dict:
    """Structured scope of a HackerOne program (live via the Hacker API when logged in, cached 6 h)."""
    entries, src = _scope(program, refresh)
    if bounty_only:
        entries = [e for e in entries if e.eligible_for_bounty and e.eligible_for_submission]
    return {"source": src, "count": len(entries), "entries": [dataclasses.asdict(e) for e in entries]}


@mcp.tool()
def my_reports(limit: int = 50) -> list[dict]:
    """The researcher's own HackerOne reports: id, state, title, created date, link."""
    try:
        reports = h1.Client().my_reports(limit=limit)
    except h1.H1Error as e:
        raise ToolError(str(e)) from e
    return [{"id": r.get("id"), "url": f"https://hackerone.com/reports/{r.get('id')}",
             "state": (r.get("attributes") or {}).get("state"), "title": (r.get("attributes") or {}).get("title"),
             "created_at": (r.get("attributes") or {}).get("created_at")} for r in reports]


@mcp.tool()
def auth_status() -> dict:
    """Whether a HackerOne API token is configured (never returns the token)."""
    try:
        creds = h1.load_credentials()
    except h1.NoCredentials as e:
        return {"authenticated": False, "hint": str(e)}
    try:
        h1.Client(creds).program(rules.PROGRAM_HANDLE)
    except h1.H1Error as e:
        return {"authenticated": False, "identifier": creds.identifier, "error": str(e)}
    return {"authenticated": True, "identifier": creds.identifier}


@mcp.tool()
def github_bounty_rules() -> dict:
    """GitHub bug bounty rules as checklists, the ineligible list, rewards and contacts (with source URLs)."""
    return {"read_on": rules.READ_ON, "program": rules.PROGRAM_URL, "sources": rules.SOURCES,
            "before_you_test": rules.BEFORE_YOU_TEST, "when_you_report": rules.WHEN_YOU_REPORT,
            "ineligible": rules.INELIGIBLE_HIGHLIGHTS, "rewards": rules.REWARDS, "contacts": rules.CONTACTS,
            "in_scope_domains": rules.IN_SCOPE_DOMAINS, "in_scope_products": rules.IN_SCOPE_PRODUCTS}


@mcp.tool()
def report_template(title: str, asset: str, program: str = rules.PROGRAM_HANDLE) -> str:
    """A report skeleton in the shape GitHub asks for, with the scope verdict for the asset filled in."""
    entries, _ = _scope(program)
    v = h1.check_target(asset, entries)
    return h1.REPORT_TEMPLATE.format(title=title, asset=asset, verdict=f"{v.status} — {v.reason}")


@mcp.tool()
def lint_report(markdown: str) -> dict:
    """Check a draft: required sections, written steps, leaked tokens/cookies, PII, off-site media links."""
    issues = h1.lint_report(markdown)
    return {"ready": not any(lvl == "error" for lvl, _ in issues),
            "issues": [{"level": lvl, "message": m} for lvl, m in issues],
            "note": "Submitting is a human action on hackerone.com; this server cannot submit."}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
