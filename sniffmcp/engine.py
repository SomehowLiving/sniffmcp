"""One scan pipeline shared by the CLI, the MCP server, the fleet scanner and tests."""
from __future__ import annotations
from . import osv
from .client import fetch_manifest, transport_of
from .checks import ManifestContext, launch_spec, run_all_checks
from .injection import analyze_descriptions
from .models import Finding, ScanReport, canonical_manifest_hash
from .scoring import score_findings


def target_of(config: dict) -> str:
    if config.get("url"):
        return str(config["url"])
    return " ".join([str(config.get("command", "?"))] + [str(a) for a in config.get("args") or []])[:200]


def report_from_manifest(config: dict, manifest: dict, prior: dict | None = None,
                         llm_hook=None, extra: list[Finding] | None = None) -> ScanReport:
    tools = manifest.get("tools", [])
    transport = transport_of(config)
    ctx = ManifestContext(target_of(config), transport, config, tools,
                          manifest.get("resources"), manifest.get("prompts"),
                          manifest.get("server_info"), manifest.get("instructions"),
                          prior_manifest=prior)
    findings = run_all_checks(ctx) + analyze_descriptions(tools, llm_hook=llm_hook) + list(extra or [])
    for err in manifest.get("errors") or []:
        findings.append(Finding("SM-10", "info", "Partial manifest", err,
                                "Some listings failed; the scan may be incomplete."))
    score, grade = score_findings(findings)
    return ScanReport(target=ctx.target, transport=transport, score=score, grade=grade,
                      findings=findings,
                      manifest_hash=canonical_manifest_hash(tools, manifest.get("resources"),
                                                            manifest.get("prompts")),
                      tool_count=len(tools))


async def scan(config: dict, prior: dict | None = None, launch: bool = True) -> tuple[ScanReport, dict]:
    """Check the package against OSV, then connect and audit.
    Known malware is reported without ever being launched. With launch=False, stdio
    servers are never started (config + OSV checks only), which is what CI wants for a
    config file that came from a pull request.
    Raises client.ConnectError if the server can't be reached."""
    pre: list[Finding] = []
    spec = launch_spec(config) if transport_of(config) == "stdio" else None
    if spec and spec[0] in osv.ECOSYSTEM and not osv.offline():
        pre = await osv.advisories_for_spec(*spec)
        if osv.blocks_launch(pre):
            manifest = {"tools": [], "errors": ["not launched: the package is known malware (OSV)"]}
            return report_from_manifest(config, manifest, prior, extra=pre), manifest
    if not launch and transport_of(config) == "stdio":
        manifest = {"tools": []}
        pre.append(Finding("SM-10", "info", "Not launched (--no-launch): config and package checks only", "",
                           "Run without --no-launch on a trusted machine to inspect the server's tools."))
        return report_from_manifest(config, manifest, prior, extra=pre), manifest
    manifest = await fetch_manifest(config)
    return report_from_manifest(config, manifest, prior, extra=pre), manifest
