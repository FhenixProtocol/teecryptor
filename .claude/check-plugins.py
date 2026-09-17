#!/usr/bin/env python3
"""Warn when the shared Fhenix plugins are not installed for this repo.

`extraKnownMarketplaces` registers the marketplace on folder-trust, but Claude Code
never installs plugins on its own -- `enabledPlugins` only enables ones that are
already installed. Without this check a teammate silently gets none of the shared
skills, agents, or engineering defaults, and nothing tells them why.

This only reports. It installs nothing.
"""
import json
import os
import sys

MARKETPLACE = "fhenix"
REQUIRED = ("fhenix-standards", "fhenix-workflow", "fhenix-ops")
INSTALLED_PLUGINS = os.path.expanduser("~/.claude/plugins/installed_plugins.json")


def active_plugins(project_dir):
    """Plugin ids installed either machine-wide or for this specific repo."""
    try:
        with open(INSTALLED_PLUGINS, encoding="utf-8") as fh:
            plugins = json.load(fh).get("plugins", {})
    except (OSError, ValueError):
        return set()

    return {
        name
        for name, installs in plugins.items()
        if any(
            install.get("scope") == "user"
            or install.get("projectPath") == project_dir
            for install in installs
        )
    }


def main():
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    installed = active_plugins(project_dir)
    missing = [p for p in REQUIRED if f"{p}@{MARKETPLACE}" not in installed]
    if not missing:
        return

    # Multi-argument install silently ignores everything after the first plugin.
    commands = "\n".join(
        f"    claude plugin install {name}@{MARKETPLACE} --scope project"
        for name in missing
    )
    message = (
        "SETUP NEEDED: the shared Fhenix Claude Code plugins are not installed in "
        "this repo, so the team skills, agents, and engineering defaults are NOT "
        "loaded in this session.\n\n"
        f"Missing: {', '.join(missing)}\n\n"
        "Tell the user to run these once, then restart Claude Code:\n\n"
        f"{commands}\n"
    )
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": message,
            }
        },
        sys.stdout,
    )


if __name__ == "__main__":
    main()
