"""
Interactive menu for Semantic Recon Engine.
Triggered when no --target/--domain are provided, or with --interactive flag.
"""

import os
import sys

try:
    import questionary
    from questionary import Style
    HAS_QUESTIONARY = True
except ImportError:
    HAS_QUESTIONARY = False


STYLE = Style([
    ("qmark",       "fg:#38bdf8 bold"),
    ("question",    "bold"),
    ("answer",      "fg:#38bdf8 bold"),
    ("pointer",     "fg:#38bdf8 bold"),
    ("highlighted", "fg:#38bdf8 bold"),
    ("selected",    "fg:#22c55e"),
    ("separator",   "fg:#475569"),
    ("instruction", "fg:#64748b"),
    ("text",        ""),
    ("disabled",    "fg:#64748b italic"),
])

SOURCES = [
    {"name": "GitHub           — repos, commits, code, issues",         "value": "github",          "checked": True},
    {"name": "Google Dorks     — tech hints, job postings, exposed files","value": "google",         "checked": True},
    {"name": "Wayback Machine  — historical snapshots, deleted pages",   "value": "wayback",         "checked": True},
    {"name": "LinkedIn         — employee roles, job postings",          "value": "linkedin",        "checked": True},
    {"name": "DNS / crt.sh     — subdomains, certificate transparency",  "value": "dns",             "checked": True},
    {"name": "GitHub Secrets   — leaked keys, tokens in repos",         "value": "github_secrets",  "checked": True},
    {"name": "Stack Overflow   — internal tool references by employees", "value": "stackoverflow",   "checked": True},
    {"name": "Paste / Gist     — leaked configs on paste sites",        "value": "paste",           "checked": True},
    {"name": "HaveIBeenPwned   — email breach lookup",                  "value": "hibp",            "checked": True},
    {"name": "WHOIS            — registration history, DNS changes",    "value": "whois",           "checked": True},
    {"name": "Shodan           — open ports, banners (needs API key)",  "value": "shodan",          "checked": False},
]


def select_sources(args):
    """
    Show only the sources checkbox menu.
    Returns modified args namespace.
    """
    if not HAS_QUESTIONARY:
        print("Install questionary for interactive mode: pip install questionary")
        sys.exit(1)

    print()
    selected = questionary.checkbox(
        "Select sources to use:",
        choices=SOURCES,
        style=STYLE,
        instruction="(Space to toggle, Enter to confirm)"
    ).ask()
    if selected is None:
        sys.exit(0)
    args.sources = selected
    return args


def prompt(args):
    """
    Fill in missing args interactively.
    Returns modified args namespace.
    """
    if not HAS_QUESTIONARY:
        print("Install questionary for interactive mode: pip install questionary")
        sys.exit(1)

    print()

    # Target
    if not args.target:
        args.target = questionary.text(
            "Target company name:",
            style=STYLE
        ).ask()
        if not args.target:
            sys.exit(0)

    # Domain
    if not args.domain:
        args.domain = questionary.text(
            "Target domain (e.g. tesla.com):",
            style=STYLE
        ).ask()
        if not args.domain:
            sys.exit(0)

    # Sources
    if not args.sources:
        selected = questionary.checkbox(
            "Select sources to use:",
            choices=SOURCES,
            style=STYLE,
            instruction="(Space to toggle, Enter to confirm)"
        ).ask()
        if selected is None:
            sys.exit(0)
        args.sources = selected

    # LLM
    if not args.llm:
        args.llm = questionary.select(
            "LLM backend:",
            choices=[
                {"name": "Anthropic Claude (requires API key)", "value": "anthropic"},
                {"name": "Ollama — local, free",                "value": "ollama"},
            ],
            style=STYLE
        ).ask()

    if args.llm == "anthropic" and not args.anthropic_key and not os.environ.get("ANTHROPIC_API_KEY"):
        key = questionary.password(
            "Anthropic API key (or press Enter to use ANTHROPIC_API_KEY env var):",
            style=STYLE
        ).ask()
        if key:
            args.anthropic_key = key

    if args.llm == "ollama" and not args.ollama_model:
        args.ollama_model = questionary.text(
            "Ollama model name:",
            default="llama3",
            style=STYLE
        ).ask()

    # Output
    if not args.html:
        save_html = questionary.confirm(
            "Save interactive HTML report?",
            default=True,
            style=STYLE
        ).ask()
        if save_html:
            args.html = questionary.text(
                "HTML output path:",
                default=f"report_{args.domain}.html",
                style=STYLE
            ).ask()

    # Optional tokens
    show_advanced = questionary.confirm(
        "Configure optional API keys (GitHub token, Shodan, HIBP, SecurityTrails)?",
        default=False,
        style=STYLE
    ).ask()

    if show_advanced:
        if not args.github_token and not os.environ.get("GITHUB_TOKEN"):
            token = questionary.password(
                "GitHub token (Enter to skip):",
                style=STYLE
            ).ask()
            if token:
                args.github_token = token

        if "shodan" in (args.sources or []) and not args.shodan_key and not os.environ.get("SHODAN_API_KEY"):
            key = questionary.password(
                "Shodan API key (Enter to skip):",
                style=STYLE
            ).ask()
            if key:
                args.shodan_key = key

        if "hibp" in (args.sources or []) and not args.hibp_key and not os.environ.get("HIBP_API_KEY"):
            key = questionary.password(
                "HaveIBeenPwned API key (Enter to skip):",
                style=STYLE
            ).ask()
            if key:
                args.hibp_key = key

        if "whois" in (args.sources or []) and not args.securitytrails_key and not os.environ.get("SECURITYTRAILS_API_KEY"):
            key = questionary.password(
                "SecurityTrails API key for WHOIS history (Enter to skip):",
                style=STYLE
            ).ask()
            if key:
                args.securitytrails_key = key

    print()
    return args
