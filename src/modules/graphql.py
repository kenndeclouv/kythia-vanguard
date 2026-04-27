"""graphql.py – GraphQL Schema Dumper module

Provides `run_graphql` which sends the standard introspection query to a
GraphQL endpoint. If the original request had authentication cookies/headers,
they are reused via the passed ``session`` (the global ``SESSION`` already
contains any captured cookies from the spider). Findings are appended to ``ScanResult.graphql_findings``.
"""

from __future__ import annotations

import json
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from src.config import console, C, SESSION, rate_limiter, TIMEOUT
from src.models import ScanResult

_INTROSPECTION_QUERY = {
    "query": """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
                directives {
                    name
                    description
                    locations
                    args {
                        ...InputValue
                    }
                }
            }
        }
        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }
        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }
        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                        }
                    }
                }
            }
        }
    """
}


def run_graphql(target_url: str, result: ScanResult, progress, task) -> None:
    """Send an introspection query to ``target_url`` and save to ``result.graphql_findings``."""
    progress.update(
        task, description=f"[cyan]GraphQL:[/cyan] Checking {target_url}…", completed=10
    )
    rate_limiter.wait()
    try:
        resp = SESSION.post(target_url, json=_INTROSPECTION_QUERY, timeout=TIMEOUT)
    except Exception as exc:
        result.graphql_findings = {"url": target_url, "error": str(exc)}
        progress.update(task, completed=100)
        return

    progress.update(task, completed=40)

    if resp.status_code != 200:
        result.graphql_findings = {
            "url": target_url,
            "status": resp.status_code,
            "error": "non‑200 response",
        }
        progress.update(task, completed=100)
        return

    progress.update(task, completed=60)

    try:
        data = resp.json()
    except json.JSONDecodeError:
        data = None

    schema_info = {"url": target_url, "status": resp.status_code, "schema_json": data}

    progress.update(task, completed=80)

    # Attempt to produce SDL if graphql-core is installed.
    try:
        from graphql import build_client_schema, print_schema

        if data and "data" in data and "__schema" in data["data"]:
            client_schema = build_client_schema(data["data"])
            schema_info["schema_sdl"] = print_schema(client_schema)
    except Exception:
        # Silently ignore – SDL is optional.
        pass

    result.graphql_findings = schema_info
    progress.console.print(
        Panel(
            f"[bold green]GraphQL Schema Extracted![/bold green]\nURL: {target_url}",
            title="GraphQL Schema Dumper",
            border_style="green",
        )
    )
    progress.update(task, description="[cyan]GraphQL:[/cyan] Done", completed=100)


def display_graphql(result: ScanResult) -> None:
    console.print(
        Rule(
            f"[{C['accent']}]🔮  GRAPHQL SCHEMA DUMPER[/{C['accent']}]", style="magenta"
        )
    )
    if not result.graphql_findings:
        console.print("  [dim]No GraphQL schema extracted.[/dim]")
        console.print()
        return

    graphql = result.graphql_findings
    if "error" in graphql:
        console.print(f"  [{C['bad']}]⚠ Error: {escape(graphql['error'])}[/{C['bad']}]")
        console.print()
        return

    panel_content = f"URL: [cyan]{escape(graphql.get('url', ''))}[/cyan]\n"
    panel_content += f"Status: [bold]{graphql.get('status', '')}[/bold]\n"

    if "schema_sdl" in graphql:
        panel_content += "\n[bold green]✓ Full GraphQL SDL extracted![/bold green] (See JSON report for full schema)"
    elif graphql.get("schema_json"):
        panel_content += "\n[bold green]✓ Schema JSON extracted![/bold green] (See JSON report for full schema)"
    else:
        panel_content += "\n[dim]No schema data could be parsed.[/dim]"

    console.print(Panel(Text.from_markup(panel_content), border_style="cyan"))
    console.print()
