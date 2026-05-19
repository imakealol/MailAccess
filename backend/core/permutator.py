from __future__ import annotations

_DEFAULT_DOMAINS = [
    "gmail.com",
    "outlook.com",
    "yahoo.com",
    "icloud.com",
    "protonmail.com",
]
_MAX_PERMUTATIONS = 60

# Ordered from highest real-world prevalence to lowest.
# Placeholders: {f}=first, {l}=last, {fi}=first initial, {li}=last initial
_BASE_PATTERNS = [
    "{f}.{l}",
    "{f}{l}",
    "{fi}{l}",
    "{f}_{l}",
    "{l}{fi}",
    "{f}.{li}",
    "{fi}.{l}",
    "{l}.{f}",
    "{l}_{f}",
    "{l}{f}",
    "{f}-{l}",
    "{fi}_{l}",
    "{f}{li}",
    "{fi}.{li}",
    "{l}.{fi}",
    "{fi}-{l}",
    "{f}",
    "{l}",
]

_YEAR_PATTERNS = [
    "{f}.{l}{y}",
    "{f}{l}{y}",
    "{fi}{l}{y}",
    "{f}{y}",
]


def generate_permutations(
    first_name: str,
    last_name: str,
    year: str | int | None = None,
    domain: str | None = None,
) -> list[str]:
    """
    Return deduplicated email permutations for (first_name, last_name),
    capped at _MAX_PERMUTATIONS (60).

    If domain is None, generates against all five default providers.
    If year is provided, appends year-suffixed patterns after the base set.
    """
    f = first_name.lower().strip()
    l = last_name.lower().strip()
    if not f or not l:
        return []

    fi = f[0]
    li = l[0]
    y = str(year) if year is not None else None

    patterns = list(_BASE_PATTERNS)
    if y:
        patterns.extend(_YEAR_PATTERNS)

    local_parts: list[str] = []
    seen_locals: set[str] = set()
    for pat in patterns:
        local = (
            pat.replace("{f}", f)
               .replace("{l}", l)
               .replace("{fi}", fi)
               .replace("{li}", li)
               .replace("{y}", y or "")
        )
        if local not in seen_locals:
            seen_locals.add(local)
            local_parts.append(local)

    domains = [domain] if domain else _DEFAULT_DOMAINS

    results: list[str] = []
    seen: set[str] = set()
    for local in local_parts:
        for d in domains:
            email = f"{local}@{d}"
            if email not in seen:
                seen.add(email)
                results.append(email)
                if len(results) >= _MAX_PERMUTATIONS:
                    return results

    return results
