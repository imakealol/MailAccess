from __future__ import annotations

from collections import Counter
from typing import Any

import httpx

from ..config import settings
from ..core.http_client import build_client
from ..core.rate_limiter import rate_limiter
from .base import BaseModule, ModuleResult, ModuleStatus

_GITHUB_API = "https://api.github.com"
_REPO_FETCH_LIMIT = 5
_UNKNOWN_LANGUAGE = "Unknown"


def _truncate(value: str, limit: int) -> str:
    value = " ".join(value.split())
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def _is_rate_limited(response: httpx.Response) -> bool:
    if response.status_code == 429:
        return True
    return response.status_code == 403 and response.headers.get("x-ratelimit-remaining") == "0"


class GitHubCommitsModule(BaseModule):
    name = "github_commits"
    description = (
        "Search GitHub commit history for direct author-email matches and related "
        "GitHub users."
    )
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        token = settings.github_token
        rate_limiter.set_delay("api.github.com", 2.0 if token else 6.0)

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        partial = False

        try:
            async with build_client(base_url=_GITHUB_API, timeout=10.0) as client:
                commit_findings, commit_errors, rate_limited = await self._search_commits(
                    client, headers, email
                )
                findings.extend(commit_findings)
                errors.extend(commit_errors)
                partial = partial or rate_limited
                await self._enrich_commit_repos(client, headers, commit_findings)

                user_finding, user_errors, rate_limited = await self._search_user(
                    client, headers, email
                )
                if user_finding:
                    findings.append(user_finding)
                errors.extend(user_errors)
                partial = partial or rate_limited
        except httpx.TimeoutException:
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=["GitHub request timed out"])
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            # True connection-level failure — network unreachable / DNS failure
            return ModuleResult(status=ModuleStatus.FAILED, errors=[f"GitHub unreachable: {exc}"])
        except Exception as exc:
            # Unexpected error; degrade to PARTIAL rather than FAILED
            return ModuleResult(status=ModuleStatus.PARTIAL, errors=[f"GitHub unexpected error: {exc}"])

        commit_findings = [f for f in findings if f.get("platform") == "github_commit"]
        commit_dates = [
            str(f.get("metadata", {}).get("commit_date"))
            for f in commit_findings
            if f.get("metadata", {}).get("commit_date")
        ]
        repos = [
            str(f.get("metadata", {}).get("repo"))
            for f in commit_findings
            if f.get("metadata", {}).get("repo")
        ]
        names = [
            str(f.get("metadata", {}).get("author_name"))
            for f in commit_findings
            if f.get("metadata", {}).get("author_name")
        ]
        languages: list[str] = []
        repos_counted_for_language: set[str] = set()
        for finding in commit_findings:
            metadata = finding.get("metadata", {})
            repo = str(metadata.get("repo") or "")
            language = str(metadata.get("repo_language") or "")
            if (
                repo
                and language
                and language != _UNKNOWN_LANGUAGE
                and repo not in repos_counted_for_language
            ):
                languages.append(language)
                repos_counted_for_language.add(repo)

        # Determine final status:
        # - PARTIAL if rate-limited, auth-blocked, or we have some data alongside errors
        # - FAILED only for genuine connection-level failures (caught above and returned early)
        # - SKIPPED is set upstream; we never set it here
        status = ModuleStatus.SUCCESS
        if partial:
            # partial=True is set when auth/rate-limit blocked commit search —
            # user search may still have run; this is never a FAILED
            status = ModuleStatus.PARTIAL
        elif errors and findings:
            status = ModuleStatus.PARTIAL
        elif errors and not findings:
            # errors with no findings = auth-blocked or empty result, not a crash
            status = ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "commits_found": len(commit_findings),
                "repos_contributed_to": sorted(set(repos)),
                "real_name_from_git": Counter(names).most_common(1)[0][0] if names else None,
                "earliest_commit": min(commit_dates) if commit_dates else "",
                "latest_commit": max(commit_dates) if commit_dates else "",
                "primary_language": Counter(languages).most_common(1)[0][0] if languages else "",
                "github_user_found": any(f.get("platform") == "github_user" for f in findings),
            },
            errors=errors,
        )

    async def _search_commits(
        self, client: httpx.AsyncClient, headers: dict[str, str], email: str
    ) -> tuple[list[dict[str, Any]], list[str], bool]:
        try:
            response = await client.get(
                "/search/commits",
                params={
                    "q": f"author-email:{email}",
                    "sort": "author-date",
                    "order": "desc",
                    "per_page": "10",
                },
                headers=headers,
            )
        except httpx.TimeoutException:
            return [], ["GitHub commit search timed out"], False
        except Exception as exc:
            return [], [f"GitHub commit search failed: {exc}"], False

        if _is_rate_limited(response):
            return [], ["GitHub API rate limit reached during commit search"], True
        if response.status_code in (403, 422) and "Authorization" not in headers:
            return [], ["GitHub commit search requires GITHUB_TOKEN. Set via: mailaccess keys set GITHUB_TOKEN your-token-here"], True
        if response.status_code != 200:
            return [], [f"GitHub commit search returned {response.status_code}"], False

        try:
            items = response.json().get("items") or []
        except Exception:
            return [], ["GitHub commit search returned unparseable JSON"], False

        findings: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            commit = item.get("commit") if isinstance(item.get("commit"), dict) else {}
            author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
            repository = item.get("repository") if isinstance(item.get("repository"), dict) else {}
            repo_name = str(repository.get("full_name") or "")
            repo_url = str(repository.get("html_url") or "")
            sha = str(item.get("sha") or "")
            findings.append(
                {
                    "platform": "github_commit",
                    "profile_url": str(item.get("html_url") or ""),
                    "confidence": "high",
                    "metadata": {
                        "repo": repo_name,
                        "repo_url": repo_url,
                        "commit_sha": sha[:7],
                        "commit_message": _truncate(str(commit.get("message") or ""), 100),
                        "author_name": str(author.get("name") or ""),
                        "commit_date": str(author.get("date") or ""),
                        "repo_description": None,
                        "repo_stars": 0,
                        "repo_language": _UNKNOWN_LANGUAGE,
                    },
                }
            )
        return findings, [], False

    async def _enrich_commit_repos(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        findings: list[dict[str, Any]],
    ) -> None:
        repo_names = []
        for finding in findings:
            repo_name = str(finding.get("metadata", {}).get("repo") or "")
            if repo_name and repo_name not in repo_names:
                repo_names.append(repo_name)

        repo_cache: dict[str, dict[str, Any]] = {}
        for repo_name in repo_names[:_REPO_FETCH_LIMIT]:
            repo_cache[repo_name] = await self._fetch_repo_detail(client, headers, repo_name)

        for finding in findings:
            metadata = finding.get("metadata")
            if not isinstance(metadata, dict):
                continue
            repo_detail = repo_cache.get(str(metadata.get("repo") or ""))
            if not repo_detail:
                continue
            metadata["repo_description"] = repo_detail.get("description")
            metadata["repo_stars"] = int(repo_detail.get("stargazers_count") or 0)
            metadata["repo_language"] = repo_detail.get("language") or _UNKNOWN_LANGUAGE

    async def _fetch_repo_detail(
        self, client: httpx.AsyncClient, headers: dict[str, str], full_name: str
    ) -> dict[str, Any]:
        try:
            response = await client.get(f"/repos/{full_name}", headers=headers, timeout=5.0)
        except (httpx.TimeoutException, httpx.HTTPError):
            return {}
        except Exception:
            return {}

        if response.status_code != 200:
            return {}
        try:
            data = response.json()
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    async def _search_user(
        self, client: httpx.AsyncClient, headers: dict[str, str], email: str
    ) -> tuple[dict[str, Any] | None, list[str], bool]:
        try:
            response = await client.get(
                "/search/users",
                params={"q": f"{email} in:email"},
                headers=headers,
            )
        except httpx.TimeoutException:
            return None, ["GitHub user search timed out"], False
        except Exception as exc:
            return None, [f"GitHub user search failed: {exc}"], False

        if _is_rate_limited(response):
            return None, ["GitHub API rate limit reached during user search"], True
        if response.status_code != 200:
            return None, [f"GitHub user search returned {response.status_code}"], False

        try:
            items = response.json().get("items") or []
        except Exception:
            return None, ["GitHub user search returned unparseable JSON"], False
        if not items or not isinstance(items[0], dict):
            return None, [], False

        user = dict(items[0])
        detail_url = user.get("url")
        if isinstance(detail_url, str) and detail_url:
            detail, detail_error, rate_limited = await self._fetch_user_detail(
                client, headers, detail_url
            )
            if detail:
                user.update(detail)
            if detail_error:
                return self._user_finding(user), [detail_error], rate_limited
            if rate_limited:
                return self._user_finding(user), [], True

        return self._user_finding(user), [], False

    async def _fetch_user_detail(
        self, client: httpx.AsyncClient, headers: dict[str, str], url: str
    ) -> tuple[dict[str, Any] | None, str | None, bool]:
        try:
            response = await client.get(url, headers=headers)
        except httpx.TimeoutException:
            return None, "GitHub user detail lookup timed out", False
        except Exception as exc:
            return None, f"GitHub user detail lookup failed: {exc}", False

        if _is_rate_limited(response):
            return None, None, True
        if response.status_code != 200:
            return None, f"GitHub user detail lookup returned {response.status_code}", False
        try:
            return response.json(), None, False
        except Exception:
            return None, "GitHub user detail lookup returned unparseable JSON", False

    def _user_finding(self, user: dict[str, Any]) -> dict[str, Any]:
        return {
            "platform": "github_user",
            "profile_url": str(user.get("html_url") or ""),
            "confidence": "high",
            "metadata": {
                "login": user.get("login"),
                "name": user.get("name"),
                "bio": user.get("bio"),
                "public_repos": int(user.get("public_repos") or 0),
                "followers": int(user.get("followers") or 0),
                "avatar_url": user.get("avatar_url"),
            },
        }
