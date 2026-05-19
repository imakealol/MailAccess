import asyncio
import hashlib
from typing import Any

import httpx

from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus


class SocialModule(BaseModule):
    name = "social"
    description = "Check social platform account existence (Duolingo, Spotify, Gravatar links, Adobe)."
    requires_key = False

    async def run(self, email: str, **kwargs) -> ModuleResult:
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        # Gravatar data can be passed via kwargs to avoid re-querying
        # if the gravatar module already ran
        gravatar_data = kwargs.get("gravatar_data")

        async with build_client(timeout=10.0, follow_redirects=True) as client:
            tasks = [
                self._check_duolingo(client, email),
                self._check_spotify(client, email),
                self._check_gravatar(client, email, gravatar_data),
                self._check_adobe(client, email),
                self._check_github(client, email),
                self._check_patreon(client, email),
                self._check_snapchat(client, email),
                self._check_skype(client, email),
                self._check_zoom(client, email),
                self._check_dropbox(client, email),
                self._check_apple(client, email),
                self._check_linkedin(client, email),
                self._check_discord(client, email)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, Exception):
                errors.append(f"Social check exception: {str(res)}")
            elif isinstance(res, dict):
                if "error" in res:
                    errors.append(res["error"])
                elif "findings" in res:
                    findings.extend(res["findings"])

        status = ModuleStatus.SUCCESS
        if errors:
            status = ModuleStatus.PARTIAL if findings else ModuleStatus.FAILED

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={},
            errors=errors
        )

    async def _check_duolingo(self, client: httpx.AsyncClient, email: str) -> dict[str, Any]:
        try:
            url = f"https://www.duolingo.com/2017-06-30/users?email={email}"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            resp = await client.get(url, headers=headers)
            
            if resp.status_code == 200:
                data = resp.json()
                users = data.get("users", [])
                findings = []
                for user in users:
                    metadata = {
                        "username": user.get("username"),
                        "display_name": user.get("name"),
                        "avatar_url": user.get("picture"),
                        "streak": user.get("streak"),
                        "joined_date": user.get("creationDate"),
                    }
                    learning = []
                    for course in user.get("courses", []):
                        if course.get("learningLanguage"):
                            learning.append(course.get("learningLanguage"))
                    if learning:
                        metadata["learning_languages"] = learning
                    
                    # Drop None values
                    metadata = {k: v for k, v in metadata.items() if v is not None}
                    
                    findings.append({
                        "platform": "Duolingo",
                        "profile_url": f"https://www.duolingo.com/profile/{user.get('username')}" if user.get("username") else None,
                        "metadata": metadata,
                        "confidence": "high"
                    })
                return {"findings": findings}
            else:
                return {"error": f"Duolingo HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": f"Duolingo failed: {str(e)}"}

    async def _check_spotify(self, client: httpx.AsyncClient, email: str) -> dict[str, Any]:
        try:
            url = "https://www.spotify.com/api/account/forgot-password/"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            data = {"email": email}
            try:
                resp = await client.post(url, headers=headers, data=data)
                try:
                    text = resp.text.lower()
                except Exception:
                    text = resp.content.decode("utf-8", errors="ignore").lower()
            except Exception:
                return {"findings": []}
            if "not found" not in text and "does not exist" not in text and "invalid email" not in text:
                return {"findings": [{
                    "platform": "Spotify",
                    "profile_url": None,
                    "metadata": {"note": "inferred via reset flow"},
                    "confidence": "medium"
                }]}
            return {"findings": []}
        except Exception as e:
            return {"error": f"Spotify failed: {repr(e)}"}

    async def _check_gravatar(self, client: httpx.AsyncClient, email: str, pre_data: dict | None) -> dict[str, Any]:
        try:
            findings = []
            accounts = []
            
            if pre_data and "accounts" in pre_data:
                accounts = pre_data["accounts"]
            else:
                email_clean = email.strip().lower()
                md5_hash = hashlib.md5(email_clean.encode("utf-8")).hexdigest()
                url = f"https://www.gravatar.com/{md5_hash}.json"
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("entry"):
                        entry = data["entry"][0]
                        accounts = entry.get("accounts", [])
                elif resp.status_code != 404:
                    return {"error": f"Gravatar HTTP {resp.status_code}"}
            
            for acc in accounts:
                shortname = acc.get("shortname", "Unknown")
                url = acc.get("url")
                
                # Exclude empty or invalid accounts
                if not url:
                    continue
                    
                findings.append({
                    "platform": f"Gravatar Linked: {shortname.capitalize()}",
                    "profile_url": url,
                    "metadata": acc,
                    "confidence": "high"
                })
                
            return {"findings": findings}
        except Exception as e:
            return {"error": f"Gravatar check failed: {str(e)}"}

    async def _check_adobe(self, client: httpx.AsyncClient, email: str) -> dict[str, Any]:
        try:
            # Equivalent public-facing existence hint endpoint
            url = "https://auth.services.adobe.com/signin/v2/users/accounts"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            data = {"username": email}
            resp = await client.post(url, headers=headers, json=data)
            
            # Usually Adobe returns an array of identities if an account exists
            if resp.status_code == 200:
                try:
                    resp_data = resp.json()
                    if isinstance(resp_data, list) and len(resp_data) > 0:
                        return {"findings": [{
                            "platform": "Adobe",
                            "profile_url": None,
                            "metadata": {"note": "Account exists"},
                            "confidence": "medium"
                        }]}
                    elif isinstance(resp_data, dict) and resp_data.get("users"):
                        return {"findings": [{
                            "platform": "Adobe",
                            "profile_url": None,
                            "metadata": {"note": "Account exists"},
                            "confidence": "medium"
                        }]}
                except Exception:
                    # If it's not JSON but returned 200, we check text
                    if "not found" not in resp.text.lower():
                        return {"findings": [{
                            "platform": "Adobe",
                            "profile_url": None,
                            "metadata": {"note": "Account exists"},
                            "confidence": "medium"
                        }]}
            elif resp.status_code in (400, 404):
                return {"findings": []}
            else:
                return {"error": f"Adobe HTTP {resp.status_code}"}
                
            return {"findings": []}
        except Exception as e:
            return {"error": f"Adobe failed: {str(e)}"}

    async def _check_github(self, client: httpx.AsyncClient, email: str) -> dict[str, Any]:
        try:
            url = "https://api.github.com/search/users"
            headers = {
                "Accept": "application/vnd.github+json",
                "User-Agent": "Mozilla/5.0"
            }
            resp = await client.get(url, headers=headers, params={"q": f"{email} in:email"})
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get("total_count", 0) > 0:
                    items = data.get("items", [])
                    if items:
                        first = items[0]
                        login = first.get("login")
                        if login:
                            user_resp = await client.get(f"https://api.github.com/users/{login}", headers=headers)
                            metadata = {
                                "login": login,
                                "avatar_url": first.get("avatar_url"),
                                "html_url": first.get("html_url"),
                                "type": first.get("type"),
                            }
                            if user_resp.status_code == 200:
                                user_data = user_resp.json()
                                for k in ["name", "bio", "location", "public_repos", "followers", "company"]:
                                    if user_data.get(k) is not None:
                                        metadata[k] = user_data.get(k)
                            return {"findings": [{
                                "platform": "GitHub",
                                "profile_url": first.get("html_url"),
                                "metadata": metadata,
                                "confidence": "high"
                            }]}
            return {"findings": []}
        except Exception as e:
            return {"error": f"GitHub failed: {str(e)}"}

    async def _check_patreon(self, client: httpx.AsyncClient, email: str) -> dict[str, Any]:
        try:
            url = "https://www.patreon.com/api/auth?include=campaign"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            data = {"data": {"type": "user", "attributes": {"email": email, "password": "invalid_password_123"}}}
            resp = await client.post(url, headers=headers, json=data)

            if resp.status_code in (403, 429, 503):
                return {"findings": []}  # blocked request is not a signal

            text = resp.text.lower()
            if "not found" not in text and "does not exist" not in text and "invalid email" not in text:
                return {"findings": [{
                    "platform": "Patreon",
                    "profile_url": None,
                    "metadata": {"note": "inferred via reset flow"},
                    "confidence": "medium"
                }]}
            return {"findings": []}
        except Exception as e:
            return {"error": f"Patreon failed: {str(e)}"}

    async def _check_snapchat(self, client: httpx.AsyncClient, email: str) -> dict[str, Any]:
        try:
            url = "https://accounts.snapchat.com/accounts/get_username_suggestions"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            data = {"email": email}
            resp = await client.post(url, headers=headers, json=data)
            
            text = resp.text.lower()
            if "suggestions" in text or "reference" in text or "error_message" in text or "taken" in text or "exists" in text:
                return {"findings": [{
                    "platform": "Snapchat",
                    "profile_url": None,
                    "metadata": {"note": "experimental"},
                    "confidence": "low"
                }]}
            return {"findings": []}
        except Exception as e:
            return {"error": f"Snapchat failed: {str(e)}"}

    async def _check_skype(self, client: httpx.AsyncClient, email: str) -> dict[str, Any]:
        try:
            url = "https://login.live.com/GetCredentialType.srf"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            data = {"username": email, "uaid": "", "isOtherIdpSupported": True}
            resp = await client.post(url, headers=headers, json=data)
            
            if resp.status_code == 200:
                resp_data = resp.json()
                if resp_data.get("IfExistsResult") == 0:
                    metadata = {}
                    if "DisplayName" in resp_data:
                        metadata["DisplayName"] = resp_data["DisplayName"]
                    if "MemberName" in resp_data:
                        metadata["MemberName"] = resp_data["MemberName"]
                    
                    return {"findings": [{
                        "platform": "skype_microsoft",
                        "profile_url": None,
                        "metadata": metadata,
                        "confidence": "high"
                    }]}
            return {"findings": []}
        except Exception as e:
            return {"error": f"Skype failed: {str(e)}"}

    async def _check_zoom(self, client: httpx.AsyncClient, email: str) -> dict[str, Any]:
        try:
            url = "https://zoom.us/signin/confirm_account"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            data = {"email": email}
            resp = await client.post(url, headers=headers, data=data)
            
            text = resp.text.lower()
            if "not found" not in text and "does not exist" not in text and "invalid" not in text:
                return {"findings": [{
                    "platform": "zoom",
                    "profile_url": None,
                    "metadata": {"note": "inferred via confirmation flow"},
                    "confidence": "medium"
                }]}
            return {"findings": []}
        except Exception as e:
            return {"error": f"Zoom failed: {str(e)}"}

    async def _check_dropbox(self, client: httpx.AsyncClient, email: str) -> dict[str, Any]:
        try:
            url = "https://www.dropbox.com/register"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            data = {"login_email": email, "login_password": "x"}
            resp = await client.post(url, headers=headers, data=data)
            
            text = resp.text.lower()
            if "already in use" in text or "already taken" in text or "exists" in text or "incorrect" in text:
                return {"findings": [{
                    "platform": "dropbox",
                    "profile_url": None,
                    "metadata": {"note": "inferred via registration flow"},
                    "confidence": "medium"
                }]}
            return {"findings": []}
        except Exception as e:
            return {"error": f"Dropbox failed: {str(e)}"}

    async def _check_apple(self, client: httpx.AsyncClient, email: str) -> dict[str, Any]:
        try:
            url = "https://appleid.apple.com/account/check/email"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Referer": "https://appleid.apple.com/account"
            }
            resp = await client.post(url, headers=headers, json={"email": email})
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("used") is True or data.get("exists") is True or data.get("isUsed") is True:
                        return {"findings": [{
                            "platform": "apple",
                            "profile_url": None,
                            "metadata": {"flag": "inferred via Apple ID check"},
                            "confidence": "medium"
                        }]}
                except Exception:
                    pass
            return {"findings": []}
        except Exception as e:
            return {"error": f"Apple failed: {str(e)}"}

    async def _check_linkedin(self, client: httpx.AsyncClient, email: str) -> dict[str, Any]:
        try:
            url = "https://www.linkedin.com/uas/request-password-reset"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            resp = await client.post(url, headers=headers, data={"email": email})
            
            if resp.status_code in (403, 429, 999):
                return {"findings": [], "error": f"LinkedIn blocked request (HTTP {resp.status_code})"}
                
            text = resp.text.lower()
            unregistered_indicators = ["could not find", "don't recognize", "not recognized", "not associated", "invalid", "not found", "please try again"]
            if any(indicator in text for indicator in unregistered_indicators):
                return {"findings": []}
                
            if resp.status_code in (200, 302):
                return {"findings": [{
                    "platform": "linkedin",
                    "profile_url": None,
                    "metadata": {
                        "flag": "inferred via reset flow — limited signal",
                        "note": "LinkedIn aggressively blocks scrapers"
                    },
                    "confidence": "medium"
                }]}
            return {"findings": []}
        except Exception as e:
            err = repr(e) if not str(e) else str(e)
            return {"error": f"LinkedIn failed: {err}"}

    async def _check_discord(self, client: httpx.AsyncClient, email: str) -> dict[str, Any]:
        try:
            url = "https://discord.com/api/v9/auth/register"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Content-Type": "application/json"
            }
            payload = {
                "email": email,
                "username": "a",
                "password": "Aa1!aaaa",
                "date_of_birth": "1990-01-01",
                "consent": True
            }
            resp = await client.post(url, headers=headers, json=payload)
            
            try:
                data = resp.json()
                errors = data.get("errors", {})
                if "email" in errors:
                    return {"findings": [{
                        "platform": "discord",
                        "profile_url": None,
                        "metadata": {"flag": "inferred via registration check"},
                        "confidence": "medium"
                    }]}
            except Exception:
                pass
            return {"findings": []}
        except Exception as e:
            return {"error": f"Discord failed: {str(e)}"}
