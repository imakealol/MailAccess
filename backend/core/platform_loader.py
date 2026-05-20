from __future__ import annotations

import logging
from pathlib import Path

import yaml

from ..platforms.schema import PlatformCheck

logger = logging.getLogger(__name__)

_PLATFORMS_DIR = Path(__file__).resolve().parent.parent / "platforms"


class PlatformLoader:
    _cache: list[PlatformCheck] | None = None

    def load_all(self) -> list[PlatformCheck]:
        if self._cache is not None:
            return list(self._cache)

        platforms: list[PlatformCheck] = []
        if not _PLATFORMS_DIR.is_dir():
            logger.warning("Platforms directory missing: %s", _PLATFORMS_DIR)
            self._cache = []
            return []

        for path in sorted(_PLATFORMS_DIR.glob("*.yaml")):
            if path.stem.lower() == "template":
                continue
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.warning("Skip platform %s: read failed (%s)", path.name, exc)
                continue
            if not isinstance(raw, dict):
                logger.warning("Skip platform %s: expected mapping", path.name)
                continue
            try:
                platform = PlatformCheck.model_validate(raw)
            except Exception as exc:
                logger.warning("Skip platform %s: invalid schema (%s)", path.name, exc)
                continue
            slug = path.stem
            platforms.append(platform.model_copy(update={"slug": slug}))

        self._cache = platforms
        return list(platforms)

    def load_category(self, category: str) -> list[PlatformCheck]:
        return [p for p in self.load_all() if p.category == category]
