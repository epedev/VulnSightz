"""Shared scoped HTTP session for every VulnSight detector.

Validates scheme, host/origin, credentials, and path prefix on every request
and every redirect hop. Detectors must not use bare ``requests.Session``.
"""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from vulnsight.scope import LOOPBACK_HOSTS, ScopeError, origin_of

METADATA_HOSTS = frozenset({"169.254.169.254", "metadata.google.internal", "metadata"})


class ScopePolicy:
    """Authorized origin + network policy for outbound scanner requests."""

    def __init__(
        self,
        allowed_origins: list[str],
        *,
        allow_loopback: bool = True,
        allow_private: bool = False,
        path_prefixes: list[str] | None = None,
        max_redirects: int = 5,
    ) -> None:
        if not allowed_origins:
            raise ScopeError("at least one allowed origin is required")
        self.allowed_origins = {origin_of(o) for o in allowed_origins}
        self.allow_loopback = allow_loopback
        self.allow_private = allow_private
        self.path_prefixes = path_prefixes or ["/"]
        self.max_redirects = max(0, max_redirects)

    @classmethod
    def for_target(
        cls,
        base_url: str,
        *,
        allow_private: bool = False,
        allow_external: bool = False,
        path_prefixes: list[str] | None = None,
        max_redirects: int = 5,
    ) -> "ScopePolicy":
        parsed = urlparse(base_url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ScopeError(f"invalid target URL: {base_url}")
        if parsed.username or parsed.password:
            raise ScopeError("credentials in URL are not allowed")
        host = (parsed.hostname or "").lower()
        if not host:
            raise ScopeError(f"invalid target host: {base_url}")

        is_loopback = host in LOOPBACK_HOSTS
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            is_loopback = is_loopback or ip.is_loopback
            is_private = ip.is_private or ip.is_link_local
        except ValueError:
            is_private = False

        if not allow_external and not is_loopback:
            if is_private and allow_private:
                pass
            elif not is_loopback:
                raise ScopeError(
                    "Testing is restricted to the local HTTP lab unless "
                    "allow_private_network / --allow-external is set."
                )

        return cls(
            [base_url],
            allow_loopback=True if is_loopback else allow_private or allow_external,
            allow_private=allow_private or allow_external or is_loopback,
            path_prefixes=path_prefixes,
            max_redirects=max_redirects,
        )

    def check_url(self, url: str, *, purpose: str = "request") -> str:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ScopeError(f"{purpose}: invalid URL {url!r}")
        if parsed.username or parsed.password:
            raise ScopeError(f"{purpose}: credentials in URL are not allowed")
        origin = origin_of(url)
        if origin not in self.allowed_origins:
            raise ScopeError(f"{purpose}: origin {origin} not allowed")
        host = (parsed.hostname or "").lower().strip("[]")
        if host in METADATA_HOSTS:
            raise ScopeError(f"{purpose}: metadata host blocked")
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_loopback and not self.allow_loopback:
                raise ScopeError(f"{purpose}: loopback blocked")
            if (ip.is_private or ip.is_link_local) and not self.allow_private:
                raise ScopeError(f"{purpose}: private/link-local blocked")
        except ValueError:
            if host in LOOPBACK_HOSTS and not self.allow_loopback:
                raise ScopeError(f"{purpose}: loopback hostname blocked")
        path = parsed.path or "/"
        if not any(path.startswith(p) for p in self.path_prefixes):
            raise ScopeError(f"{purpose}: path {path!r} outside prefixes")
        return url

    def url_in_scope(self, url: str) -> bool:
        try:
            self.check_url(url, purpose="filter")
            return True
        except ScopeError:
            return False


class ScopedSession:
    """requests.Session wrapper that re-validates every hop."""

    def __init__(
        self,
        policy: ScopePolicy,
        session: requests.Session | None = None,
        *,
        user_agent: str = "VulnSight/0.2 (+authorized-assessment)",
    ) -> None:
        self.policy = policy
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", user_agent)
        self.redirect_chains: list[list[str]] = []

    def __enter__(self) -> "ScopedSession":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.session.close()

    @classmethod
    def for_target(
        cls,
        base_url: str,
        *,
        allow_private: bool = False,
        allow_external: bool = False,
        session: requests.Session | None = None,
        **kwargs: Any,
    ) -> "ScopedSession":
        policy = ScopePolicy.for_target(
            base_url,
            allow_private=allow_private,
            allow_external=allow_external,
        )
        return cls(policy, session=session, **kwargs)

    def request(
        self,
        method: str,
        url: str,
        *,
        allow_redirects: bool = False,
        timeout: float | tuple[float, float] = 5.0,
        **kwargs: Any,
    ) -> requests.Response:
        target = self.policy.check_url(url, purpose="request")
        # Always fetch first hop without auto-follow so we can re-check scope.
        resp = self.session.request(
            method,
            target,
            allow_redirects=False,
            timeout=timeout,
            **kwargs,
        )
        chain = [str(resp.url)]
        hops = 0
        follow = allow_redirects
        while follow and resp.is_redirect and hops < self.policy.max_redirects:
            loc = resp.headers.get("Location")
            if not loc:
                break
            next_url = urljoin(str(resp.url), loc)
            next_url = self.policy.check_url(next_url, purpose="redirect")
            hops += 1
            resp = self.session.request(
                "GET",
                next_url,
                allow_redirects=False,
                timeout=timeout,
            )
            chain.append(str(resp.url))
        if len(chain) > 1:
            self.redirect_chains.append(chain)
        # Expose final URL consistently
        if not hasattr(resp, "url") or not resp.url:
            resp.url = chain[-1]  # type: ignore[attr-defined]
        return resp

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        allow_redirects = bool(kwargs.pop("allow_redirects", False))
        timeout = kwargs.pop("timeout", 5.0)
        target = self.policy.check_url(url, purpose="request")
        resp = self.session.get(
            target, allow_redirects=False, timeout=timeout, **kwargs
        )
        if not allow_redirects:
            return resp
        chain = [str(getattr(resp, "url", target) or target)]
        hops = 0
        while bool(getattr(resp, "is_redirect", False)) and hops < self.policy.max_redirects:
            headers = getattr(resp, "headers", None) or {}
            loc = headers.get("Location") if hasattr(headers, "get") else None
            if loc is None or not isinstance(loc, str) or not loc:
                break
            next_url = urljoin(str(getattr(resp, "url", target) or target), loc)
            next_url = self.policy.check_url(next_url, purpose="redirect")
            hops += 1
            resp = self.session.get(
                next_url, allow_redirects=False, timeout=timeout, **kwargs
            )
            chain.append(str(getattr(resp, "url", next_url) or next_url))
        if len(chain) > 1:
            self.redirect_chains.append(chain)
        return resp

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        allow_redirects = bool(kwargs.pop("allow_redirects", False))
        if not allow_redirects:
            target = self.policy.check_url(url, purpose="request")
            return self.session.post(target, allow_redirects=False, **kwargs)
        return self.request("POST", url, allow_redirects=True, **kwargs)

    def put(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("DELETE", url, **kwargs)
