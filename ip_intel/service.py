from __future__ import annotations

import ipaddress
import os
from dataclasses import asdict, dataclass
from typing import Any, Optional

import requests
from dotenv import load_dotenv

load_dotenv()

try:
    import ipinfo
except ImportError:
    ipinfo = None

try:
    import geoip2.database
except ImportError:
    geoip2 = None


@dataclass
class IPIntelResult:
    ip: str
    source: str
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    postal: Optional[str] = None
    timezone: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    hostname: Optional[str] = None
    privacy: Optional[dict[str, Any]] = None
    ip_type: Optional[str] = None
    risk_score: int = 0
    risk_flags: Optional[list[str]] = None
    raw: Optional[dict[str, Any]] = None
    error: Optional[str] = None


class IPIntelligenceService:
    def __init__(
        self,
        ipinfo_token: Optional[str] = None,
        maxmind_city_db_path: Optional[str] = None,
        timeout: int = 8,
    ) -> None:
        self.ipinfo_token = ipinfo_token or os.getenv("IPINFO_TOKEN")
        self.maxmind_city_db_path = maxmind_city_db_path or os.getenv("MAXMIND_CITY_DB")
        self.timeout = timeout

    @staticmethod
    def validate_ip(ip: str) -> str:
        try:
            return str(ipaddress.ip_address(ip))
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {ip}") from exc

    @staticmethod
    def classify_ip(ip: str) -> str:
        addr = ipaddress.ip_address(ip)

        if addr.is_private:
            return "private"
        if addr.is_loopback:
            return "loopback"
        if addr.is_multicast:
            return "multicast"
        if addr.is_reserved:
            return "reserved"
        if addr.is_link_local:
            return "link_local"
        if addr.is_unspecified:
            return "unspecified"

        return "public"

    @staticmethod
    def compute_risk(
        ip_type: str,
        hostname: Optional[str] = None,
        privacy: Optional[dict[str, Any]] = None,
        org: Optional[str] = None,
        error: Optional[str] = None,
    ) -> tuple[int, list[str]]:
        score = 0
        flags: list[str] = []

        if error:
            score += 15
            flags.append("lookup_error")

        if ip_type != "public":
            score += 20
            flags.append(f"non_public_ip:{ip_type}")

        if privacy:
            if privacy.get("proxy") is True:
                score += 35
                flags.append("proxy_detected")
            if privacy.get("hosting") is True:
                score += 20
                flags.append("hosting_provider")
            if privacy.get("mobile") is True:
                score += 5
                flags.append("mobile_network")

        if hostname:
            lowered = hostname.lower()
            suspicious_terms = ["tor", "proxy", "vpn", "relay", "exit"]
            for term in suspicious_terms:
                if term in lowered:
                    score += 15
                    flags.append(f"hostname_contains:{term}")

        if org:
            lowered_org = org.lower()
            datacenter_terms = [
                "amazon",
                "aws",
                "google cloud",
                "microsoft",
                "azure",
                "digitalocean",
                "linode",
                "ovh",
                "vultr",
                "hetzner",
                "oracle cloud",
            ]
            for term in datacenter_terms:
                if term in lowered_org:
                    score += 10
                    flags.append(f"datacenter_org:{term}")
                    break

        score = min(score, 100)
        return score, flags

    def enrich_result(self, result: IPIntelResult) -> IPIntelResult:
        ip_type = self.classify_ip(result.ip)
        risk_score, risk_flags = self.compute_risk(
            ip_type=ip_type,
            hostname=result.hostname,
            privacy=result.privacy,
            org=result.org,
            error=result.error,
        )
        result.ip_type = ip_type
        result.risk_score = risk_score
        result.risk_flags = risk_flags
        return result

    def lookup(self, ip: str) -> IPIntelResult:
        ip = self.validate_ip(ip)

        if self.maxmind_city_db_path:
            result = self._lookup_maxmind(ip)
            if result and not result.error:
                return self.enrich_result(result)

        if self.ipinfo_token:
            result = self._lookup_ipinfo(ip)
            if result and not result.error:
                return self.enrich_result(result)

        return self.enrich_result(self._lookup_ip_api(ip))

    def _lookup_ipinfo(self, ip: str) -> IPIntelResult:
        if ipinfo is None:
            return IPIntelResult(ip=ip, source="ipinfo", error="ipinfo package not installed")

        try:
            handler = ipinfo.getHandler(self.ipinfo_token)
            details = handler.getDetails(ip)

            lat = None
            lon = None
            if getattr(details, "loc", None):
                parts = str(details.loc).split(",")
                if len(parts) == 2:
                    lat = float(parts[0])
                    lon = float(parts[1])

            asn = None
            raw = details.all if hasattr(details, "all") else {}

            if isinstance(raw, dict):
                asn_data = raw.get("asn")
                if isinstance(asn_data, dict):
                    asn = asn_data.get("asn")

            return IPIntelResult(
                ip=ip,
                source="ipinfo",
                city=getattr(details, "city", None),
                region=getattr(details, "region", None),
                country=getattr(details, "country", None),
                postal=getattr(details, "postal", None),
                timezone=getattr(details, "timezone", None),
                org=getattr(details, "org", None),
                asn=asn,
                latitude=lat,
                longitude=lon,
                raw=raw,
            )
        except Exception as exc:
            return IPIntelResult(ip=ip, source="ipinfo", error=str(exc))

    def _lookup_ip_api(self, ip: str) -> IPIntelResult:
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={
                    "fields": ",".join(
                        [
                            "status",
                            "message",
                            "query",
                            "country",
                            "regionName",
                            "city",
                            "zip",
                            "lat",
                            "lon",
                            "timezone",
                            "isp",
                            "org",
                            "as",
                            "reverse",
                            "proxy",
                            "hosting",
                            "mobile",
                        ]
                    )
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()

            if data.get("status") != "success":
                return IPIntelResult(
                    ip=ip,
                    source="ip-api",
                    raw=data,
                    error=data.get("message", "Lookup failed"),
                )

            return IPIntelResult(
                ip=data.get("query", ip),
                source="ip-api",
                city=data.get("city"),
                region=data.get("regionName"),
                country=data.get("country"),
                postal=data.get("zip"),
                timezone=data.get("timezone"),
                org=data.get("org") or data.get("isp"),
                asn=data.get("as"),
                latitude=data.get("lat"),
                longitude=data.get("lon"),
                hostname=data.get("reverse"),
                privacy={
                    "proxy": data.get("proxy"),
                    "hosting": data.get("hosting"),
                    "mobile": data.get("mobile"),
                },
                raw=data,
            )
        except Exception as exc:
            return IPIntelResult(ip=ip, source="ip-api", error=str(exc))

    def _lookup_maxmind(self, ip: str) -> IPIntelResult:
        if geoip2 is None:
            return IPIntelResult(ip=ip, source="maxmind", error="geoip2 package not installed")

        try:
            with geoip2.database.Reader(self.maxmind_city_db_path) as reader:
                record = reader.city(ip)

                return IPIntelResult(
                    ip=ip,
                    source="maxmind",
                    city=record.city.name,
                    region=record.subdivisions.most_specific.name if record.subdivisions else None,
                    country=record.country.iso_code,
                    postal=record.postal.code,
                    timezone=record.location.time_zone,
                    latitude=record.location.latitude,
                    longitude=record.location.longitude,
                    raw={
                        "country": record.country.name,
                        "continent": record.continent.name,
                    },
                )
        except Exception as exc:
            return IPIntelResult(ip=ip, source="maxmind", error=str(exc))

    @staticmethod
    def as_dict(result: IPIntelResult) -> dict[str, Any]:
        return asdict(result)
    

    