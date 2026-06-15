"""Phone adapter — region / carrier / line-type, fully offline (keyless).

kipi treats `phone` as a first-class entity type but had no enrichment for it. This
parses a number with Google's libphonenumber (the `phonenumbers` lib) using its bundled
offline metadata: region, carrier, and line-type (incl. VoIP, a real fraud signal). No
network, deterministic — so it is T1/T2, not a scrape.

The lib is a pip dependency (`phonenumbers`); the import is self-guarded so a missing dep
returns a clear [needs phonenumbers] result rather than crashing the agent. Note: per the
q-investigation rule, a phone used as an identity ANCHOR still needs an independent second
source — this adapter only parses the number, it does not assert account attribution.
"""
from __future__ import annotations

from investigations.enrich.base import Adapter, EnrichmentResult, EnrichmentError

_LINE_TYPES = {0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE", 3: "TOLL_FREE",
               4: "PREMIUM_RATE", 5: "SHARED_COST", 6: "VOIP", 7: "PERSONAL_NUMBER",
               8: "PAGER", 9: "UAN", 10: "VOICEMAIL", 27: "UNKNOWN"}


class PhoneAdapter(Adapter):
    slug = "phone"
    watched_types = ("phone",)
    display_name = "Phone intel (region/carrier/line-type, offline)"
    env_var = None  # keyless, fully offline
    category = "identity"
    cost_per_call_usd = 0.0

    def run(self, query: str, mode: str | None = None,
            timeout: int = 10) -> list[EnrichmentResult]:
        num = (query or "").strip()
        if not num:
            raise EnrichmentError("phone: empty number")
        try:
            import phonenumbers
            from phonenumbers import geocoder, carrier
        except ImportError:
            return [EnrichmentResult(
                result_type="document",
                title="phone: phonenumbers not installed",
                summary="[needs phonenumbers] pip install 'phonenumbers>=8.13,<9' and retry.",
                confidence="low")]
        try:
            parsed = phonenumbers.parse(num, None)
        except phonenumbers.NumberParseException as exc:
            raise EnrichmentError(f"phone: cannot parse '{num}' ({exc}) — use E.164 (+<cc>...)")
        if not phonenumbers.is_valid_number(parsed):
            return [EnrichmentResult(
                result_type="document",
                title=f"phone: {num} — invalid",
                summary="Not a valid phone number per libphonenumber metadata.",
                raw_json={"input": num, "valid": False}, confidence="low")]
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        region = geocoder.description_for_number(parsed, "en") or ""
        carrier_name = carrier.name_for_number(parsed, "en") or ""
        line_type = _LINE_TYPES.get(phonenumbers.number_type(parsed), "UNKNOWN")
        country = phonenumbers.region_code_for_number(parsed) or ""
        header = EnrichmentResult(
            result_type="document",
            title=f"phone: {e164} — {region or country}, {line_type}",
            summary=(f"E.164: {e164}\nregion: {region}\ncountry: {country}\n"
                     f"carrier: {carrier_name or '(unknown)'}\nline type: {line_type}"
                     + ("\nVoIP — a common fraud/disposable signal." if line_type == "VOIP" else "")),
            raw_json={"input": num, "e164": e164, "phone_country": country,
                      "region": region, "carrier": carrier_name, "line_type": line_type,
                      "valid": True},
            confidence="high")
        rows = [EnrichmentResult(
            result_type="profile", title=carrier_name,
            summary=f"Carrier/operator for {e164} ({line_type}).",
            confidence="medium")] if carrier_name else []
        return [header] + rows
