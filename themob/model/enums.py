"""Controlled vocabularies shared across the engine, storage, and UI.

Keep these as the single source of truth for every categorical value. The SQLite
schema mirrors them with CHECK constraints; if you add a value here, add it to the
matching CHECK in the migration too.
"""
from __future__ import annotations

from enum import Enum


class Platform(str, Enum):
    ANDROID = "android"
    IOS = "ios"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Tester workflow state. Analyzers emit NEW; the human moves it from there."""
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class Stage(str, Enum):
    """Pipeline stages. Also the tester-facing sections (each a view over the graph)."""
    INTAKE = "intake"
    UNPACK = "unpack"
    REVERSE_ENGINEERING = "reverse_engineering"
    SECRETS = "secrets"
    SAST = "sast"
    DEPENDENCIES = "dependencies"
    CONFIG_AUDIT = "config_audit"
    API_RECON = "api_recon"
    DYNAMIC = "dynamic"
    CORRELATE = "correlate"


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


class EntityType(str, Enum):
    APP = "app"
    COMPONENT = "component"
    PERMISSION = "permission"
    DEEP_LINK = "deep_link"
    ENDPOINT = "endpoint"
    CLOUD_ASSET = "cloud_asset"
    SECRET = "secret"
    LIBRARY = "library"
    NATIVE_LIB = "native_lib"
    CRYPTO_USAGE = "crypto_usage"
    STORAGE_SINK = "storage_sink"


class ComponentKind(str, Enum):
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"


class EdgeType(str, Enum):
    DECLARES = "declares"
    EXPORTS = "exports"
    REQUESTS_PERMISSION = "requests_permission"
    CALLS = "calls"
    TALKS_TO = "talks_to"
    EMBEDS = "embeds"
    USES = "uses"
    STORES_IN = "stores_in"
    EVIDENCES = "evidences"
    RESOLVES_TO = "resolves_to"


class MASVSCategory(str, Enum):
    STORAGE = "MASVS-STORAGE"
    CRYPTO = "MASVS-CRYPTO"
    AUTH = "MASVS-AUTH"
    NETWORK = "MASVS-NETWORK"
    PLATFORM = "MASVS-PLATFORM"
    CODE = "MASVS-CODE"
    RESILIENCE = "MASVS-RESILIENCE"
    PRIVACY = "MASVS-PRIVACY"


class EvidenceKind(str, Enum):
    SNIPPET = "snippet"
    ARTIFACT = "artifact"
    SCREENSHOT = "screenshot"
    HTTP = "http"
    LOG = "log"
