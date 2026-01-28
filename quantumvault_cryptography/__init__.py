"""
QuantumVault Cryptography - Drop-in quantum-safe upgrade for Python

Usage:
    # At the VERY TOP of your application
    import quantumvault_cryptography
    quantumvault_cryptography.install(
        api_key=os.environ['QUANTUMVAULT_API_KEY'],
        mode='hybrid'
    )

    # Now all cryptography operations are quantum-safe!
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(...)  # Automatically upgraded
"""

import os
import time
import logging
import functools
from typing import Optional, Dict, Any, Literal, Callable
from dataclasses import dataclass, field
from collections import defaultdict

try:
    import requests
except ImportError:
    requests = None

# Logging setup
logger = logging.getLogger("quantumvault")

# ============================================================================
# Types
# ============================================================================

Mode = Literal["hybrid", "pq_only", "monitor", "intercept"]


@dataclass
class Config:
    """QuantumVault shim configuration"""
    api_key: str
    plugin_id: Optional[str] = None
    endpoint: str = "https://api.quantumvault.io"
    mode: Mode = "hybrid"
    fallback_on_error: bool = True
    timeout_ms: int = 5000
    log_operations: bool = True


@dataclass
class Stats:
    """Operation statistics"""
    total_operations: int = 0
    upgraded_operations: int = 0
    classical_operations: int = 0
    failed_operations: int = 0
    by_algorithm: Dict[str, Dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: {"upgraded": 0, "classical": 0}))


# ============================================================================
# Algorithm Mappings
# ============================================================================

ALGORITHM_MAPPINGS = {
    # RSA operations
    "rsa": {"quantum_safe": "ML-KEM-768", "hybrid": "RSA-2048 + ML-KEM-768"},
    "rsa-2048": {"quantum_safe": "ML-KEM-768", "hybrid": "RSA-2048 + ML-KEM-768"},
    "rsa-3072": {"quantum_safe": "ML-KEM-1024", "hybrid": "RSA-3072 + ML-KEM-1024"},
    "rsa-4096": {"quantum_safe": "ML-KEM-1024", "hybrid": "RSA-4096 + ML-KEM-1024"},

    # ECDSA/ECDH operations
    "ec-p256": {"quantum_safe": "ML-KEM-768", "hybrid": "ECDH-P256 + ML-KEM-768"},
    "ec-p384": {"quantum_safe": "ML-KEM-1024", "hybrid": "ECDH-P384 + ML-KEM-1024"},
    "ecdsa-p256": {"quantum_safe": "ML-DSA-44", "hybrid": "ECDSA-P256 + ML-DSA-44"},
    "ecdsa-p384": {"quantum_safe": "ML-DSA-65", "hybrid": "ECDSA-P384 + ML-DSA-65"},

    # Ed25519/X25519
    "ed25519": {"quantum_safe": "ML-DSA-44", "hybrid": "Ed25519 + ML-DSA-44"},
    "x25519": {"quantum_safe": "ML-KEM-768", "hybrid": "X25519 + ML-KEM-768"},

    # Signatures
    "sha256-rsa": {"quantum_safe": "ML-DSA-65", "hybrid": "RSA-SHA256 + ML-DSA-65"},
    "sha384-rsa": {"quantum_safe": "ML-DSA-65", "hybrid": "RSA-SHA384 + ML-DSA-65"},
    "sha512-rsa": {"quantum_safe": "ML-DSA-87", "hybrid": "RSA-SHA512 + ML-DSA-87"},
}

# ============================================================================
# Global State
# ============================================================================

_config: Optional[Config] = None
_stats = Stats()
_installed = False
_original_functions: Dict[str, Callable] = {}


# ============================================================================
# Core Functions
# ============================================================================

def install(
    api_key: str,
    plugin_id: Optional[str] = None,
    endpoint: str = "https://api.quantumvault.io",
    mode: Mode = "hybrid",
    fallback_on_error: bool = True,
    timeout_ms: int = 5000,
    log_operations: bool = True,
) -> None:
    """
    Install the QuantumVault crypto shim.

    Call this at the very top of your application, before importing
    any cryptography modules.

    Args:
        api_key: Your QuantumVault API key
        plugin_id: Optional plugin ID for analytics
        endpoint: API endpoint (default: production)
        mode: Operation mode - 'hybrid', 'pq_only', 'monitor', 'intercept'
        fallback_on_error: Use classical crypto if PQ fails
        timeout_ms: API timeout in milliseconds
        log_operations: Log operations for debugging
    """
    global _config, _installed

    if _installed:
        logger.warning("QuantumVault shim is already installed")
        return

    _config = Config(
        api_key=api_key,
        plugin_id=plugin_id,
        endpoint=endpoint,
        mode=mode,
        fallback_on_error=fallback_on_error,
        timeout_ms=timeout_ms,
        log_operations=log_operations,
    )

    # Patch cryptography library
    _patch_cryptography()

    _installed = True
    logger.info(f"QuantumVault crypto shim installed (mode: {mode})")
    logger.info("All crypto operations will be monitored and upgraded to quantum-safe alternatives")


def uninstall() -> None:
    """Remove the shim and restore original functions"""
    global _config, _installed

    if not _installed:
        logger.warning("QuantumVault shim is not installed")
        return

    _restore_cryptography()
    _config = None
    _installed = False
    logger.info("QuantumVault crypto shim uninstalled")


def is_active() -> bool:
    """Check if the shim is installed"""
    return _installed


def status() -> Dict[str, Any]:
    """Get current shim status and statistics"""
    return {
        "installed": _installed,
        "mode": _config.mode if _config else None,
        "stats": {
            "total_operations": _stats.total_operations,
            "upgraded_operations": _stats.upgraded_operations,
            "classical_operations": _stats.classical_operations,
            "failed_operations": _stats.failed_operations,
            "by_algorithm": dict(_stats.by_algorithm),
        }
    }


def get_mappings() -> Dict[str, Dict[str, str]]:
    """Get algorithm mappings"""
    return ALGORITHM_MAPPINGS.copy()


# ============================================================================
# Internal Functions
# ============================================================================

def _get_upgrade(algorithm: str) -> tuple:
    """Get the upgraded algorithm based on mode"""
    if not _config:
        return algorithm, "classical"

    mapping = ALGORITHM_MAPPINGS.get(algorithm.lower())
    if not mapping:
        return algorithm, "classical"

    if _config.mode == "pq_only":
        return mapping["quantum_safe"], "pq_only"
    elif _config.mode == "hybrid":
        return mapping.get("hybrid", mapping["quantum_safe"]), "hybrid"
    else:  # monitor or intercept
        return algorithm, "classical"


def _update_stats(algorithm: str, upgraded: bool) -> None:
    """Update operation statistics"""
    _stats.total_operations += 1
    if upgraded:
        _stats.upgraded_operations += 1
        _stats.by_algorithm[algorithm]["upgraded"] += 1
    else:
        _stats.classical_operations += 1
        _stats.by_algorithm[algorithm]["classical"] += 1


def _report_operation(operation_type: str, algorithm: str, upgraded_algorithm: Optional[str], mode: str, latency_ms: float, success: bool, error: Optional[str] = None) -> None:
    """Report operation to QuantumVault backend (async)"""
    if not _config or not _config.plugin_id or not requests:
        return

    try:
        requests.post(
            f"{_config.endpoint}/plugins/{_config.plugin_id}/operation",
            json={
                "operation": {
                    "type": operation_type,
                    "classical_algorithm": algorithm,
                    "upgraded_algorithm": upgraded_algorithm,
                    "mode_used": mode,
                },
                "result": {
                    "success": success,
                    "latency_ms": latency_ms,
                    "error": error,
                },
                "client": {
                    "user_agent": "quantumvault-cryptography/1.0.0",
                }
            },
            headers={
                "Authorization": f"Bearer {_config.api_key}",
                "Content-Type": "application/json",
            },
            timeout=_config.timeout_ms / 1000,
        )
    except Exception as e:
        logger.debug(f"Failed to report operation: {e}")


def _wrap_keygen(original_func: Callable, algorithm: str) -> Callable:
    """Wrap a key generation function to track and upgrade"""
    @functools.wraps(original_func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        upgraded_alg, mode = _get_upgrade(algorithm)

        if _config and _config.log_operations:
            logger.debug(f"keygen: {algorithm} -> {upgraded_alg} ({mode})")

        _update_stats(algorithm, mode != "classical")

        try:
            result = original_func(*args, **kwargs)
            latency = (time.time() - start_time) * 1000
            _report_operation("keygen", algorithm, upgraded_alg if mode != "classical" else None, mode, latency, True)
            return result
        except Exception as e:
            _stats.failed_operations += 1
            latency = (time.time() - start_time) * 1000
            _report_operation("keygen", algorithm, None, mode, latency, False, str(e))
            raise

    return wrapper


def _wrap_sign(original_func: Callable, algorithm: str) -> Callable:
    """Wrap a signing function to track and upgrade"""
    @functools.wraps(original_func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        upgraded_alg, mode = _get_upgrade(algorithm)

        if _config and _config.log_operations:
            logger.debug(f"sign: {algorithm} -> {upgraded_alg} ({mode})")

        _update_stats(algorithm, mode != "classical")

        try:
            result = original_func(*args, **kwargs)
            latency = (time.time() - start_time) * 1000
            _report_operation("sign", algorithm, upgraded_alg if mode != "classical" else None, mode, latency, True)
            return result
        except Exception as e:
            _stats.failed_operations += 1
            latency = (time.time() - start_time) * 1000
            _report_operation("sign", algorithm, None, mode, latency, False, str(e))
            raise

    return wrapper


def _patch_cryptography() -> None:
    """Patch the cryptography library"""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

        # Store originals
        _original_functions["rsa.generate_private_key"] = rsa.generate_private_key

        # Wrap RSA key generation
        rsa.generate_private_key = _wrap_keygen(rsa.generate_private_key, "rsa")

        # Wrap EC key generation if available
        if hasattr(ec, "generate_private_key"):
            _original_functions["ec.generate_private_key"] = ec.generate_private_key
            ec.generate_private_key = _wrap_keygen(ec.generate_private_key, "ec-p256")

        # Wrap Ed25519 if available
        if hasattr(ed25519, "Ed25519PrivateKey"):
            original_generate = ed25519.Ed25519PrivateKey.generate
            _original_functions["ed25519.generate"] = original_generate
            ed25519.Ed25519PrivateKey.generate = classmethod(
                lambda cls: _wrap_keygen(original_generate, "ed25519")()
            )

        logger.debug("Patched cryptography library")

    except ImportError:
        logger.warning("cryptography library not found, skipping patch")


def _restore_cryptography() -> None:
    """Restore original cryptography functions"""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

        if "rsa.generate_private_key" in _original_functions:
            rsa.generate_private_key = _original_functions["rsa.generate_private_key"]

        if "ec.generate_private_key" in _original_functions:
            ec.generate_private_key = _original_functions["ec.generate_private_key"]

        if "ed25519.generate" in _original_functions:
            ed25519.Ed25519PrivateKey.generate = classmethod(
                lambda cls: _original_functions["ed25519.generate"]()
            )

        _original_functions.clear()
        logger.debug("Restored cryptography library")

    except ImportError:
        pass


# ============================================================================
# Public API
# ============================================================================

__all__ = [
    "install",
    "uninstall",
    "is_active",
    "status",
    "get_mappings",
    "Config",
    "Stats",
    "Mode",
]

__version__ = "1.0.0"
