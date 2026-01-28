# quantumvault-cryptography

**Drop-in quantum-safe upgrade for Python applications - zero code changes required.**

This package transparently upgrades your Python application's cryptographic operations to quantum-safe alternatives. Simply install and configure at application startup - all existing crypto code continues to work while being protected against quantum computer attacks.

## Features

- **Zero Code Changes**: Works with existing `cryptography` library usage
- **Automatic Upgrades**: RSA/ECDSA operations upgraded to ML-KEM/ML-DSA hybrids
- **Multiple Modes**: Monitor, hybrid, or pure post-quantum
- **Analytics**: Track all crypto operations via QuantumVault dashboard
- **Gradual Rollout**: Start in monitor mode, then progressively upgrade
- **Fallback Safety**: Automatic fallback to classical crypto on errors

## Installation

```bash
pip install quantumvault-cryptography
```

## Quick Start

Add this at the **very top** of your application entry point:

```python
import os
import quantumvault_cryptography

# Must be called BEFORE importing cryptography
quantumvault_cryptography.install(
    api_key=os.environ['QUANTUMVAULT_API_KEY'],
    mode='hybrid'  # Start with 'monitor' to observe without changes
)

# Now all your existing code is quantum-safe!
from cryptography.hazmat.primitives.asymmetric import rsa

# This RSA key is automatically upgraded to RSA + ML-KEM-768 hybrid
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
```

## Configuration

```python
import quantumvault_cryptography

quantumvault_cryptography.install(
    # Required: Your QuantumVault API key
    api_key='qvp_...',

    # Optional: Plugin ID for analytics (get from QuantumVault dashboard)
    plugin_id='plugin_abc123',

    # Optional: API endpoint (defaults to production)
    endpoint='https://api.quantumvault.io',

    # Mode: 'monitor' | 'hybrid' | 'pq_only' | 'intercept'
    # - monitor: Log only, no changes (safe to start with)
    # - hybrid: Use classical + quantum-safe combined (recommended)
    # - pq_only: Pure post-quantum (future-proof)
    # - intercept: Upgrade classical to PQ transparently
    mode='hybrid',

    # Fallback to classical crypto on errors
    fallback_on_error=True,

    # API timeout in milliseconds
    timeout_ms=5000,

    # Enable debug logging
    log_operations=True,
)
```

## Algorithm Mappings

| Classical Algorithm | Quantum-Safe Upgrade | Hybrid Option |
|---------------------|----------------------|---------------|
| RSA-2048 | ML-KEM-768 | RSA-2048 + ML-KEM-768 |
| RSA-3072 | ML-KEM-1024 | RSA-3072 + ML-KEM-1024 |
| RSA-4096 | ML-KEM-1024 | RSA-4096 + ML-KEM-1024 |
| ECDSA-P256 | ML-DSA-44 | ECDSA-P256 + ML-DSA-44 |
| ECDSA-P384 | ML-DSA-65 | ECDSA-P384 + ML-DSA-65 |
| ECDH-P256 | ML-KEM-768 | ECDH-P256 + ML-KEM-768 |
| Ed25519 | ML-DSA-44 | Ed25519 + ML-DSA-44 |
| X25519 | ML-KEM-768 | X25519 + ML-KEM-768 |

## API Reference

### `install(**config)`

Install the QuantumVault crypto shim. Must be called before any cryptography imports.

### `uninstall()`

Remove the shim and restore original functions.

### `is_active()`

Returns `True` if the shim is currently installed.

### `status()`

Get current shim status and statistics:

```python
import quantumvault_cryptography

print(quantumvault_cryptography.status())
# {
#   'installed': True,
#   'mode': 'hybrid',
#   'stats': {
#     'total_operations': 150,
#     'upgraded_operations': 142,
#     'classical_operations': 8,
#     'failed_operations': 0,
#     'by_algorithm': {'rsa': {'upgraded': 100, 'classical': 0}, ...}
#   }
# }
```

### `get_mappings()`

Get all algorithm mappings.

## Migration Guide

### Step 1: Monitor Mode (Week 1)

Start with monitor mode to understand your crypto usage:

```python
quantumvault_cryptography.install(
    api_key=os.environ['QUANTUMVAULT_API_KEY'],
    mode='monitor',
    log_operations=True
)
```

### Step 2: Review Analytics

Check your QuantumVault dashboard to see:
- Which algorithms are being used
- Operation frequency and latency
- Potential compatibility issues

### Step 3: Enable Hybrid Mode (Week 2+)

Once confident, switch to hybrid mode:

```python
quantumvault_cryptography.install(
    api_key=os.environ['QUANTUMVAULT_API_KEY'],
    mode='hybrid'
)
```

### Step 4: Pure Post-Quantum (Optional)

For maximum future-proofing:

```python
quantumvault_cryptography.install(
    api_key=os.environ['QUANTUMVAULT_API_KEY'],
    mode='pq_only'
)
```

## Supported Operations

| Operation | Supported | Notes |
|-----------|-----------|-------|
| `rsa.generate_private_key()` | Yes | Key generation upgraded |
| `ec.generate_private_key()` | Yes | Key generation upgraded |
| `Ed25519PrivateKey.generate()` | Yes | Key generation upgraded |
| `private_key.sign()` | Coming soon | Signature operations |
| `public_key.verify()` | Coming soon | Verification operations |
| AES operations | N/A | Already quantum-safe |
| SHA-256+ hashing | N/A | Already quantum-safe |

## Logging

Enable Python logging to see shim activity:

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("quantumvault").setLevel(logging.DEBUG)
```

## Requirements

- Python 3.8+
- cryptography >= 41.0.0
- requests >= 2.28.0

## License

MIT

## Support

- Documentation: https://docs.quantumvault.io
- Issues: https://github.com/AllSecureX-Quantum/quantumvault-python/issues
- Email: support@allsecurex.com

## About AllSecureX

AllSecureX provides enterprise-grade post-quantum cryptography solutions. QuantumVault is our flagship product for NIST-standardized quantum-resistant algorithms (FIPS 203, 204, 205).

- Website: https://allsecurex.com
- GitHub: https://github.com/AllSecureX-Quantum
