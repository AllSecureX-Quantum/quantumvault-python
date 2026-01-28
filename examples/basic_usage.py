#!/usr/bin/env python3
"""
Example: Basic Usage of quantumvault-cryptography

This demonstrates how existing Python cryptography code works unchanged
while being automatically upgraded to quantum-safe algorithms.
"""

import os
import sys
import logging

# Enable logging to see shim activity
logging.basicConfig(
    level=logging.DEBUG,
    format='%(name)s - %(levelname)s - %(message)s'
)

# Add parent directory to path for local testing
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# IMPORTANT: Install the shim BEFORE importing cryptography
import quantumvault_cryptography

quantumvault_cryptography.install(
    api_key=os.environ.get('QUANTUMVAULT_API_KEY', 'demo_key_for_testing'),
    mode='hybrid',
    log_operations=True
)

# Now use cryptography normally - operations are automatically upgraded!
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

print("\n" + "=" * 60)
print("QuantumVault Cryptography Shim Demo")
print("=" * 60 + "\n")

# Example 1: Generate RSA key pair (upgraded to hybrid RSA + ML-KEM)
print("1. Generating RSA-2048 key pair (quantum-safe hybrid)...")
rsa_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
print("   RSA key pair generated successfully!\n")

# Example 2: Generate another RSA key with different size
print("2. Generating RSA-4096 key pair (quantum-safe hybrid)...")
rsa_private_key_4096 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)
print("   RSA-4096 key pair generated successfully!\n")

# Example 3: Generate EC key pair (upgraded to hybrid ECDH + ML-KEM)
print("3. Generating EC P-256 key pair (quantum-safe hybrid)...")
from cryptography.hazmat.primitives.asymmetric import ec as ec_module
ec_private_key = ec_module.generate_private_key(ec_module.SECP256R1())
print("   EC key pair generated successfully!\n")

# Example 4: Generate EC P-384 key
print("4. Generating EC P-384 key pair (quantum-safe hybrid)...")
ec_private_key_384 = ec_module.generate_private_key(ec_module.SECP384R1())
print("   EC P-384 key pair generated successfully!\n")

# Example 5: Sign data (signature operations monitored)
print("5. Signing data with RSA-SHA256...")
message = b"Important message that needs quantum-safe signature"
signature = rsa_private_key.sign(
    message,
    padding.PKCS1v15(),
    hashes.SHA256()
)
print(f"   Signature: {signature[:30].hex()}...")
print("   Signature created successfully!\n")

# Example 6: Verify signature
print("6. Verifying RSA signature...")
public_key = rsa_private_key.public_key()
try:
    public_key.verify(
        signature,
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("   Signature valid!\n")
except Exception as e:
    print(f"   Verification failed: {e}\n")

# Check shim status
print("=" * 60)
print("Shim Status")
print("=" * 60)
status = quantumvault_cryptography.status()
print(f"Installed: {status['installed']}")
print(f"Mode: {status['mode']}")
print(f"Total Operations: {status['stats']['total_operations']}")
print(f"Upgraded Operations: {status['stats']['upgraded_operations']}")
print(f"Classical Operations: {status['stats']['classical_operations']}")
print(f"Failed Operations: {status['stats']['failed_operations']}")

print("\n" + "=" * 60)
print("Algorithm Usage")
print("=" * 60)
for algorithm, counts in status['stats']['by_algorithm'].items():
    print(f"{algorithm}: {counts['upgraded']} upgraded, {counts['classical']} classical")

print("\n" + "=" * 60)
print("Demo Complete!")
print("=" * 60)
print("Your existing code is now quantum-safe with ZERO code changes!")
