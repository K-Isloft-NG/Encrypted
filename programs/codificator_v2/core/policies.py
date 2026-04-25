"""
Configuration and security policies module.

Features:
- Security profiles (personal, work, forensic)
- Policy enforcement (password length, algorithms, etc.)
- Configuration file management (TOML/JSON)
- Locked settings (cannot be changed by user)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import (
    Algorithm, CompressionType, ProfileType, SecurityPolicy, AppConfig,
    DEFAULT_MIN_PASSWORD_LENGTH, RECOMMENDED_MIN_PASSWORD_LENGTH,
    DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P,
    DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, DEFAULT_MAX_WORKERS,
    DEFAULT_AUDIT_MAX_SIZE, CONFIG_FILENAME
)
from .errors import PolicyViolationError, LockedSettingError, InvalidConfigError
from .io_utils import normalize_path, ensure_parent_exists


# ══════════════════════════════════════════════════════════════════════════════
# PREDEFINED PROFILES
# ══════════════════════════════════════════════════════════════════════════════

def get_personal_policy() -> SecurityPolicy:
    """Get default personal profile policy."""
    return SecurityPolicy(
        name="personal",
        min_password_length=DEFAULT_MIN_PASSWORD_LENGTH,
        require_uppercase=False,
        require_lowercase=False,
        require_digits=False,
        require_special=False,
        allowed_algorithms=[Algorithm.AES_256_GCM, Algorithm.CHACHA20_POLY1305],
        default_algorithm=Algorithm.AES_256_GCM,
        min_scrypt_n=2 ** 14,
        min_scrypt_r=8,
        min_scrypt_p=1,
        force_chunking=False,
        min_chunk_size=DEFAULT_CHUNK_SIZE,
        max_chunk_size=MAX_CHUNK_SIZE,
        allow_compression=True,
        default_compression=CompressionType.NONE,
        paranoid_mode=False,
        log_plaintext_hash=False,
        locked_settings=[],
    )


def get_work_policy() -> SecurityPolicy:
    """Get work/enterprise profile policy - more restrictive."""
    return SecurityPolicy(
        name="work",
        min_password_length=RECOMMENDED_MIN_PASSWORD_LENGTH,
        require_uppercase=True,
        require_lowercase=True,
        require_digits=True,
        require_special=False,
        allowed_algorithms=[Algorithm.AES_256_GCM],  # Only AES for compliance
        default_algorithm=Algorithm.AES_256_GCM,
        min_scrypt_n=2 ** 15,  # Higher cost
        min_scrypt_r=8,
        min_scrypt_p=1,
        force_chunking=True,  # Always chunk for reliability
        min_chunk_size=DEFAULT_CHUNK_SIZE,
        max_chunk_size=MAX_CHUNK_SIZE,
        allow_compression=False,  # No compression for predictable behavior
        default_compression=CompressionType.NONE,
        paranoid_mode=False,
        log_plaintext_hash=False,
        locked_settings=[
            "min_password_length",
            "allowed_algorithms",
            "min_scrypt_n",
            "paranoid_mode",
        ],
    )


def get_forensic_policy() -> SecurityPolicy:
    """Get forensic/maximum security profile."""
    return SecurityPolicy(
        name="forensic",
        min_password_length=20,
        require_uppercase=True,
        require_lowercase=True,
        require_digits=True,
        require_special=True,
        allowed_algorithms=[Algorithm.AES_256_GCM, Algorithm.CHACHA20_POLY1305],
        default_algorithm=Algorithm.AES_256_GCM,
        min_scrypt_n=2 ** 17,  # Very high cost
        min_scrypt_r=8,
        min_scrypt_p=2,
        force_chunking=True,
        min_chunk_size=DEFAULT_CHUNK_SIZE,
        max_chunk_size=DEFAULT_CHUNK_SIZE * 4,
        allow_compression=False,
        default_compression=CompressionType.NONE,
        paranoid_mode=True,  # Hash all paths in logs
        log_plaintext_hash=False,
        locked_settings=[
            "min_password_length",
            "require_uppercase",
            "require_lowercase",
            "require_digits",
            "require_special",
            "min_scrypt_n",
            "paranoid_mode",
            "log_plaintext_hash",
        ],
    )


def get_policy_for_profile(profile: ProfileType) -> SecurityPolicy:
    """Get security policy for a profile type."""
    if profile == ProfileType.PERSONAL:
        return get_personal_policy()
    elif profile == ProfileType.WORK:
        return get_work_policy()
    elif profile == ProfileType.FORENSIC:
        return get_forensic_policy()
    else:
        return get_personal_policy()


# ══════════════════════════════════════════════════════════════════════════════
# POLICY ENFORCEMENT
# ══════════════════════════════════════════════════════════════════════════════

class PolicyEnforcer:
    """
    Enforces security policies on operations.
    
    Usage:
        enforcer = PolicyEnforcer(policy)
        enforcer.validate_password(password)
        enforcer.validate_algorithm(algorithm)
        enforcer.validate_scrypt_params(n, r, p)
    """
    
    def __init__(self, policy: SecurityPolicy):
        """Initialize with a security policy."""
        self.policy = policy
    
    def validate_password(self, password: str) -> None:
        """
        Validate password against policy.
        
        Raises:
            PolicyViolationError: If password doesn't meet requirements
        """
        errors = []
        
        if len(password) < self.policy.min_password_length:
            errors.append(
                f"Password must be at least {self.policy.min_password_length} characters"
            )
        
        if self.policy.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.policy.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.policy.require_digits and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
        
        if self.policy.require_special:
            special = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
            if not any(c in special for c in password):
                errors.append("Password must contain at least one special character")
        
        if errors:
            raise PolicyViolationError("password", "; ".join(errors))
    
    def validate_algorithm(self, algorithm: Algorithm) -> None:
        """
        Validate algorithm against policy.
        
        Raises:
            PolicyViolationError: If algorithm is not allowed
        """
        if algorithm not in self.policy.allowed_algorithms:
            allowed = ", ".join(a.name for a in self.policy.allowed_algorithms)
            raise PolicyViolationError(
                "algorithm",
                f"{algorithm.name} not allowed. Allowed: {allowed}"
            )
    
    def validate_scrypt_params(self, n: int, r: int, p: int) -> None:
        """
        Validate scrypt parameters against policy.
        
        Raises:
            PolicyViolationError: If params don't meet minimums
        """
        if n < self.policy.min_scrypt_n:
            raise PolicyViolationError(
                "scrypt_n",
                f"scrypt N must be at least {self.policy.min_scrypt_n}"
            )
        
        if r < self.policy.min_scrypt_r:
            raise PolicyViolationError(
                "scrypt_r",
                f"scrypt r must be at least {self.policy.min_scrypt_r}"
            )
        
        if p < self.policy.min_scrypt_p:
            raise PolicyViolationError(
                "scrypt_p",
                f"scrypt p must be at least {self.policy.min_scrypt_p}"
            )
    
    def validate_chunk_size(self, chunk_size: int) -> None:
        """Validate chunk size against policy."""
        if chunk_size < self.policy.min_chunk_size:
            raise PolicyViolationError(
                "chunk_size",
                f"Chunk size must be at least {self.policy.min_chunk_size}"
            )
        
        if chunk_size > self.policy.max_chunk_size:
            raise PolicyViolationError(
                "chunk_size",
                f"Chunk size must be at most {self.policy.max_chunk_size}"
            )
    
    def check_setting_locked(self, setting: str) -> bool:
        """Check if a setting is locked by policy."""
        return setting in self.policy.locked_settings
    
    def modify_setting(self, setting: str, value: Any) -> None:
        """
        Attempt to modify a setting.
        
        Raises:
            LockedSettingError: If setting is locked
        """
        if self.check_setting_locked(setting):
            raise LockedSettingError(setting)


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class ConfigManager:
    """
    Manages application configuration.
    
    Supports:
    - Loading/saving config files
    - Profile switching
    - Setting validation
    
    Usage:
        config = ConfigManager()
        config.load()
        config.set_profile(ProfileType.WORK)
        config.save()
    """
    
    def __init__(self, path: Optional[Path] = None):
        """
        Initialize config manager.
        
        Args:
            path: Path to config file. If None, uses default.
        """
        if path is None:
            path = Path.home() / ".codificator" / CONFIG_FILENAME
        
        self.path = normalize_path(path)
        self.config = self._get_default_config()
        self._enforcer: Optional[PolicyEnforcer] = None
    
    def _get_default_config(self) -> AppConfig:
        """Get default configuration."""
        return AppConfig(
            profile=ProfileType.PERSONAL,
            policy=get_personal_policy(),
            default_output_dir=None,
            confirm_overwrite=True,
            show_progress=True,
            max_workers=DEFAULT_MAX_WORKERS,
            continue_on_error=True,
            audit_log_path=None,
            audit_max_size=DEFAULT_AUDIT_MAX_SIZE,
            keyring_path=None,
            auto_lock_timeout=300,
        )
    
    @property
    def enforcer(self) -> PolicyEnforcer:
        """Get policy enforcer for current config."""
        if self._enforcer is None:
            self._enforcer = PolicyEnforcer(self.config.policy)
        return self._enforcer
    
    def load(self) -> None:
        """Load configuration from file."""
        if not self.path.exists():
            return
        
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse profile
            profile_name = data.get("profile", "personal")
            try:
                profile = ProfileType(profile_name)
            except:
                profile = ProfileType.PERSONAL
            
            # Get base policy for profile
            policy = get_policy_for_profile(profile)
            
            # Apply custom policy settings
            policy_data = data.get("policy", {})
            if policy_data:
                for key, value in policy_data.items():
                    if hasattr(policy, key):
                        # Handle special types
                        if key == "allowed_algorithms":
                            value = [Algorithm(v) for v in value]
                        elif key == "default_algorithm":
                            value = Algorithm(value)
                        elif key == "default_compression":
                            value = CompressionType(value)
                        setattr(policy, key, value)
            
            # Build config
            self.config = AppConfig(
                profile=profile,
                policy=policy,
                default_output_dir=data.get("default_output_dir"),
                confirm_overwrite=data.get("confirm_overwrite", True),
                show_progress=data.get("show_progress", True),
                max_workers=data.get("max_workers", DEFAULT_MAX_WORKERS),
                continue_on_error=data.get("continue_on_error", True),
                audit_log_path=data.get("audit_log_path"),
                audit_max_size=data.get("audit_max_size", DEFAULT_AUDIT_MAX_SIZE),
                keyring_path=data.get("keyring_path"),
                auto_lock_timeout=data.get("auto_lock_timeout", 300),
            )
            
            self._enforcer = None  # Reset enforcer
            
        except Exception as e:
            raise InvalidConfigError(f"Failed to load config: {e}")
    
    def save(self) -> None:
        """Save configuration to file."""
        ensure_parent_exists(self.path)
        
        # Serialize policy
        policy_data = {
            "name": self.config.policy.name,
            "min_password_length": self.config.policy.min_password_length,
            "require_uppercase": self.config.policy.require_uppercase,
            "require_lowercase": self.config.policy.require_lowercase,
            "require_digits": self.config.policy.require_digits,
            "require_special": self.config.policy.require_special,
            "allowed_algorithms": [a.value for a in self.config.policy.allowed_algorithms],
            "default_algorithm": self.config.policy.default_algorithm.value,
            "min_scrypt_n": self.config.policy.min_scrypt_n,
            "min_scrypt_r": self.config.policy.min_scrypt_r,
            "min_scrypt_p": self.config.policy.min_scrypt_p,
            "force_chunking": self.config.policy.force_chunking,
            "min_chunk_size": self.config.policy.min_chunk_size,
            "max_chunk_size": self.config.policy.max_chunk_size,
            "allow_compression": self.config.policy.allow_compression,
            "default_compression": self.config.policy.default_compression.value,
            "paranoid_mode": self.config.policy.paranoid_mode,
            "log_plaintext_hash": self.config.policy.log_plaintext_hash,
            "locked_settings": self.config.policy.locked_settings,
        }
        
        data = {
            "profile": self.config.profile.value,
            "policy": policy_data,
            "default_output_dir": self.config.default_output_dir,
            "confirm_overwrite": self.config.confirm_overwrite,
            "show_progress": self.config.show_progress,
            "max_workers": self.config.max_workers,
            "continue_on_error": self.config.continue_on_error,
            "audit_log_path": self.config.audit_log_path,
            "audit_max_size": self.config.audit_max_size,
            "keyring_path": self.config.keyring_path,
            "auto_lock_timeout": self.config.auto_lock_timeout,
        }
        
        with open(self.path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    def set_profile(self, profile: ProfileType) -> None:
        """
        Switch to a different profile.
        
        This resets the policy to the profile's default.
        """
        self.config.profile = profile
        self.config.policy = get_policy_for_profile(profile)
        self._enforcer = None
    
    def get_profile_info(self) -> Dict[str, Any]:
        """Get current profile information."""
        return {
            "profile": self.config.profile.value,
            "policy_name": self.config.policy.name,
            "min_password_length": self.config.policy.min_password_length,
            "allowed_algorithms": [a.name for a in self.config.policy.allowed_algorithms],
            "default_algorithm": self.config.policy.default_algorithm.name,
            "paranoid_mode": self.config.policy.paranoid_mode,
            "locked_settings": self.config.policy.locked_settings,
        }
    
    def reset_to_defaults(self) -> None:
        """Reset configuration to defaults."""
        self.config = self._get_default_config()
        self._enforcer = None


# Global config instance
_global_config: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """Get the global configuration manager."""
    global _global_config
    if _global_config is None:
        _global_config = ConfigManager()
        try:
            _global_config.load()
        except:
            pass
    return _global_config


def get_policy() -> SecurityPolicy:
    """Get the current security policy."""
    return get_config().config.policy


def get_enforcer() -> PolicyEnforcer:
    """Get the current policy enforcer."""
    return get_config().enforcer
