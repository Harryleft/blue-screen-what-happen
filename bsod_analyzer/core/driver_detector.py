"""
Driver detector module.

Identifies problematic drivers based on known issues and patterns.
"""

import json
from pathlib import Path
from typing import Optional, List, Dict

from loguru import logger

from bsod_analyzer.database.models import DriverInfo
from bsod_analyzer.utils.config import get_config


# Known problematic drivers database
KNOWN_BAD_DRIVERS = {
    # Graphics drivers
    "nvlddmkm.sys": {
        "issue": "NVIDIA GPU driver - known to cause BSOD with certain configurations",
        "recommendation": "Update to latest NVIDIA driver or perform clean install",
    },
    "amdkmdag.sys": {
        "issue": "AMD GPU driver - can cause crashes with certain hardware",
        "recommendation": "Update AMD graphics drivers",
    },
    "igdkmd64.sys": {
        "issue": "Intel GPU driver - may cause system instability",
        "recommendation": "Update Intel graphics driver",
    },
    # Network drivers
    "rtwlanu.sys": {
        "issue": "Realtek USB WiFi driver - known stability issues",
        "recommendation": "Update Realtek driver or use alternative WiFi adapter",
    },
    "netr28x.sys": {
        "issue": "Ralink network driver - can cause BSOD",
        "recommendation": "Update or replace network driver",
    },
    # Antivirus/Security
    "avgtdix.sys": {
        "issue": "AVG Antivirus driver - known conflicts",
        "recommendation": "Update AVG or temporarily disable for testing",
    },
    "avghwnda.sys": {
        "issue": "AVG driver component",
        "recommendation": "Update AVG Antivirus",
    },
    "bdss.sys": {
        "issue": "BitDefender security driver",
        "recommendation": "Update BitDefender or check for conflicts",
    },
    "symefa.sys": {
        "issue": "Symantec/Norton driver",
        "recommendation": "Update Norton Security",
    },
    "symevent.sys": {
        "issue": "Symantec event driver",
        "recommendation": "Update or remove Symantec product",
    },
    "epfwwfp.sys": {
        "issue": "ESET firewall driver",
        "recommendation": "Update ESET Security",
    },
    # Storage drivers
    "iaStorA.sys": {
        "issue": "Intel RST driver - can cause BSOD with certain SSDs",
        "recommendation": "Update Intel Rapid Storage Technology driver",
    },
    "iaStorV.sys": {
        "issue": "Intel storage driver",
        "recommendation": "Update Intel RST driver",
    },
    # Virtualization
    "vmm.sys": {
        "issue": "VirtualBox memory manager",
        "recommendation": "Update VirtualBox or disable if not in use",
    },
    "vboxdrv.sys": {
        "issue": "VirtualBox driver",
        "recommendation": "Update VirtualBox",
    },
    "vmci.sys": {
        "issue": "VMware CI driver",
        "recommendation": "Update VMware Workstation",
    },
    # Game/Audio
    "rgl64vk.sys": {
        "issue": "Razer game capture driver",
        "recommendation": "Update Razer software",
    },
    " Nahimic.sys": {
        "issue": "Nahimic audio driver - known BSOD issues",
        "recommendation": "Update or disable Nahimic audio service",
    },
    # Overclocking/Utilities
    "AiCharger.sys": {
        "issue": "ASUS AI Charger driver",
        "recommendation": "Update or remove ASUS AI Suite",
    },
    "AsIO.sys": {
        "issue": "ASUS I/O driver for monitoring",
        "recommendation": "Update ASUS software",
    },
    # Third-party
    "ks.sys": {
        "issue": "Windows kernel streaming - usually third-party filter driver issue",
        "recommendation": "Check audio/video capture software drivers",
    },
}


class DriverDetector:
    """Detects problematic drivers."""

    def __init__(self):
        """Initialize the driver detector."""
        self._known_bad = KNOWN_BAD_DRIVERS
        self._load_custom_database()

    def _load_custom_database(self):
        """Load custom driver database from knowledge folder."""
        config = get_config()
        db_path = Path(__file__).parent.parent / "knowledge" / "known_bad_drivers.json"

        if db_path.exists():
            try:
                with open(db_path, "r", encoding="utf-8") as f:
                    custom_data = json.load(f)
                    self._known_bad.update(custom_data)
                    logger.debug(f"Loaded custom driver database: {db_path}")
            except Exception as e:
                logger.warning(f"Failed to load custom driver database: {e}")

    def is_problematic(self, driver: DriverInfo) -> bool:
        """Check if a driver is known to be problematic."""
        driver_name_lower = driver.name.lower()

        for bad_driver in self._known_bad:
            if bad_driver.lower() in driver_name_lower:
                return True

        return False

    def get_known_issue(self, driver: DriverInfo) -> Optional[str]:
        """Get known issue information for a driver."""
        driver_name_lower = driver.name.lower()

        for bad_driver, info in self._known_bad.items():
            if bad_driver.lower() in driver_name_lower:
                return f"{info['issue']}. {info['recommendation']}"

        return None

    def get_recommendation(self, driver: DriverInfo) -> Optional[str]:
        """Get recommendation for a problematic driver."""
        driver_name_lower = driver.name.lower()

        for bad_driver, info in self._known_bad.items():
            if bad_driver.lower() in driver_name_lower:
                return info["recommendation"]

        return None

    def find_problematic_drivers(self, drivers: List[DriverInfo]) -> List[tuple[DriverInfo, str]]:
        """Find all problematic drivers from a list."""
        problematic = []

        for driver in drivers:
            if self.is_problematic(driver):
                issue = self.get_known_issue(driver)
                problematic.append((driver, issue))

        return problematic

    def is_system_driver(self, driver_name: str) -> bool:
        """Check if driver is a Windows system driver."""
        system_drivers = [
            "ntoskrnl.exe",
            "hal.dll",
            "ntkrnlmp.exe",
            "ntkrnlpa.exe",
            "kernel32.dll",
            "ntdll.dll",
            "win32k.sys",
            "csrss.exe",
            "lsass.exe",
            "services.exe",
            "svchost.exe",
            "explorer.exe",
        ]
        return driver_name.lower() in [d.lower() for d in system_drivers]

    def classify_driver(self, driver: DriverInfo) -> str:
        """Classify driver type."""
        name_lower = driver.name.lower()

        if self.is_system_driver(driver.name):
            return "system"

        type_keywords = {
            "graphics": ["nvlddmkm", "amdkmdag", "igdkmd", "nvidia", "amd", "intel", "gpu"],
            "network": ["net", "wifi", "wlan", "ethernet", "realtek", "broadcom"],
            "storage": ["stor", "disk", "raid", "ahci", "sata"],
            "audio": ["audio", "sound", "hdaudio", "realtek", "conexant"],
            "security": ["antivirus", "firewall", "security", "bdss", "avg", "norton"],
            "virtualization": ["vbox", "vmware", "virtual"],
        }

        for driver_type, keywords in type_keywords.items():
            if any(keyword in name_lower for keyword in keywords):
                return driver_type

        return "unknown"
