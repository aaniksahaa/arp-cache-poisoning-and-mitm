#!/usr/bin/env python3
"""
User Configuration Template
Copy this file and modify the values for your network
"""

# Network Configuration
NETWORK_INTERFACE = "wlp2s0"  # Your network interface
NETWORK_RANGE = "192.168.0.0/24"  # Your network range

# Attack Target Configuration
VICTIM_IP = "192.168.0.105"
VICTIM_MAC = "9a:be:d0:91:f3:76"

GATEWAY_IP = "192.168.0.1"
GATEWAY_MAC = "40:ed:00:4a:67:44"

# Custom injection payload
CUSTOM_INJECTION = b"<h1>Custom Attack Payload</h1>"

# Safety settings
REQUIRE_CONFIRMATION = True
MAX_ATTACK_DURATION = 1800  # 30 minutes

# Defense settings
ENABLE_EMAIL_ALERTS = False
NOTIFICATION_EMAIL = None  # "admin@example.com"
