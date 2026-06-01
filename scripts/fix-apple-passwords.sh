#!/usr/bin/env bash
set -euo pipefail

echo "Forcefully terminating Apple Passwords and AuthenticationServices daemons..."

killall -9 Passwords 2>/dev/null
killall -9 com.apple.Passwords.MenuBarExtra 2>/dev/null
killall -9 AuthenticationServicesAgent 2>/dev/null
killall -9 CredentialProviderExtensionHelper 2>/dev/null
killall -9 AutoFillPanelService 2>/dev/null

echo "Done! The system will automatically restart these services when you open the Passwords app."
