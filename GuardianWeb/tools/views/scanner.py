import socket
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.http import JsonResponse
from django.shortcuts import render

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
}

# key: scan_id, value: scan state dict. Shared between the background
# scan thread and the polling requests, so it's guarded by a lock.
SCANS = {}
SCANS_LOCK = threading.Lock()

MAX_PORT_RANGE = 3000


def scan_one_port(host, port, timeout=0.5):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def run_scan(scan_id, host, start, end):
    ports = list(range(start, end + 1))
    total = len(ports)

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_one_port, host, port): port for port in ports}

        for i, future in enumerate(as_completed(futures), start=1):
            port = futures[future]
            try:
                is_open = future.result()
            except Exception:
                is_open = False

            with SCANS_LOCK:
                if is_open:
                    SCANS[scan_id]["open_ports"].append({
                        "port": port,
                        "service": COMMON_PORTS.get(port, "unknown"),
                    })
                    SCANS[scan_id]["open_ports"].sort(key=lambda p: p["port"])
                SCANS[scan_id]["scanned"] = i
                SCANS[scan_id]["progress"] = int(i / total * 100)

    with SCANS_LOCK:
        SCANS[scan_id]["status"] = "done"


def port_scanner(request):
    return render(request, "tools/scanner.html")


def start_scan(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    host = request.POST.get("host", "").strip()

    try:
        start = int(request.POST.get("start", 1))
        end = int(request.POST.get("end", 1024))
    except ValueError:
        return JsonResponse({"error": "Port values must be numbers"}, status=400)

    if not host:
        return JsonResponse({"error": "Host is required"}, status=400)
    if start < 1 or end > 65535 or start > end:
        return JsonResponse({"error": "Invalid port range"}, status=400)
    if end - start + 1 > MAX_PORT_RANGE:
        return JsonResponse({"error": f"Range too large (max {MAX_PORT_RANGE} ports at a time)"}, status=400)

    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror:
        return JsonResponse({"error": f"Could not resolve host: {host}"}, status=400)

    scan_id = uuid.uuid4().hex
    with SCANS_LOCK:
        SCANS[scan_id] = {
            "status": "running",
            "host": host,
            "resolved_ip": resolved_ip,
            "scanned": 0,
            "total": end - start + 1,
            "progress": 0,
            "open_ports": [],
        }

    thread = threading.Thread(target=run_scan, args=(scan_id, resolved_ip, start, end), daemon=True)
    thread.start()

    return JsonResponse({"scan_id": scan_id})


def scan_status(request, scan_id):
    with SCANS_LOCK:
        data = SCANS.get(scan_id)

    if data is None:
        return JsonResponse({"error": "Scan not found"}, status=404)

    return JsonResponse(data)
