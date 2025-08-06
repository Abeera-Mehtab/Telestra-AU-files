# www.theforage.com - Telstra Cyber Task 3
# Telstra Security Operations - Firewall Server Handler for Spring4Shell (CVE-2022-22965)

from http.server import BaseHTTPRequestHandler, HTTPServer

host = "localhost"
port = 8000

# Define suspicious headers and values from known Spring4Shell exploit patterns
MALICIOUS_HEADERS = {
    "suffix": "%>//",
    "c1": "Runtime",
    "c2": "<%",
    "DNT": "1",
    "Content-Type": "application/x-www-form-urlencoded"
}

SUSPICIOUS_PATH = "/tomcatwar.jsp"

def block_request(self):
    print("[!] Potential Spring4Shell exploit detected. Blocking request from:", self.client_address)
    self.send_response(403)
    self.send_header("Content-Type", "text/plain")
    self.end_headers()
    self.wfile.write(b"403 Forbidden: Request blocked due to potential exploit attempt.")

def handle_request(self):
    # Check for suspicious path and POST method
    if self.path == SUSPICIOUS_PATH and self.command == "POST":
        print("[!] Exploit pattern: Suspicious path '/tomcatwar.jsp' with POST method detected.")
        return block_request(self)

    # Check for known malicious headers
    for key, expected_value in MALICIOUS_HEADERS.items():
        header_value = self.headers.get(key)
        if header_value and expected_value in header_value:
            print(f"[!] Exploit pattern: Malicious header '{key}: {header_value}' detected.")
            return block_request(self)

    # If no malicious patterns detected, allow the request
    self.send_response(200)
    self.send_header("Content-Type", "application/json")
    self.end_headers()
    self.wfile.write(b'{"success": true, "message": "Request processed successfully."}')

class ServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        handle_request(self)

    def do_POST(self):
        handle_request(self)

if __name__ == "__main__":
    server = HTTPServer((host, port), ServerHandler)
    print("[+] Telstra Firewall Server Started")
    print(f"[+] Listening on {host}:{port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutdown signal received. Terminating server.")
    finally:
        server.server_close()
        print("[+] Server terminated. Exiting...")
