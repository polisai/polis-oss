import http.server
import socketserver
import json
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

PORT = 8081


class MockLLMHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length_str = self.headers.get("Content-Length")
        if content_length_str:
            content_length = int(content_length_str)
            post_data = self.rfile.read(content_length)
            logger.info(f"Received POST request to {self.path}")
            logger.info(f"Body: {post_data.decode('utf-8')}")
        else:
            logger.info(f"Received POST request to {self.path} (no body)")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        response = {
            "id": "mock-response",
            "object": "chat.completion",
            "created": 1677652288,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "This is a mock response from the upstream server.",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
        }
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def do_GET(self):
        logger.info(f"Received GET request to {self.path}")
        super().do_GET()


if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), MockLLMHandler) as httpd:
        logger.info(f"Mock LLM Server serving at port {PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down server...")
            httpd.server_close()
