#!/usr/bin/env python3
"""Simple HTTP server for testing HTTP injection"""

import socket
import threading
import time

def handle_request(client_socket, addr):
    """Handle a single HTTP request"""
    try:
        # Receive request
        request = client_socket.recv(1024).decode('utf-8')
        print(f"Request from {addr}: {request.split()[0]} {request.split()[1] if len(request.split()) > 1 else '/'}")
        
        # Simple HTML response
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
</head>
<body>
    <h1>Hello from Test Server!</h1>
    <p>This is a simple test page for HTTP injection testing.</p>
    <p>Current time: """ + time.strftime('%Y-%m-%d %H:%M:%S') + """</p>
</body>
</html>"""
        
        # HTTP response
        response = f"""HTTP/1.1 200 OK\r
Content-Type: text/html\r
Content-Length: {len(html_content)}\r
Connection: close\r
\r
{html_content}"""
        
        # Send response in one go to avoid fragmentation
        client_socket.send(response.encode('utf-8'))
        client_socket.close()
        
    except Exception as e:
        print(f"Error handling request: {e}")
        client_socket.close()

def start_server(host='0.0.0.0', port=8000):
    """Start the simple HTTP server"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"🚀 Simple HTTP server started on {host}:{port}")
        print(f"💡 Test by browsing to: http://192.168.0.125:{port}/")
        print(f"🛑 Press Ctrl+C to stop")
        
        while True:
            client_socket, addr = server_socket.accept()
            # Handle each request in a separate thread
            thread = threading.Thread(target=handle_request, args=(client_socket, addr))
            thread.daemon = True
            thread.start()
            
    except KeyboardInterrupt:
        print("\n🛑 Stopping server...")
    except Exception as e:
        print(f"❌ Server error: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server() 