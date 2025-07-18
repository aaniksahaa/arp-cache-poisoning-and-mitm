#!/usr/bin/env python3
"""
Simple TCP Server for Testing Socket Interception
Run this on Ubuntu laptop (server side)
"""

import socket
import time
import threading

def handle_client(client, addr):
    """Handle individual client connections"""
    print(f"📱 New connection from {addr[0]}:{addr[1]}")
    
    try:
        while True:
            # Receive message
            message = client.recv(1024).decode('utf-8')
            if not message:
                break
                
            print(f"📨 Received from {addr[0]}: '{message.strip()}'")
            
            # Send response back
            timestamp = time.strftime('%H:%M:%S')
            response = f"Server reply at {timestamp}: {message.upper()}"
            client.send(response.encode('utf-8'))
            print(f"📤 Sent to {addr[0]}: '{response}'")
            
    except Exception as e:
        print(f"❌ Error with {addr[0]}: {e}")
    finally:
        client.close()
        print(f"🔌 Disconnected from {addr[0]}")

def run_server():
    """Main server function"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind to all interfaces on port 9999
    server.bind(('0.0.0.0', 9999))
    server.listen(5)
    
    print("🖥️  TCP Test Server Started")
    print("=" * 40)
    print(f"Listening on: 0.0.0.0:9999")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 40)
    print("Waiting for connections...")
    print("(Press Ctrl+C to stop)")
    
    try:
        while True:
            client, addr = server.accept()
            
            # Handle each client in a separate thread
            client_thread = threading.Thread(
                target=handle_client, 
                args=(client, addr)
            )
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        print("\n🛑 Server shutting down...")
    finally:
        server.close()
        print("✅ Server stopped")

if __name__ == "__main__":
    run_server() 