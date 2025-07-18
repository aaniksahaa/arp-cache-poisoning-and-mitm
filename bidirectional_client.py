#!/usr/bin/env python3
"""
Bidirectional TCP Client for Testing Socket Interception
Matches the threading pattern from the user's example
Run this on the client device (e.g., Windows laptop)
"""

import socket
import threading
import time
import sys

def receive_messages(client, client_name="Client"):
    """Thread to receive messages from server"""
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            if not message:
                break
            print(f"\n📨 Server: {message}")
            
            # Check if message was intercepted
            if "[MITM:" in message:
                print("🚨 MESSAGE WAS INTERCEPTED AND MODIFIED! 🚨")
                
        except:
            break

def send_messages(client, client_name="Client"):
    """Thread to send messages to server"""
    while True:
        try:
            message = input(f"🧑 {client_name}: ")
            if not message:
                continue
            if message.lower() in ['quit', 'exit', 'q']:
                print("👋 Disconnecting...")
                break
                
            # Add timestamp to message
            timestamped = f"[{time.strftime('%H:%M:%S')}] {client_name}: {message}"
            client.send(timestamped.encode('utf-8'))
            
        except Exception as e:
            print(f"❌ Send error: {e}")
            break

def run_client():
    """Main client function with bidirectional communication"""
    
    # Get server IP
    server_ip = input("Enter server IP (e.g., 192.168.0.105): ").strip()
    if not server_ip:
        print("❌ No IP address provided")
        return
    
    server_port = 9999
    client_name = input("Enter your name (default: Client): ").strip() or "Client"
    
    print("💻 Bidirectional TCP Client Started")
    print("=" * 50)
    print(f"Connecting to: {server_ip}:{server_port}")
    print(f"Client Name: {client_name}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_ip, server_port))
        print(f"✅ Connected to server!")
        print("💡 Type messages to send (type 'quit' to exit)")
        print("🎯 Try words like 'hello', 'hi', 'secret' to test interception")
        print("=" * 50)
        
        # Start threads for bidirectional communication
        receive_thread = threading.Thread(target=receive_messages, args=(client, client_name), daemon=True)
        send_thread = threading.Thread(target=send_messages, args=(client, client_name), daemon=True)
        
        receive_thread.start()
        send_thread.start()
        
        # Keep main thread alive
        while True:
            try:
                time.sleep(1)
                # Check if send thread is still alive
                if not send_thread.is_alive():
                    break
            except KeyboardInterrupt:
                print("\n🔌 Closing connection...")
                break
                
    except ConnectionRefused:
        print(f"❌ Could not connect to {server_ip}:{server_port}")
        print("💡 Make sure the server is running")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        try:
            client.close()
        except:
            pass
        print("✅ Client stopped")

def test_interception_keywords():
    """Send predefined test messages to test interception"""
    server_ip = input("Enter server IP: ").strip()
    if not server_ip:
        return
    
    test_messages = [
        "hello world",
        "hi there",
        "secret message",
        "password 123456",
        "normal message",
        "Hello from client!",
        "Hi, how are you?",
        "This is a secret",
        "My password is test123"
    ]
    
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_ip, 9999))
        print(f"✅ Connected! Sending test messages...")
        
        for i, msg in enumerate(test_messages, 1):
            print(f"\n📤 [{i}/{len(test_messages)}] Sending: '{msg}'")
            
            # Add timestamp like the real client
            timestamped = f"[{time.strftime('%H:%M:%S')}] TestClient: {msg}"
            client.send(timestamped.encode('utf-8'))
            
            # Try to receive response
            try:
                response = client.recv(1024).decode('utf-8')
                print(f"📥 Received: '{response}'")
                
                if "[MITM:" in response:
                    print("🚨 INTERCEPTED AND MODIFIED!")
                    
            except socket.timeout:
                print("⏰ No response received")
            
            time.sleep(2)  # Wait between messages
            
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        try:
            client.close()
        except:
            pass

if __name__ == "__main__":
    print("🎯 Bidirectional TCP Socket Interception Test Client")
    print("1. Interactive bidirectional mode (like your example)")
    print("2. Auto-test mode (predefined messages)")
    
    choice = input("Choose mode (1 or 2): ").strip()
    
    if choice == "2":
        test_interception_keywords()
    else:
        run_client() 