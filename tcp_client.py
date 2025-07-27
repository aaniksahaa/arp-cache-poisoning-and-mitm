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

# Configuration
SERVER_IP = "192.168.68.125"  # Change this to your server's IP address
SERVER_PORT = 9999

def receive_messages(client, client_name="Client"):
    """Thread to receive messages from server"""
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            if not message:
                break
            print(f"\n📨 Server: {message}")
            
            # Check if message was intercepted (both old and new formats)
            if "[MITM:" in message or "[M:" in message:
                print("🚨 MESSAGE WAS INTERCEPTED AND MODIFIED! 🚨")
                
        except Exception as e:
            print(f"❌ Receive error: {e}")
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
            timestamped = f"[{time.strftime('%H:%M:%S')}]: {message}"
            client.send(timestamped.encode('utf-8'))
            print(f"📤 Sent ({len(timestamped)} bytes): '{timestamped}'")
            
        except Exception as e:
            print(f"❌ Send error: {e}")
            break

def run_client():
    """Main client function with bidirectional communication"""
    
    # Use default client name
    client_name = "Client"
    
    print("💻 Bidirectional TCP Client Started")
    print("=" * 50)
    print(f"Connecting to: {SERVER_IP}:{SERVER_PORT}")
    print(f"Client Name: {client_name}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(10)  # 10 second timeout for connection
        client.connect((SERVER_IP, SERVER_PORT))
        client.settimeout(None)  # Remove timeout for normal operation
        
        print(f"✅ Connected to server!")
        print("💡 Type messages to send (type 'quit' to exit)")
        print("🎯 Try words like 'hello', 'hi', 'secret' to test interception")
        print("🔍 Watch for [M:X→Y] markers indicating MITM modification")
        print("=" * 50)
        
        # Start threads for bidirectional communication
        receive_thread = threading.Thread(target=receive_messages, args=(client, client_name), daemon=True)
        send_thread = threading.Thread(target=send_messages, args=(client, client_name), daemon=True)
        
        receive_thread.start()
        send_thread.start()
        
        # Keep main thread alive and monitor connection health
        consecutive_errors = 0
        while True:
            try:
                time.sleep(1)
                
                # Check if send thread is still alive
                if not send_thread.is_alive():
                    print("📡 Send thread stopped, exiting...")
                    break
                    
                # Check if receive thread is still alive
                if not receive_thread.is_alive():
                    print("📡 Receive thread stopped, exiting...")
                    break
                    
                consecutive_errors = 0
                
            except KeyboardInterrupt:
                print("\n🔌 Closing connection...")
                break
            except Exception as e:
                consecutive_errors += 1
                print(f"⚠️ Connection issue #{consecutive_errors}: {e}")
                if consecutive_errors > 3:
                    print("❌ Too many connection errors, exiting...")
                    break
                    
    except ConnectionRefusedError:
        print(f"❌ Could not connect to {SERVER_IP}:{SERVER_PORT}")
        print("💡 Make sure the server is running on that address")
        print(f"🔧 To change server IP, edit SERVER_IP = \"{SERVER_IP}\" at the top of this file")
    except socket.timeout:
        print(f"❌ Connection timeout to {SERVER_IP}:{SERVER_PORT}")
        print("💡 Check if the server is reachable at that address")
        print(f"🔧 To change server IP, edit SERVER_IP = \"{SERVER_IP}\" at the top of this file")
    except Exception as e:
        print(f"❌ Error: {e}")
        print(f"🔧 To change server IP, edit SERVER_IP = \"{SERVER_IP}\" at the top of this file")
    finally:
        try:
            client.close()
        except:
            pass
        print("✅ Client stopped")

def test_interception_keywords():
    """Send predefined test messages to test interception"""
    
    test_messages = [
        "hello world",
        "hi there", 
        "secret message",
        "password 123456",
        "normal message",
        "Hello from client!",
        "Hi, how are you?",
        "This is a secret",
        "My password is test123",
        "hello again",  # Test multiple hello modifications
        "hi once more"  # Test multiple hi modifications
    ]
    
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(10)
        client.connect((SERVER_IP, SERVER_PORT))
        client.settimeout(5)  # 5 second timeout for responses
        print(f"✅ Connected! Sending test messages...")
        
        successful_modifications = 0
        
        for i, msg in enumerate(test_messages, 1):
            print(f"\n📤 [{i}/{len(test_messages)}] Sending: '{msg}'")
            
            # Add timestamp like the real client
            timestamped = f"[{time.strftime('%H:%M:%S')}] TestClient: {msg}"
            client.send(timestamped.encode('utf-8'))
            print(f"📊 Sent {len(timestamped)} bytes")
            
            # Try to receive response
            try:
                response = client.recv(1024).decode('utf-8')
                print(f"📥 Received ({len(response)} bytes): '{response}'")
                
                if "[MITM:" in response or "[M:" in response:
                    print("🚨 INTERCEPTED AND MODIFIED!")
                    successful_modifications += 1
                else:
                    print("✅ Normal response (no modification detected)")
                    
            except socket.timeout:
                print("⏰ No response received (timeout)")
            except Exception as e:
                print(f"❌ Error receiving response: {e}")
            
            time.sleep(2)  # Wait between messages
        
        print(f"\n📊 Test Summary:")
        print(f"   Total messages: {len(test_messages)}")
        print(f"   Modifications detected: {successful_modifications}")
        print(f"   Success rate: {(successful_modifications/len(test_messages)*100):.1f}%")
            
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        try:
            client.close()
        except:
            pass

if __name__ == "__main__":
    print("🎯 Bidirectional TCP Socket Interception Test Client")
    run_client() 