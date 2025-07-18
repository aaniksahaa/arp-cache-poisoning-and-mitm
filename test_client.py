#!/usr/bin/env python3
"""
Simple TCP Client for Testing Socket Interception
Run this on Windows laptop (client side)
"""

import socket
import time
import sys

def run_client():
    """Main client function"""
    # You need to replace this with the Ubuntu laptop's IP address
    server_ip = input("Enter Ubuntu server IP (e.g., 192.168.0.105): ").strip()
    if not server_ip:
        print("❌ No IP address provided")
        return
    
    server_port = 9999
    
    print("💻 TCP Test Client Started")
    print("=" * 40)
    print(f"Connecting to: {server_ip}:{server_port}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 40)
    
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_ip, server_port))
        print(f"✅ Connected to server!")
        print("💡 Type messages to send (type 'quit' to exit)")
        print("🎯 Try words like 'hello', 'password', 'secret' to test interception")
        print("-" * 40)
        
        while True:
            # Get message from user
            message = input("📝 Enter message: ").strip()
            
            if message.lower() in ['quit', 'exit', 'q']:
                print("👋 Disconnecting...")
                break
            
            if not message:
                continue
                
            # Send message to server
            client.send(message.encode('utf-8'))
            print(f"📤 Sent: '{message}'")
            
            # Receive response from server
            response = client.recv(1024).decode('utf-8')
            print(f"📥 Server replied: '{response}'")
            
            # Check if message was modified
            if "[MITM_MODIFIED]" in response:
                print("🚨 MESSAGE WAS INTERCEPTED AND MODIFIED! 🚨")
            
            print("-" * 40)
            
    except ConnectionRefused:
        print(f"❌ Could not connect to {server_ip}:{server_port}")
        print("💡 Make sure the server is running on the Ubuntu laptop")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        try:
            client.close()
        except:
            pass
        print("✅ Client stopped")

def test_predefined_messages():
    """Send predefined test messages"""
    server_ip = input("Enter Ubuntu server IP: ").strip()
    if not server_ip:
        return
    
    test_messages = [
        "hello world",
        "secret message",
        "password 123456",
        "normal message",
        "Hello from Windows!",
        "Secret data transfer"
    ]
    
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_ip, 9999))
        print(f"✅ Connected! Sending test messages...")
        
        for msg in test_messages:
            print(f"\n📤 Sending: '{msg}'")
            client.send(msg.encode('utf-8'))
            
            response = client.recv(1024).decode('utf-8')
            print(f"📥 Received: '{response}'")
            
            if "[MITM_MODIFIED]" in response:
                print("🚨 INTERCEPTED AND MODIFIED!")
            
            time.sleep(2)  # Wait between messages
            
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        try:
            client.close()
        except:
            pass

if __name__ == "__main__":
    print("🎯 TCP Socket Interception Test Client")
    print("1. Interactive mode")
    print("2. Auto-test mode (predefined messages)")
    
    choice = input("Choose mode (1 or 2): ").strip()
    
    if choice == "2":
        test_predefined_messages()
    else:
        run_client() 