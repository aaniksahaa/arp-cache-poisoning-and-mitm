#!/usr/bin/env python3
import socket
import threading
import time

def receive_messages(client):
   while True:
       try:
           message = client.recv(1024).decode('utf-8')
           if not message:
               break
           print(f"\n📨 Client: {message}")
       except:
           break

def send_messages(client):
   while True:
       try:
           message = input("🧑 You: ")
           if not message:
               continue
           timestamped = f"[{time.strftime('%H:%M:%S')}]: {message}"
           client.send(timestamped.encode('utf-8'))
       except:
           break

def run_server():
   server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   server.bind(('0.0.0.0', 9999))
   server.listen(1)
  
   print("🖥️  Server listening on port 9999...")
   client, addr = server.accept()
   print(f"📱 Connection from {addr}")

   # Start threads for bidirectional communication
   threading.Thread(target=receive_messages, args=(client,), daemon=True).start()
   threading.Thread(target=send_messages, args=(client,), daemon=True).start()

   # Keep main thread alive
   while True:
       try:
           time.sleep(1)
       except KeyboardInterrupt:
           print("\n🔌 Closing connection...")
           client.close()
           break

if __name__ == "__main__":
   run_server()

