# TCP Socket Interception Testing Guide

## 🎯 Complete Setup for Testing Socket Interception

This guide shows you the **simplest way** to test TCP socket interception between Ubuntu and Windows laptops.

## 📋 Requirements

### Hardware Setup
- **3 laptops**:
  - **Attacker Laptop**: Ubuntu with Python (your current machine)
  - **Ubuntu Laptop**: Will run the server
  - **Windows Laptop**: Will run the client
- All connected to **same WiFi network**

### Software Requirements

#### On Attacker Laptop (Ubuntu):
```bash
# Already installed from existing codebase
sudo apt install python3 python3-pip iptables
pip3 install scapy netfilterqueue
```

#### On Ubuntu Server Laptop:
```bash
sudo apt install python3
# Copy test_server.py to this machine
```

#### On Windows Client Laptop:
```bash
# Install Python 3.x from python.org
# Copy test_client.py to this machine
```

## 🚀 Step-by-Step Testing

### **Step 1: Network Discovery**

On the **attacker laptop**, discover all devices:

```bash
# Find all devices on your network
python3 network_device_scanner.py

# Example output:
# 192.168.0.105 - 9a:be:d0:91:f3:76 (Ubuntu Laptop)
# 192.168.0.150 - 4c:32:75:9e:82:1a (Windows Laptop)
# 192.168.0.1   - 60:a4:b7:a9:77:05 (Router)
```

### **Step 2: Configure Attack**

Edit `user_config.py` with discovered IPs:

```python
# Network Configuration
NETWORK_INTERFACE = "wlp2s0"  # Your WiFi interface
NETWORK_RANGE = "192.168.0.0/24"

# Attack Target Configuration  
VICTIM_IP = "192.168.0.105"      # Ubuntu server laptop
VICTIM_MAC = "9a:be:d0:91:f3:76" # Ubuntu server MAC

GATEWAY_IP = "192.168.0.1"       # Your router
GATEWAY_MAC = "60:a4:b7:a9:77:05" # Router MAC
```

### **Step 3: Start Server (Ubuntu Laptop)**

On the **Ubuntu laptop**, run:

```bash
python3 test_server.py
```

You should see:
```
🖥️  TCP Test Server Started
========================================
Listening on: 0.0.0.0:9999
Time: 2024-01-20 15:30:45
========================================
Waiting for connections...
(Press Ctrl+C to stop)
```

### **Step 4: Test Normal Connection First**

On the **Windows laptop**, test normal connection:

```bash
python test_client.py
```

Enter the Ubuntu server IP when prompted, then type some messages:
```
Enter Ubuntu server IP: 192.168.0.105
💻 TCP Test Client Started
✅ Connected to server!
📝 Enter message: hello world
📤 Sent: 'hello world'
📥 Server replied: 'Server reply at 15:31:20: HELLO WORLD'
```

**This should work normally without interception.**

### **Step 5: Start Interception Attack**

On the **attacker laptop**, start the interception:

```bash
sudo python3 tcp_socket_interceptor.py
```

You should see:
```
🎯 TCP SOCKET INTERCEPTION ATTACK CONFIGURATION
============================================================
Interface:        wlp2s0
Target IP:        192.168.0.105
Target MAC:       9a:be:d0:91:f3:76
Gateway IP:       192.168.0.1
Gateway MAC:      60:a4:b7:a9:77:05
Socket Ports:     [9999, 8080, 12345]
Modification:     Enabled
============================================================
🤔 Proceed with socket interception attack? (yes/no): yes

[ATTACK] 🚀 Starting ARP poisoning & TCP socket interception attack
[ARP-POISON] 🎯 Starting continuous ARP poisoning
[MITM] 🚀 TCP Socket interception system started
[MITM] 📡 Monitoring socket traffic on ports: [9999, 8080, 12345]
```

### **Step 6: Test Interception**

Now on the **Windows laptop**, send test messages again:

```bash
📝 Enter message: hello world
📤 Sent: 'hello world'
📥 Server replied: 'Server reply at 15:33:45: [MITM_MODIFIED] INTERCEPTED_HELLO WORLD'
🚨 MESSAGE WAS INTERCEPTED AND MODIFIED! 🚨
```

**Perfect! The message was intercepted and modified!**

### **Step 7: Test Different Keywords**

Try these test messages to see different modifications:

```bash
📝 Enter message: secret data
📤 Sent: 'secret data'
📥 Server replied: '[MITM_MODIFIED] INTERCEPTED_SECRET data'

📝 Enter message: password 123
📤 Sent: 'password 123'  
📥 Server replied: '[MITM_MODIFIED] HACKED_PASSWORD_123'

📝 Enter message: normal message
📤 Sent: 'normal message'
📥 Server replied: 'Server reply at 15:34:20: NORMAL MESSAGE'
```

### **Step 8: Monitor Attack Logs**

On the **attacker laptop**, check the logs:

```bash
tail -f tcp_socket_attack.log
```

You should see:
```
[SOCKET-TRAFFIC] 🎯 192.168.0.150:52341 -> 192.168.0.105:9999
[SOCKET-MESSAGE] 📨 Intercepted: 'hello world'
[SOCKET-MODIFY] 🔧 Original: 'hello world'
[SOCKET-MODIFY] 🔧 Modified: '[MITM_MODIFIED] INTERCEPTED_HELLO world'
[SOCKET-MODIFY] ✅ Message successfully modified!
```

## 🎯 Alternative Test Methods

### **Option 2: Java Socket Test**

If you want to test with Java instead:

#### **Java Server (Ubuntu Laptop):**
```java
import java.io.*;
import java.net.*;

public class SocketServer {
    public static void main(String[] args) throws IOException {
        ServerSocket server = new ServerSocket(9999);
        System.out.println("Java Server listening on port 9999...");
        
        while (true) {
            Socket client = server.accept();
            BufferedReader in = new BufferedReader(
                new InputStreamReader(client.getInputStream()));
            PrintWriter out = new PrintWriter(
                client.getOutputStream(), true);
            
            String message = in.readLine();
            System.out.println("Received: " + message);
            
            out.println("Java Server Response: " + message.toUpperCase());
            client.close();
        }
    }
}
```

#### **Java Client (Windows Laptop):**
```java
import java.io.*;
import java.net.*;

public class SocketClient {
    public static void main(String[] args) throws IOException {
        Socket socket = new Socket("192.168.0.105", 9999);
        
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(
            new InputStreamReader(socket.getInputStream()));
        
        out.println("Hello from Java client!");
        String response = in.readLine();
        System.out.println("Server replied: " + response);
        
        socket.close();
    }
}
```

### **Option 3: Netcat Test**

For the simplest possible test:

#### **Ubuntu Laptop:**
```bash
nc -l -p 9999
```

#### **Windows Laptop:**
```bash
nc 192.168.0.105 9999
```

Then type messages - they should be intercepted the same way!

## 🔧 Customizing Interception

To modify what gets intercepted, edit the `modify_socket_message()` function in `tcp_socket_interceptor.py`:

```python
def modify_socket_message(original_message):
    message = original_message
    
    # Add your custom modifications here
    if "login" in message.lower():
        message = message.replace(message.strip(), "FAKE_CREDENTIALS")
    
    if "credit" in message.lower():
        message = message.replace("credit", "STOLEN")
    
    # Add your own patterns
    return message
```

## 🛑 Stopping the Attack

1. **Stop the interceptor**: Press `Ctrl+C` on the attacker laptop
2. **Cleanup happens automatically**: ARP tables restored, IP forwarding disabled
3. **Test normal connection**: The socket communication should work normally again

## 📊 Expected Results

### **Without Attack:**
```
Client: "hello world"
Server: "Server reply: HELLO WORLD"
```

### **With Attack:**
```
Client: "hello world" 
→ [INTERCEPTED & MODIFIED] 
→ Server receives: "[MITM_MODIFIED] INTERCEPTED_HELLO world"
Server: "Server reply: [MITM_MODIFIED] INTERCEPTED_HELLO WORLD"
```

## 🚨 Troubleshooting

### **Connection Issues:**
```bash
# Check if devices can ping each other
ping 192.168.0.105  # From Windows to Ubuntu
ping 192.168.0.150  # From Ubuntu to Windows
```

### **Permission Issues:**
```bash
# Make sure to run interceptor as root
sudo python3 tcp_socket_interceptor.py
```

### **Port Issues:**
```bash
# Check if port 9999 is available
netstat -an | grep 9999
```

### **Network Interface Issues:**
```bash
# Find your correct WiFi interface
ip addr show
iwconfig
```

This setup demonstrates that **any unencrypted TCP socket communication can be intercepted and modified** using ARP poisoning, regardless of whether it's Java, Python, C++, or any other language - they all use the same underlying TCP protocol! 