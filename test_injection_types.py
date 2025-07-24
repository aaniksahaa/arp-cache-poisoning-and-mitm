#!/usr/bin/env python3
"""
Test Script for HTML Injection Types
Demonstrates different injection blocks available for HTTP tampering
"""

import os
import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Import config
from config import AttackConfig

def display_injection_types():
    """Display all available injection types"""
    print(f"\n{Fore.CYAN}{'='*70}")
    print("💉 HTML INJECTION TYPES - DEMONSTRATION")
    print(f"{'='*70}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}📋 CURRENT INJECTION TYPE: {AttackConfig.CURRENT_HTML_INJECTION}{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}📋 AVAILABLE INJECTION TYPES:{Style.RESET_ALL}")
    
    for injection_name, injection_content in AttackConfig.HTML_INJECTION_BLOCKS.items():
        size = len(injection_content)
        
        print(f"\n{Fore.BLUE}🔹 {injection_name.upper()}{Style.RESET_ALL}")
        print(f"   Size: {size} bytes")
        
        # Show preview of injection content
        preview = injection_content.decode('utf-8', errors='ignore')[:200]
        if 'security' in injection_name.lower():
            print(f"   {Fore.RED}Type: Security Alert Banner{Style.RESET_ALL}")
            print(f"   Description: Professional security warning with timestamp")
        elif 'warning' in injection_name.lower():
            print(f"   {Fore.YELLOW}Type: Simple Warning{Style.RESET_ALL}")
            print(f"   Description: Basic HTTP interception notice")
        elif 'update' in injection_name.lower():
            print(f"   {Fore.GREEN}Type: Fake Update Prompt{Style.RESET_ALL}")
            print(f"   Description: Social engineering - fake security update")
        elif 'data' in injection_name.lower():
            print(f"   {Fore.BLUE}Type: Data Collection Notice{Style.RESET_ALL}")
            print(f"   Description: Network analysis progress bar")
        
        print(f"   Preview: {preview[:100]}{'...' if len(preview) > 100 else ''}")

def change_injection_type():
    """Allow user to change injection type"""
    print(f"\n{Fore.CYAN}🔧 CHANGE INJECTION TYPE{Style.RESET_ALL}")
    
    injection_types = list(AttackConfig.HTML_INJECTION_BLOCKS.keys())
    
    print(f"\n{Fore.WHITE}Available injection types:{Style.RESET_ALL}")
    for i, injection_type in enumerate(injection_types, 1):
        current = " (CURRENT)" if injection_type == AttackConfig.CURRENT_HTML_INJECTION else ""
        print(f"{i}. {injection_type}{Fore.GREEN}{current}{Style.RESET_ALL}")
    
    try:
        choice = input(f"\n{Fore.CYAN}Select injection type (1-{len(injection_types)}): {Style.RESET_ALL}").strip()
        choice_idx = int(choice) - 1
        
        if 0 <= choice_idx < len(injection_types):
            new_injection = injection_types[choice_idx]
            AttackConfig.CURRENT_HTML_INJECTION = new_injection
            print(f"\n{Fore.GREEN}✅ Injection type changed to: {new_injection}{Style.RESET_ALL}")
            
            # Show what this means
            injection_content = AttackConfig.HTML_INJECTION_BLOCKS[new_injection]
            print(f"{Fore.BLUE}📏 New injection size: {len(injection_content)} bytes{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}💡 This will be injected into HTML pages during TAMPER mode{Style.RESET_ALL}")
            
            return True
        else:
            print(f"{Fore.RED}❌ Invalid choice{Style.RESET_ALL}")
            return False
            
    except (ValueError, IndexError):
        print(f"{Fore.RED}❌ Invalid input{Style.RESET_ALL}")
        return False

def test_injection_on_sample():
    """Test injection on a sample HTML page"""
    print(f"\n{Fore.CYAN}🧪 TEST INJECTION ON SAMPLE HTML{Style.RESET_ALL}")
    
    # Get current injection
    current_injection = AttackConfig.HTML_INJECTION_BLOCKS.get(
        AttackConfig.CURRENT_HTML_INJECTION,
        AttackConfig.HTML_INJECTION_BLOCK
    )
    
    # Test cases with different HTML structures
    test_cases = {
        'proper_html': b"""<!DOCTYPE html>
<html>
<head>
    <title>Sample Page</title>
</head>
<body>
    <h1>Welcome to Sample Page</h1>
    <p>This is the original content of the page.</p>
    <p>The injection will appear above this content.</p>
</body>
</html>""",
        
        'no_body_tag': b"""<!DOCTYPE html>
<html>
<head>
    <title>No Body Tag</title>
</head>
<h1>Content without body tag</h1>
<p>This HTML is missing the body tag.</p>
</html>""",
        
        'minimal_html': b"""<html>
<h1>Minimal HTML</h1>
<p>Very basic HTML structure.</p>
</html>""",
        
        'fragment_html': b"""<div>
<h2>HTML Fragment</h2>
<p>Just a fragment, no html/head/body tags.</p>
</div>""",
        
        'plain_text': b"""This is just plain text content.
No HTML tags at all.
Should still get injected properly.""",
        
        'empty_content': b"",
        
        'malformed_html': b"""<html><head><title>Malformed
<h1>Missing closing tags
<p>Broken HTML structure"""
    }
    
    print(f"\n{Fore.GREEN}📋 Testing injection with different HTML structures:{Style.RESET_ALL}")
    
    for test_name, sample_html in test_cases.items():
        print(f"\n{Fore.BLUE}🔹 Testing: {test_name.upper()}{Style.RESET_ALL}")
        print(f"   Original size: {len(sample_html)} bytes")
        
        if sample_html:
            preview = sample_html[:60].decode('utf-8', errors='ignore')
            print(f"   Preview: {preview}{'...' if len(sample_html) > 60 else ''}")
        else:
            print(f"   Preview: (empty content)")
        
        # Simulate the injection logic from the interceptor
        injected_html = simulate_injection(sample_html, current_injection)
        
        print(f"   Injected size: {len(injected_html)} bytes")
        print(f"   Added: {len(injected_html) - len(sample_html)} bytes")
        
        # Save to file for viewing
        filename = f'/tmp/injected_{test_name}.html'
        with open(filename, 'wb') as f:
            f.write(injected_html)
        
        print(f"   {Fore.GREEN}✅ Saved to: {filename}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}💡 Open the files in /tmp/ with a browser to see the results{Style.RESET_ALL}")
    print(f"{Fore.BLUE}💡 Notice how each case handles the injection differently based on HTML structure{Style.RESET_ALL}")

def simulate_injection(html_bytes, injection_code):
    """Simulate the injection logic from the interceptor with all fallback strategies"""
    import re
    
    # Strategy 1: Find <body> tag and inject right after it
    body_pattern = re.compile(b"(<body[^>]*>)", re.IGNORECASE)
    match = body_pattern.search(html_bytes)
    if match:
        insert_pos = match.end()
        return html_bytes[:insert_pos] + injection_code + html_bytes[insert_pos:]
    
    # Strategy 2: If no <body> tag, try after </head>
    head_pattern = re.compile(b"(</head>)", re.IGNORECASE)
    head_match = head_pattern.search(html_bytes)
    if head_match:
        insert_pos = head_match.end()
        wrapped_injection = b"\n<body>\n" + injection_code + b"\n"
        return html_bytes[:insert_pos] + wrapped_injection + html_bytes[insert_pos:]
    
    # Strategy 3: If no </head>, try after <head> tag
    head_start_pattern = re.compile(b"(<head[^>]*>)", re.IGNORECASE)
    head_start_match = head_start_pattern.search(html_bytes)
    if head_start_match:
        insert_pos = head_start_match.end()
        wrapped_injection = b"\n</head>\n<body>\n" + injection_code + b"\n"
        return html_bytes[:insert_pos] + wrapped_injection + html_bytes[insert_pos:]
    
    # Strategy 4: If no proper head structure, try after <html> tag
    html_pattern = re.compile(b"(<html[^>]*>)", re.IGNORECASE)
    html_match = html_pattern.search(html_bytes)
    if html_match:
        insert_pos = html_match.end()
        wrapped_injection = b"\n<head></head>\n<body>\n" + injection_code + b"\n"
        return html_bytes[:insert_pos] + wrapped_injection + html_bytes[insert_pos:]
    
    # Strategy 5: Check if it looks like HTML at all
    if b'<' in html_bytes and b'>' in html_bytes:
        first_tag_pattern = re.compile(b"(<[^>]+>)", re.IGNORECASE)
        first_tag_match = first_tag_pattern.search(html_bytes)
        if first_tag_match:
            wrapped_injection = b"<html><head></head><body>\n" + injection_code + b"\n</body></html>\n"
            return wrapped_injection + html_bytes
    
    # Strategy 6: Plain text or malformed HTML
    content_preview = html_bytes[:200].decode('utf-8', errors='ignore').strip()
    if content_preview:
        wrapped_html = b"""<!DOCTYPE html>
<html>
<head>
    <title>Intercepted Content</title>
    <meta charset="utf-8">
</head>
<body>
""" + injection_code + b"""
<div style="margin-top: 20px; padding: 15px; border: 1px solid #ccc; background: #f9f9f9;">
    <h3>Original Content:</h3>
    <pre style="white-space: pre-wrap; word-wrap: break-word;">""" + html_bytes + b"""</pre>
</div>
</body>
</html>"""
        return wrapped_html
    
    # Strategy 7: Last resort for empty content
    minimal_html = b"""<!DOCTYPE html>
<html>
<head><title>HTTP Intercepted</title></head>
<body>
""" + injection_code + b"""
<p><strong>Original content was empty or invalid.</strong></p>
</body>
</html>"""
    return minimal_html

def main():
    """Main test function"""
    print(f"\n{Fore.CYAN}🧪 HTML INJECTION TESTING TOOL{Style.RESET_ALL}")
    
    while True:
        print(f"\n{Fore.WHITE}Available actions:{Style.RESET_ALL}")
        print("1. Display injection types")
        print("2. Change injection type")
        print("3. Test injection on sample HTML")
        print("4. Exit")
        
        try:
            choice = input(f"\n{Fore.CYAN}Select action (1-4): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                display_injection_types()
            elif choice == '2':
                change_injection_type()
            elif choice == '3':
                test_injection_on_sample()
            elif choice == '4':
                print(f"{Fore.GREEN}👋 Testing complete!{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.YELLOW}⚠️  Invalid choice. Please select 1-4.{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}👋 Testing interrupted by user{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 