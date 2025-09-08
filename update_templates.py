#!/usr/bin/env python3
"""
Template Updater Script
Applies Universal Cyberpunk Theme to All Templates
"""

import os
import re
from pathlib import Path

def update_template_file(file_path):
    """Update a single template file with universal theme"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Skip if already has universal theme
        if 'universal-theme.css' in content:
            print(f"✅ {file_path.name} - Already updated")
            return False
        
        # Add universal theme CSS after existing stylesheets
        if '<link rel="stylesheet"' in content and 'universal-theme.css' not in content:
            # Find the last stylesheet link
            last_css_match = None
            for match in re.finditer(r'<link rel="stylesheet"[^>]*>', content):
                last_css_match = match
            
            if last_css_match:
                insert_pos = last_css_match.end()
                universal_css = '\n    <link rel="stylesheet" href="/css/universal-theme.css">'
                content = content[:insert_pos] + universal_css + content[insert_pos:]
        
        # Add universal theme JavaScript before closing head tag
        if '</head>' in content and 'universal-theme.js' not in content:
            head_close = content.find('</head>')
            if head_close != -1:
                universal_js = '    <script src="/js/universal-theme.js"></script>\n'
                content = content[:head_close] + universal_js + content[head_close:]
        
        # Add cyberpunk-page class to body if not login page
        if '<body' in content and 'class=' not in content and 'login' not in file_path.name.lower():
            body_match = re.search(r'<body([^>]*)>', content)
            if body_match:
                body_tag = body_match.group(0)
                new_body_tag = body_tag.replace('>', ' class="cyberpunk-page fade-in">')
                content = content.replace(body_tag, new_body_tag)
        
        # Add fade-in class to existing body classes
        elif '<body class="' in content and 'fade-in' not in content:
            content = re.sub(r'<body class="([^"]*)', r'<body class="\1 fade-in', content)
        
        # Write updated content if changes were made
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✅ {file_path.name} - Updated successfully")
            return True
        else:
            print(f"ℹ️  {file_path.name} - No changes needed")
            return False
            
    except Exception as e:
        print(f"❌ {file_path.name} - Error: {e}")
        return False

def main():
    """Main function to update all templates"""
    print("🔮 Applying Universal Cyberpunk Theme to All Templates...\n")
    
    # Get templates directory
    templates_dir = Path(__file__).parent / 'templates'
    
    if not templates_dir.exists():
        print("❌ Templates directory not found!")
        return
    
    # Get all HTML files
    html_files = list(templates_dir.glob('*.html'))
    
    if not html_files:
        print("❌ No HTML templates found!")
        return
    
    print(f"Found {len(html_files)} template files:\n")
    
    updated_count = 0
    
    # Update each template
    for html_file in sorted(html_files):
        if update_template_file(html_file):
            updated_count += 1
    
    print(f"\n🎉 Template Update Complete!")
    print(f"📊 Updated: {updated_count}/{len(html_files)} files")
    print(f"\n🔮 Universal Cyberpunk Theme applied to all templates!")
    print(f"\n📝 Changes made:")
    print(f"   • Added universal-theme.css to all templates")
    print(f"   • Added universal-theme.js to all templates")
    print(f"   • Added cyberpunk-page and fade-in classes to body tags")
    print(f"   • Preserved existing login page styling")
    
if __name__ == '__main__':
    main()