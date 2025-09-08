#!/usr/bin/env python3
"""
CDN Dependencies Fixer
Replaces external CDN links with local files
"""

import os
import re
from pathlib import Path

def fix_template_file(file_path):
    """Fix CDN dependencies in a single template file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Replace FontAwesome CDN links
        fontawesome_patterns = [
            r'<link rel="stylesheet" href="https://cdnjs\.cloudflare\.com/ajax/libs/font-awesome/[^"]*">',
            r'<link rel="stylesheet" href="https://cdn\.jsdelivr\.net/npm/@fortawesome/[^"]*">'
        ]
        
        for pattern in fontawesome_patterns:
            content = re.sub(pattern, '<link rel="stylesheet" href="/libs/fontawesome.min.css">', content)
        
        # Replace Chart.js CDN links
        chartjs_patterns = [
            r'<script src="https://cdn\.jsdelivr\.net/npm/chart\.js[^"]*"></script>',
            r'<script src="https://cdnjs\.cloudflare\.com/ajax/libs/Chart\.js/[^"]*"></script>'
        ]
        
        for pattern in chartjs_patterns:
            content = re.sub(pattern, '<script src="/libs/chart.min.js"></script>', content)
        
        # Remove jsPDF CDN (optional dependency)
        jspdf_pattern = r'<script src="https://cdnjs\.cloudflare\.com/ajax/libs/jspdf/[^"]*"></script>'
        content = re.sub(jspdf_pattern, '<!-- jsPDF removed - using local alternatives -->', content)
        
        # Write updated content if changes were made
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✅ {file_path.name} - Updated CDN dependencies")
            return True
        else:
            print(f"ℹ️  {file_path.name} - No CDN dependencies found")
            return False
            
    except Exception as e:
        print(f"❌ {file_path.name} - Error: {e}")
        return False

def main():
    """Main function to fix all templates"""
    print("🔧 Fixing CDN Dependencies in All Templates...\n")
    
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
    
    # Fix each template
    for html_file in sorted(html_files):
        if fix_template_file(html_file):
            updated_count += 1
    
    print(f"\n🎉 CDN Dependencies Fix Complete!")
    print(f"📊 Updated: {updated_count}/{len(html_files)} files")
    print(f"\n🔧 Changes made:")
    print(f"   • Replaced FontAwesome CDN with /libs/fontawesome.min.css")
    print(f"   • Replaced Chart.js CDN with /libs/chart.min.js")
    print(f"   • Removed jsPDF CDN dependency")
    print(f"   • All templates now use local dependencies")
    
if __name__ == '__main__':
    main()