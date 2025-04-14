#!/usr/bin/env python3
import os
from svglib.svglib import svg2rlg
from reportlab.graphics import renderPM
from PIL import Image

def generate_pwa_icons():
    print("Generating PWA icons from SVG...")
    
    # Source SVG file
    svg_path = 'static/icons/app-icon.svg'
    
    # Check if SVG file exists
    if not os.path.exists(svg_path):
        print(f"Error: SVG file {svg_path} not found")
        return False
    
    # Icon sizes needed for PWA
    icon_sizes = [72, 96, 128, 144, 152, 192, 384, 512]
    
    try:
        # Load SVG
        drawing = svg2rlg(svg_path)
        
        # Generate base PNG at highest resolution
        base_png_path = 'static/icons/icon-temp.png'
        renderPM.drawToFile(drawing, base_png_path, fmt='PNG')
        
        # Resize to all required sizes
        with Image.open(base_png_path) as img:
            for size in icon_sizes:
                resized = img.resize((size, size), Image.Resampling.LANCZOS)
                output_path = f'static/icons/icon-{size}x{size}.png'
                resized.save(output_path, 'PNG', quality=95)
                print(f"Created: {output_path}")
        
        # Clean up temporary file
        if os.path.exists(base_png_path):
            os.remove(base_png_path)
        
        # Create special links for manifest file (these need to be named exactly as referenced)
        for special_size in [192, 512]:
            src = f'static/icons/icon-{special_size}x{special_size}.png'
            dst = f'static/icons/icon-{special_size}x{special_size}.png'
            
            # If they already exist from the loop above, no need to copy
            if os.path.exists(src) and not os.path.exists(dst) and src != dst:
                with open(src, 'rb') as source:
                    with open(dst, 'wb') as dest:
                        dest.write(source.read())
                print(f"Created special link: {dst}")
        
        print("PWA icons generated successfully!")
        return True
    
    except Exception as e:
        print(f"Error generating icons: {str(e)}")
        return False

if __name__ == "__main__":
    generate_pwa_icons()