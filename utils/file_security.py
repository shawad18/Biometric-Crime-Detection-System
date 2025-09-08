import os
import magic
from PIL import Image, ImageFile
import hashlib
import mimetypes
from werkzeug.utils import secure_filename
import logging
from typing import Tuple, Optional, List
import re

# Enable loading of truncated images
ImageFile.LOAD_TRUNCATED_IMAGES = True

class FileSecurityValidator:
    """Comprehensive file upload security validator"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Allowed file extensions
        self.allowed_extensions = {
            'image': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'},
            'face': {'.jpg', '.jpeg', '.png'},
            'fingerprint': {'.jpg', '.jpeg', '.png', '.bmp'}
        }
        
        # Allowed MIME types
        self.allowed_mime_types = {
            'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 
            'image/tiff', 'image/webp'
        }
        
        # File size limits (in bytes)
        self.size_limits = {
            'face_image': 16 * 1024 * 1024,      # 16MB
            'fingerprint_image': 10 * 1024 * 1024,  # 10MB
            'general': 5 * 1024 * 1024           # 5MB
        }
        
        # Image dimension limits
        self.dimension_limits = {
            'max_width': 4096,
            'max_height': 4096,
            'min_width': 50,
            'min_height': 50
        }
        
        # Dangerous file signatures to block
        self.dangerous_signatures = {
            b'\x4D\x5A': 'PE/DOS executable',
            b'\x7F\x45\x4C\x46': 'ELF executable',
            b'\xCA\xFE\xBA\xBE': 'Mach-O executable',
            b'\x50\x4B\x03\x04': 'ZIP archive (potential)',
            b'\x52\x61\x72\x21': 'RAR archive',
            b'\x1F\x8B\x08': 'GZIP archive',
            b'\x42\x5A\x68': 'BZIP2 archive'
        }
    
    def validate_filename(self, filename: str) -> Tuple[bool, str]:
        """Validate filename for security issues"""
        if not filename:
            return False, "No filename provided"
        
        # Check for dangerous characters
        dangerous_chars = ['..', '/', '\\', ':', '*', '?', '"', '<', '>', '|']
        if any(char in filename for char in dangerous_chars):
            return False, "Filename contains dangerous characters"
        
        # Check filename length
        if len(filename) > 255:
            return False, "Filename too long"
        
        # Check for null bytes
        if '\x00' in filename:
            return False, "Filename contains null bytes"
        
        # Check for script extensions
        dangerous_extensions = {'.php', '.asp', '.aspx', '.jsp', '.js', '.html', '.htm', '.exe', '.bat', '.cmd', '.scr'}
        file_ext = os.path.splitext(filename.lower())[1]
        if file_ext in dangerous_extensions:
            return False, f"Dangerous file extension: {file_ext}"
        
        return True, "Filename is valid"
    
    def validate_file_extension(self, filename: str, file_type: str = 'image') -> Tuple[bool, str]:
        """Validate file extension"""
        if not filename:
            return False, "No filename provided"
        
        file_ext = os.path.splitext(filename.lower())[1]
        
        if file_type not in self.allowed_extensions:
            file_type = 'image'
        
        if file_ext not in self.allowed_extensions[file_type]:
            allowed = ', '.join(self.allowed_extensions[file_type])
            return False, f"Invalid file extension. Allowed: {allowed}"
        
        return True, "File extension is valid"
    
    def validate_file_size(self, file_size: int, file_type: str = 'general') -> Tuple[bool, str]:
        """Validate file size"""
        if file_size <= 0:
            return False, "Invalid file size"
        
        limit = self.size_limits.get(file_type, self.size_limits['general'])
        
        if file_size > limit:
            limit_mb = limit / (1024 * 1024)
            return False, f"File too large. Maximum size: {limit_mb:.1f}MB"
        
        return True, "File size is valid"
    
    def validate_mime_type(self, file_path: str) -> Tuple[bool, str]:
        """Validate MIME type using python-magic"""
        try:
            # Try to use python-magic if available
            try:
                mime_type = magic.from_file(file_path, mime=True)
            except:
                # Fallback to mimetypes module
                mime_type, _ = mimetypes.guess_type(file_path)
            
            if mime_type not in self.allowed_mime_types:
                return False, f"Invalid MIME type: {mime_type}"
            
            return True, "MIME type is valid"
            
        except Exception as e:
            self.logger.error(f"Error validating MIME type: {e}")
            return False, "Could not validate MIME type"
    
    def validate_file_signature(self, file_path: str) -> Tuple[bool, str]:
        """Validate file signature (magic bytes)"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)  # Read first 16 bytes
            
            # Check for dangerous file signatures
            for signature, description in self.dangerous_signatures.items():
                if header.startswith(signature):
                    return False, f"Dangerous file type detected: {description}"
            
            # Check for valid image signatures
            valid_signatures = {
                b'\xFF\xD8\xFF': 'JPEG',
                b'\x89\x50\x4E\x47': 'PNG',
                b'\x47\x49\x46\x38': 'GIF',
                b'\x42\x4D': 'BMP',
                b'\x49\x49\x2A\x00': 'TIFF (little endian)',
                b'\x4D\x4D\x00\x2A': 'TIFF (big endian)',
                b'\x52\x49\x46\x46': 'WEBP (RIFF container)'
            }
            
            for signature, description in valid_signatures.items():
                if header.startswith(signature):
                    return True, f"Valid image signature: {description}"
            
            return False, "Unknown or invalid file signature"
            
        except Exception as e:
            self.logger.error(f"Error validating file signature: {e}")
            return False, "Could not validate file signature"
    
    def validate_image_content(self, file_path: str) -> Tuple[bool, str]:
        """Validate image content and dimensions"""
        try:
            with Image.open(file_path) as img:
                # Check image dimensions
                width, height = img.size
                
                if width > self.dimension_limits['max_width'] or height > self.dimension_limits['max_height']:
                    return False, f"Image too large: {width}x{height}. Max: {self.dimension_limits['max_width']}x{self.dimension_limits['max_height']}"
                
                if width < self.dimension_limits['min_width'] or height < self.dimension_limits['min_height']:
                    return False, f"Image too small: {width}x{height}. Min: {self.dimension_limits['min_width']}x{self.dimension_limits['min_height']}"
                
                # Check image format
                if img.format not in ['JPEG', 'PNG', 'GIF', 'BMP', 'TIFF', 'WEBP']:
                    return False, f"Unsupported image format: {img.format}"
                
                # Check for potential issues
                if hasattr(img, 'verify'):
                    img.verify()  # This will raise an exception if the image is corrupted
                
                return True, f"Valid image: {width}x{height}, format: {img.format}"
                
        except Exception as e:
            self.logger.error(f"Error validating image content: {e}")
            return False, f"Invalid or corrupted image: {str(e)}"
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating file hash: {e}")
            return None
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe storage"""
        # Use werkzeug's secure_filename
        safe_name = secure_filename(filename)
        
        # Additional sanitization
        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', safe_name)
        
        # Ensure filename is not empty
        if not safe_name:
            safe_name = 'unnamed_file'
        
        # Limit filename length
        if len(safe_name) > 100:
            name, ext = os.path.splitext(safe_name)
            safe_name = name[:95] + ext
        
        return safe_name
    
    def comprehensive_validation(self, file_path: str, filename: str, file_type: str = 'image') -> Tuple[bool, List[str]]:
        """Run comprehensive file validation"""
        errors = []
        
        # Validate filename
        valid, msg = self.validate_filename(filename)
        if not valid:
            errors.append(f"Filename: {msg}")
        
        # Validate file extension
        valid, msg = self.validate_file_extension(filename, file_type)
        if not valid:
            errors.append(f"Extension: {msg}")
        
        # Validate file size
        try:
            file_size = os.path.getsize(file_path)
            valid, msg = self.validate_file_size(file_size, file_type)
            if not valid:
                errors.append(f"Size: {msg}")
        except Exception as e:
            errors.append(f"Size: Could not determine file size - {e}")
        
        # Validate MIME type
        valid, msg = self.validate_mime_type(file_path)
        if not valid:
            errors.append(f"MIME: {msg}")
        
        # Validate file signature
        valid, msg = self.validate_file_signature(file_path)
        if not valid:
            errors.append(f"Signature: {msg}")
        
        # Validate image content
        valid, msg = self.validate_image_content(file_path)
        if not valid:
            errors.append(f"Content: {msg}")
        
        return len(errors) == 0, errors
    
    def create_secure_upload_path(self, filename: str, upload_dir: str, file_type: str = 'image') -> str:
        """Create secure upload path with hash-based naming"""
        # Sanitize filename
        safe_filename = self.sanitize_filename(filename)
        
        # Create hash-based subdirectory
        file_hash = hashlib.md5(safe_filename.encode()).hexdigest()[:8]
        subdir = os.path.join(upload_dir, file_type, file_hash[:2])
        
        # Ensure directory exists
        os.makedirs(subdir, exist_ok=True)
        
        # Create unique filename with timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        name, ext = os.path.splitext(safe_filename)
        unique_filename = f"{timestamp}_{file_hash}_{name}{ext}"
        
        return os.path.join(subdir, unique_filename)

# Utility functions for Flask integration
def validate_uploaded_file(file, file_type='image'):
    """Validate uploaded file in Flask context"""
    validator = FileSecurityValidator()
    
    if not file or not file.filename:
        return False, ["No file provided"]
    
    # Save file temporarily for validation
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        file.save(temp_file.name)
        temp_path = temp_file.name
    
    try:
        # Run validation
        is_valid, errors = validator.comprehensive_validation(temp_path, file.filename, file_type)
        return is_valid, errors
    finally:
        # Clean up temporary file
        try:
            os.unlink(temp_path)
        except:
            pass

def secure_file_upload(file, upload_dir, file_type='image'):
    """Securely handle file upload"""
    validator = FileSecurityValidator()
    
    # Validate file first
    is_valid, errors = validate_uploaded_file(file, file_type)
    if not is_valid:
        return None, errors
    
    # Create secure upload path
    secure_path = validator.create_secure_upload_path(file.filename, upload_dir, file_type)
    
    # Save file
    try:
        file.save(secure_path)
        
        # Final validation on saved file
        is_valid, errors = validator.comprehensive_validation(secure_path, file.filename, file_type)
        if not is_valid:
            # Remove invalid file
            try:
                os.unlink(secure_path)
            except:
                pass
            return None, errors
        
        return secure_path, []
        
    except Exception as e:
        return None, [f"Upload failed: {str(e)}"]

if __name__ == '__main__':
    # Example usage
    validator = FileSecurityValidator()
    
    # Test file validation
    test_file = "test_image.jpg"
    if os.path.exists(test_file):
        is_valid, errors = validator.comprehensive_validation(test_file, test_file)
        print(f"File valid: {is_valid}")
        if errors:
            print("Errors:", errors)