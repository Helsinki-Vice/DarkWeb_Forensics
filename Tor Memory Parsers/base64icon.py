import os
import re
import base64
import binascii

def is_valid_base64(s: str) -> bool:
    """Check if a string is a valid Base64 encoded string."""
    try:
        base64.b64decode(s, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def extract_base64_icon(favicon_url: str, index: int, extracted_icons_folder: str) ->  tuple[str, str] | None:
    """Extract base64-encoded favicons and save them to a folder."""
    
    if not favicon_url.startswith('data:image'):
        return None  # Not a Base64 image

    try:
        # Extract Base64 data part
        base64_data = favicon_url.split(',', 1)[1].strip()

        # Ensure only valid Base64 characters remain
        base64_data = re.sub(r'[^A-Za-z0-9+/=]', '', base64_data)

        # Validate Base64 data before decoding
        if not is_valid_base64(base64_data):
            print(f"[-] Invalid Base64 favicon at offset {index}, skipping extraction.")
            return None

        # Decode Base64 data
        image_data = base64.b64decode(base64_data)

        # Determine file extension
        file_extension = 'ico' if 'image/x-icon' in favicon_url else 'png'

        # Ensure output folder exists
        os.makedirs(extracted_icons_folder, exist_ok=True)

        # Name the file as the starting offset for the favicon data
        output_filename = f"{index}_favicon.{file_extension}"
        icon_output = os.path.join(extracted_icons_folder, output_filename)

        # Save image data to file
        with open(icon_output, 'wb') as image_file:
            image_file.write(image_data)

        print(f"[+] Favicon Extracted: {icon_output}")
        return output_filename, icon_output

    except (binascii.Error, OSError, IndexError, ValueError) as e:
        print(f"[-] Error decoding Base64 Favicon at offset {index}: {e}")
        return None