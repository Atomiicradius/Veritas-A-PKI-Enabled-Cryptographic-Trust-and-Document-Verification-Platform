
import json
import io
import qrcode
import fitz  # PyMuPDF

def stamp_pdf_with_qr(pdf_bytes: bytes, metadata_dict: dict) -> bytes:
    """
    Compresses cryptographic metadata into a QR code and stamps it onto a new page
    at the end of the provided PDF bytes.
    
    All operations are kept strictly in memory for stateless cloud deployment.
    
    :param pdf_bytes: The original PDF document as bytes.
    :param metadata_dict: Dictionary containing signature metadata to encode.
    :return: Stamped PDF document as bytes.
    """
    # 1. Compact the metadata into a minified JSON string
    try:
        # separators=(',', ':') removes unnecessary spaces for a denser, smaller QR code
        compact_json = json.dumps(metadata_dict, separators=(',', ':'))
    except Exception as e:
        raise ValueError(f"Failed to serialize signature metadata: {e}")

    # 2. Generate a high-error-correction QR code image in memory
    try:
        qr = qrcode.QRCode(
            version=None,  # Automatically determine size based on data
            error_correction=qrcode.constants.ERROR_CORRECT_H,  # High error correction
            box_size=10,
            border=4,
        )
        qr.add_data(compact_json)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white")
        
        qr_io = io.BytesIO()
        qr_img.save(qr_io, format="PNG")
        qr_bytes = qr_io.getvalue()
    except Exception as e:
        raise RuntimeError(f"Failed to generate QR code: {e}")

    # 3. Read original PDF and insert a stamped page at the end
    try:
        # Load PDF document from bytes stream
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as e:
        raise ValueError(f"Invalid PDF file structure. PyMuPDF failed to open the file: {e}")

    try:
        # Determine page size based on the last page of the PDF (or use standard A4 if empty)
        if len(doc) > 0:
            last_page = doc[-1]
            width, height = last_page.rect.width, last_page.rect.height
        else:
            width, height = 595.27, 841.89  # Standard A4 dimensions in points (72 points/inch)

        # Create a new, blank page at the end of the document
        new_page = doc.new_page(width=width, height=height)

        # Define dimensions and bounding box for the QR code (centered, slightly shifted up)
        qr_size = min(220, min(width, height) * 0.4)
        x0 = (width - qr_size) / 2
        y0 = (height - qr_size) / 2 - 40  # Leave room for the text caption below
        x1 = x0 + qr_size
        y1 = y0 + qr_size
        
        qr_rect = fitz.Rect(x0, y0, x1, y1)
        
        # Insert the in-memory QR code image
        new_page.insert_image(qr_rect, stream=qr_bytes)

        # Draw a caption box below the QR code
        caption = "Scan using the Veritas Mobile App to verify cryptographic authenticity."
        text_rect = fitz.Rect(x0 - 60, y1 + 20, x1 + 60, y1 + 70)
        
        # Insert the warning/verification text
        # Align is set to 1 for text center alignment
        new_page.insert_textbox(
            text_rect,
            caption,
            fontsize=10,
            fontname="helv",
            align=1,  # Center text
            color=(0.133, 0.200, 0.290)  # Veritas Navy (#22334A -> 34/255, 51/255, 74/255)
        )

        # 4. Save the modified PDF back to a byte stream
        stamped_pdf_bytes = doc.tobytes()
        doc.close()
        
        return stamped_pdf_bytes
    except Exception as e:
        if 'doc' in locals():
            doc.close()
        raise RuntimeError(f"Error occurred during PDF stamping operations: {e}")
