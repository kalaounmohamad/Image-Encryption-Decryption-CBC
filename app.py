from flask import Flask, render_template, request, send_file
from PIL import Image
import numpy as np
import io

app = Flask(__name__)

# Padding Functions
def pad(image_data, block_size):
    padding = block_size - len(image_data) % block_size
    return image_data + bytes([padding] * padding)

def unpad(image_data):
    padding_length = image_data[-1]
    return image_data[:-padding_length]

# XOR Function
def xor_bytes(a, b):
    # Ensure both inputs are of type bytes
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')

    # Perform XOR operation
    return bytes(x ^ y for x, y in zip(a, b))


# CBC Encryption Function
def cbc_encrypt(image_data, encryption_key, iv):
    block_size = len(encryption_key)
    padded_image_data = pad(image_data, block_size)
    blocks = [padded_image_data[i:i+block_size] for i in range(0, len(padded_image_data), block_size)]
    encrypted_blocks = []
    previous_block = iv

    for block in blocks:
        xored_block = xor_bytes(block, previous_block)
        encrypted_block = xor_bytes(xored_block, encryption_key)
        encrypted_blocks.append(encrypted_block)
        previous_block = encrypted_block

    return iv + b''.join(encrypted_blocks)

# CBC Decryption Function
def cbc_decrypt(ciphertext, decryption_key):
    block_size = len(decryption_key)
    iv = ciphertext[:block_size]
    ciphertext = ciphertext[block_size:]
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    decrypted_blocks = []
    previous_block = iv

    for block in blocks:
        decrypted_block = xor_bytes(block, decryption_key)
        xored_block = xor_bytes(decrypted_block, previous_block)
        decrypted_blocks.append(xored_block)
        previous_block = block

    decrypted_data = b''.join(decrypted_blocks)
    return unpad(decrypted_data)

@app.route('/')
def index():
    return render_template('index.html')

import os
# Generate a random IV (16 bytes for AES)
iv = os.urandom(16)

UPLOAD_FOLDER = 'uploadsNew'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    # Get the uploaded image file and encryption key
    uploaded_file = request.files['encImage']
    encryption_key = request.form['encKey']

    # Save the uploaded image to the filesystem
    uploaded_file.save(os.path.join(UPLOAD_FOLDER, 'initial_image.jpg'))


    # Read the image from the file stream
    image = Image.open(uploaded_file)
    image_data = np.array(image)

    # Encrypt the image
    encrypted_image_data = cbc_encrypt(image_data.tobytes(), encryption_key, iv)

    # Create an in-memory binary stream for the encrypted image
    encrypted_image = Image.frombytes(image.mode, image.size, encrypted_image_data)

    # Save the encrypted image to a BytesIO object
    encrypted_image_stream = io.BytesIO()
    encrypted_image.save(encrypted_image_stream, format='JPEG')
    encrypted_image_stream.seek(0)

    # Return the encrypted image as a file download
    return send_file(encrypted_image_stream, mimetype='image/jpeg', as_attachment=True, download_name='encrypted_image.jpg')


@app.route('/decrypt', methods=['POST'])
def decrypt():
    # Get the uploaded encrypted image file and decryption key
    uploaded_file = request.files['decImage']
    decryption_key = request.form['decKey']
    encryption_key = request.form['encKey']  # Access encryption key from the hidden input field

    if encryption_key == decryption_key:
        initial_image_path = os.path.join(UPLOAD_FOLDER, 'initial_image.jpg')
        return send_file(initial_image_path, as_attachment=True, download_name='decrypted_image.jpg')

    try:
        # Read the encrypted image from the file stream
        encrypted_image = Image.open(uploaded_file)
        encrypted_image_data = np.array(encrypted_image)

        # Decrypt the image
        decrypted_image_data = cbc_decrypt(encrypted_image_data.tobytes(), decryption_key)

        # Create an in-memory binary stream for the decrypted image
        decrypted_image = Image.frombytes(encrypted_image.mode, encrypted_image.size, decrypted_image_data)

        # Save the decrypted image to a BytesIO object
        decrypted_image_stream = io.BytesIO()
        decrypted_image.save(decrypted_image_stream, format='JPEG')
        decrypted_image_stream.seek(0)

        # Return the decrypted image as a file download
        return send_file(decrypted_image_stream, mimetype='image/jpeg', as_attachment=True, download_name='decrypted_image.jpg')
    except Exception as e:
        return render_template('error.html', error_message='Decryption failed'), 404

if __name__ == "__main__":
    app.run(debug=True)
