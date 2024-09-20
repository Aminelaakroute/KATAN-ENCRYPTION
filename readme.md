# KATAN Encryption Project

This project implements the KATAN (K-Ary Tree Adding Network) block cipher with a graphical user interface using PyQt5.

## Description

KATAN is a lightweight block cipher designed for resource-constrained devices. This implementation supports three variants of KATAN: KATAN32, KATAN48, and KATAN64, which operate on 32-bit, 48-bit, and 64-bit blocks respectively.

The project consists of two main components:
1. A KATAN cipher implementation (`katan.py`)
2. A graphical user interface for encryption and decryption (`main.py`)

## Features

- Supports KATAN32, KATAN48, and KATAN64 variants
- Encryption and decryption functionality
- User-friendly graphical interface
- Input validation for plaintext/ciphertext and key
- Hexadecimal input and output

## Requirements

- Python 3.x
- PyQt5

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/Aminelaakroute/KATAN-ENCRYPTION.git
   ```
2. Install the required dependencies:
   ```
   pip install PyQt5
   ```

## Usage

Run the `main.py` script to start the application:

```
python main.py
```

In the GUI:
1. Select the KATAN variant (32, 48, or 64 bits)
2. Enter the plaintext or ciphertext in hexadecimal format
3. Enter the 80-bit key in hexadecimal format
4. Click "Encrypt" or "Decrypt" as needed
5. The result will be displayed in the output field

## Implementation Details

- The KATAN class in `katan.py` implements the core encryption and decryption algorithms
- The GUI in `main.py` provides a user-friendly interface for interacting with the KATAN implementation
- Input validation ensures that the entered values are within the correct range for the selected KATAN variant

## Contributing

Contributions to improve the project are welcome. Please feel free to submit issues or pull requests.

## License

.....

## Acknowledgments

- The KATAN cipher was designed by Christophe De Cannière, Orr Dunkelman, and Miroslav Knežević