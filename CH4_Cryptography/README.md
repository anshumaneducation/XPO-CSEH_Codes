## Install required python packages from `requirements.txt`

- Install virtual environment python - `python3 -m venv myenv`
- Activate virtual environment - `source myenv/bin/activate`
- Command - `pip3 install -r requirements.txt`

This implementation of the Diffie-Hellman key exchange uses a TCP client-server model with GUI support. The client (Alice) and server (Bob) each choose a private number and use shared constants p (prime) and g (primitive root) to compute public keys. The client sends its private number to the server, which calculates both public keys and derives the shared secret on both sides. The secret key is never transmitted, ensuring secure key agreement over an insecure network.