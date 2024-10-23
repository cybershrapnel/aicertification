from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
import json
import os
import re
import uuid
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
import requests
from decimal import Decimal
import json
import logging
from typing import Optional

# RPC connection details
RPC_USER = 'nanocheeze'
RPC_PASSWORD = 'ncz'
RPC_HOST = '127.0.0.1'
RPC_PORT = '12782'

# The address from which to spend
SPENDING_ADDRESS = 'NhvjwjKJsPciKE1fg8tAwYGuZjVVMFAyQC'




app = FastAPI()

# Enable CORS (if needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this if you have specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the 'static' directory to serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# File paths for storing certificates and file records
CERTS_FILE = "certificates.json"
FILE_RECORDS_FILE = "file_records.json"

# Static message for signing
STATIC_MESSAGE = "Test message for signing"


# Blockchain RPC helpers
def call_rpc(method, params=None):
    url = f"http://{RPC_HOST}:{RPC_PORT}/"
    headers = {'content-type': 'application/json'}
    payload = json.dumps({
        "method": method,
        "params": params or [],
        "jsonrpc": "1.0",
        "id": "python-rpc"
    })
    response = requests.post(url, headers=headers, data=payload, auth=(RPC_USER, RPC_PASSWORD))
    if response.status_code != 200:
        raise Exception(f"RPC call failed: {response.status_code} {response.text}")
    response_json = response.json()
    if response_json.get('error'):
        raise Exception(f"RPC call error: {response_json['error']}")
    return response_json['result']

def list_unspent(address):
    return call_rpc('listunspent', [0, 9999999, [address]])

def create_raw_transaction(unspent_outputs, to_address, amount_to_send, op_return_data_hex):
    inputs = []
    total_input_value = Decimal('0')
    for utxo in unspent_outputs:
        inputs.append({"txid": utxo['txid'], "vout": utxo['vout']})
        total_input_value += Decimal(str(utxo['amount']))
        if total_input_value >= amount_to_send:
            break

    if total_input_value < amount_to_send:
        raise Exception("Not enough balance")

    outputs = {}

    # Send change back to the sender address
    change_amount = total_input_value - amount_to_send
    if change_amount > 0:
        outputs[to_address] = float(change_amount)  # Ensure it's a float

    # Add OP_RETURN data
    outputs['data'] = op_return_data_hex

    # Create raw transaction
    raw_tx = call_rpc('createrawtransaction', [inputs, outputs])
    return raw_tx

def sign_raw_transaction(raw_tx):
    result = call_rpc('signrawtransaction', [raw_tx])
    return result['hex'] if 'hex' in result else None

def send_raw_transaction(signed_tx_hex):
    return call_rpc('sendrawtransaction', [signed_tx_hex])





# Ensure the necessary files exist
if not os.path.exists(CERTS_FILE):
    with open(CERTS_FILE, "w") as f:
        json.dump({}, f)

if not os.path.exists(FILE_RECORDS_FILE):
    with open(FILE_RECORDS_FILE, "w") as f:
        json.dump({}, f)

# Data models for request payloads
class CertRequest(BaseModel):
    username: str

class PublicKeyRegistration(BaseModel):
    cert_id: str
    public_key: str

class SignatureRequest(BaseModel):
    cert_id: str
    signature: str

class WatermarkRequest(BaseModel):
    cert_id: str
    signature: str
    file_hash: str
    original_file_size: int
    file_name: str

class FinalizeWatermarkRequest(BaseModel):
    cert_id: str
    final_file_hash: str
    final_file_size: int
    original_file_hash: str  # Add this field
    txid: Optional[str] = None  # New optional field

class ImageVerificationRequest(BaseModel):
    username: str
    file_hash: str
    file_size: int

# Helper functions to load/save certs and file records
def load_certs():
    with open(CERTS_FILE, "r") as f:
        return json.load(f)

def save_certs(certs):
    with open(CERTS_FILE, "w") as f:
        json.dump(certs, f, indent=4)

def load_file_records():
    with open(FILE_RECORDS_FILE, "r") as f:
        return json.load(f)

def save_file_records(records):
    with open(FILE_RECORDS_FILE, "w") as f:
        json.dump(records, f, indent=4)

# Create a new certificate
USERNAME_REGEX = re.compile(r'^[\w\-_=]+$')

@app.post("/create_cert")
def create_cert(req: CertRequest):
    certs = load_certs()

    # Validate the username to only allow alphanumeric, underscore, dash, and equals
    if not USERNAME_REGEX.match(req.username):
        raise HTTPException(status_code=400, detail="Invalid username. Only alphanumeric characters, underscores, dashes, and equals are allowed.")

    # Generate a unique cert_id
    cert_id = str(uuid.uuid4())

    # Ensure the username doesn't already exist
    if any(cert.get("username") == req.username for cert in certs.values()):
        raise HTTPException(status_code=400, detail="Username already taken")

    # Create the certificate entry
    certs[cert_id] = {
        "username": req.username,
        "public_key": None,  # Will be updated once public key is registered
        "txid": None          # Will be updated once OP_RETURN is executed
    }

    save_certs(certs)
    return {"cert_id": cert_id, "message": f"Cert generated for {req.username}"}







# Register the public key after generating the cert ID and key pair
# ... [All previous imports and configurations]

# Register the public key after generating the cert ID and key pair
@app.post("/register_public_key")
def register_public_key(req: PublicKeyRegistration):
    certs = load_certs()

    # Check if cert_id exists
    if req.cert_id not in certs:
        raise HTTPException(status_code=404, detail="Cert ID not found")

    # Store the public key in PEM format
    certs[req.cert_id]["public_key"] = req.public_key

    # Get username
    username = certs[req.cert_id]["username"]

    # Define cert_level
    cert_level = 1

    # Prepare the OP_RETURN data
    # Ensure that 'req.public_key' contains the public key you intend to clean
    clean_public_key = strip_pem_headers(req.public_key)

    # Now, embed the cleaned public key into OP_RETURN data
    op_return_data = f"{req.cert_id}|{username}|{clean_public_key}|{cert_level}"
    #op_return_data = f"{certs[req.cert_id]['txid']}|{clean_public_key}"

    # Encode to hex
    op_return_data_hex = op_return_data.encode('utf-8').hex()

    # Prepare OP_RETURN transaction
    try:
        # List unspent outputs
        unspent_outputs = list_unspent(SPENDING_ADDRESS)

        # Set amount to send (transaction fee)
        amount_to_send = Decimal('0.001')  # Adjust fee as necessary

        # Create raw transaction with OP_RETURN
        raw_tx = create_raw_transaction(unspent_outputs, SPENDING_ADDRESS, amount_to_send, op_return_data_hex)

        # Sign raw transaction
        signed_tx = sign_raw_transaction(raw_tx)
        if not signed_tx:
            raise Exception("Failed to sign the transaction")

        # Send raw transaction to the blockchain
        txid = send_raw_transaction(signed_tx)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating OP_RETURN transaction: {str(e)}")

    # Save txid in certs
    certs[req.cert_id]['txid'] = txid

    # Save certs
    save_certs(certs)

    return {"message": "Public key registered and OP_RETURN transaction created successfully", "txid": txid}


def strip_pem_headers(pem_key):
    """
    Strips the PEM headers and footers from a key string.
    
    Args:
        pem_key (str): The PEM-formatted key string.
        
    Returns:
        str: The key string without PEM headers and footers.
    """
    # Define the headers and footers
    headers = ["-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"]
    
    # Remove headers and footers
    for header in headers:
        pem_key = pem_key.replace(header, "")
    
    # Remove any newline or carriage return characters
    pem_key = pem_key.replace("\n", "").replace("\r", "").strip()
    
    return pem_key


# Verify the signature
@app.post("/verify_signature")
def verify_signature(req: SignatureRequest):
    certs = load_certs()

    # Check if the cert_id exists
    if req.cert_id not in certs:
        raise HTTPException(status_code=404, detail="Cert ID not found")

    # Retrieve the public key for the cert_id
    public_key_pem = certs[req.cert_id]["public_key"]
    if not public_key_pem:
        raise HTTPException(status_code=400, detail="Public key not registered")

    # Load the public key from PEM format
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail="Failed to load public key")

    # Convert the signature from hex to bytes
    try:
        signature_bytes = bytes.fromhex(req.signature)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid signature format")

    # Encode the static message (same as in the client-side)
    message_bytes = STATIC_MESSAGE.encode()

    try:
        # Verify the signature using ECDSA and SHA256
        public_key.verify(
            signature_bytes,
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail="Signature verification failed")

    return {"message": "Signature verified successfully"}


# Get username by cert_id
@app.get("/get_username/{cert_id}")
def get_username(cert_id: str):
    certs = load_certs()
    if cert_id not in certs:
        raise HTTPException(status_code=404, detail="Cert ID not found")
    return {"username": certs[cert_id]["username"]}


# Verify the signed file hash and provide a watermark
@app.post("/verify_watermark")
def verify_watermark(req: WatermarkRequest):
    certs = load_certs()

    # Check if the cert_id exists
    if req.cert_id not in certs:
        raise HTTPException(status_code=404, detail="Cert ID not found")

    # Retrieve the public key for the cert_id
    public_key_pem = certs[req.cert_id]["public_key"]
    if not public_key_pem:
        raise HTTPException(status_code=400, detail="Public key not registered")

    # Load the public key from PEM format
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail="Failed to load public key")

    # Convert the signature from hex to bytes
    try:
        signature_bytes = bytes.fromhex(req.signature)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid signature format")

    # Convert the file hash from hex to bytes
    try:
        file_hash_bytes = bytes.fromhex(req.file_hash)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid file hash format")

    try:
        # Verify the signature using ECDSA and SHA256
        public_key.verify(
            signature_bytes,
            file_hash_bytes,
            ec.ECDSA(hashes.SHA256())
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail="Signature verification failed")

    # Get the CertTXID from the certs.json for the given cert_id
    cert_txid = certs[req.cert_id].get("txid", "Not available")


    # Generate a watermark (this is a simple example; you can customize it)
    #watermark = f"NanoCheeze AI Certification Watermark: CertID: {req.cert_id}, Cert_txID: {cert_txid}, Signed Hash: {req.signature}"
    cleaned_file_name = req.file_name.replace(",", "_")
    watermark = f"NanoCheeze AI Certification Watermark: CertID: {req.cert_id}, Cert_txID: {cert_txid}, Original File Name: {cleaned_file_name}, Signed Hash: {req.signature}"

    # Store the file record without final hash and size
    records = load_file_records()

    # Initialize an entry for the cert_id if it doesn't exist
    if req.cert_id not in records:
        records[req.cert_id] = []

    # Check for duplicate original hash under the same cert_id
    for record in records[req.cert_id]:
        if record["original_file_hash"] == req.file_hash:
            raise HTTPException(status_code=400, detail="A file with the same original hash already exists for this cert_id")

    # Add the new file record
    records[req.cert_id].append({
        "file_name": req.file_name,
        "original_file_hash": req.file_hash,
        "original_file_size": req.original_file_size,
        "username": certs[req.cert_id]["username"],
        "final_file_hash": None,
        "final_file_size": None
    })
    save_file_records(records)

    return {"message": "File verified and watermark generated", "watermark": watermark}
import logging

logging.basicConfig(level=logging.DEBUG)

@app.post("/finalize_watermark")
def finalize_watermark(req: FinalizeWatermarkRequest):
    logging.debug(f"Received FinalizeWatermarkRequest: cert_id='{req.cert_id}', final_file_hash='{req.final_file_hash}', final_file_size={req.final_file_size}, original_file_hash='{req.original_file_hash}', txid='{req.txid}'")
    
    records = load_file_records()
    # Load certificates to retrieve cert_txid
    certs = load_certs()

    # Ensure cert_id exists in the certificates
    if req.cert_id not in certs:
        raise HTTPException(status_code=404, detail="Cert ID not found in certificate records")

    # Retrieve the cert_txid
    cert_txid = certs[req.cert_id].get("txid", None)
    if not cert_txid:
        raise HTTPException(status_code=400, detail="Transaction ID (txid) not found for this cert_id")

    # Debug: Check if the records are loaded correctly
    logging.debug(f"Loaded file records: {records}")

    # Check if the cert_id exists in the records
    if req.cert_id not in records:
        logging.error(f"Cert ID {req.cert_id} not found in records.")
        raise HTTPException(status_code=404, detail="Cert ID not found in file records")

    found = False
    txid = req.txid  # Initialize txid with the value from the request
    final_op_txid = None  # Initialize final_op_txid to avoid UnboundLocalError

    for record in records[req.cert_id]:
        logging.debug(f"Checking record: {record}")

        # Match the original_file_hash
        if record["original_file_hash"] == req.original_file_hash:


            # If txid is provided, use it without performing blockchain write
            if txid:
                logging.info(f"Using provided txid: {txid}")
            else:
                # Proceed to finalize by writing to the blockchain
                try:
                    logging.debug(f"Starting blockchain write for cert_id={req.cert_id}")


                    cert_txid = certs[req.cert_id]['txid']  # Fetch the cert_txid for the cert_id

                    # Prepare the data for OP_RETURN using cert_txid only
                    data_values = [
                        cert_txid,  # Use cert_txid instead of cert_id and username
                        record.get("file_name", ""),
                        req.original_file_hash,
                        str(record.get("original_file_size", "")),
                    ]

                  

                    # Create the data string by joining with '|'
                    data_string = '|'.join(data_values)
                    logging.debug(f"Data string: {data_string}")

                    # Ensure the data fits within 255 characters
                    if len(data_string) > 255:
                        logging.error(f"Data length exceeds 255 characters: {len(data_string)}")
                        raise HTTPException(status_code=400, detail="Data exceeds 255 characters")

                    # Convert the data string to hexadecimal
                    data_hex = data_string.encode('utf-8').hex()
                    logging.debug(f"Hexadecimal data: {data_hex}")

                    # List unspent outputs
                    logging.debug(f"Listing unspent outputs for address: {SPENDING_ADDRESS}")
                    unspent_outputs = list_unspent(SPENDING_ADDRESS)
                    logging.debug(f"Unspent outputs: {unspent_outputs}")

                    # Set amount to send (transaction fee)
                    amount_to_send = Decimal('0.001')  # Adjust fee as necessary
                    logging.debug(f"Amount to send (transaction fee): {amount_to_send}")

                    # Create raw transaction
                    logging.debug("Creating raw transaction...")
                    raw_tx = create_raw_transaction(unspent_outputs, SPENDING_ADDRESS, amount_to_send, data_hex)
                    logging.debug(f"Raw transaction: {raw_tx}")

                    # Sign raw transaction
                    logging.debug("Signing raw transaction...")
                    signed_tx = sign_raw_transaction(raw_tx)
                    logging.debug(f"Signed transaction: {signed_tx}")

                    if not signed_tx:
                        logging.error("Failed to sign the transaction.")
                        raise HTTPException(status_code=500, detail="Failed to sign the transaction")

                    # Send raw transaction to the blockchain
                    logging.debug("Sending signed transaction to blockchain...")
                    txid = send_raw_transaction(signed_tx)
                    logging.info(f"Data written to blockchain with txid {txid}")

                except Exception as e:
                    logging.error(f"Error writing data to blockchain: {e}")
                    raise HTTPException(status_code=500, detail=f"Error writing data to blockchain: {e}")
            try:
                # Prepare data for the final OP_RETURN
                op_return_data = f"{txid}|{cert_txid}|{req.final_file_hash}|{req.final_file_size}"
                data_hex = op_return_data.encode('utf-8').hex()

                # List unspent outputs for the spending address
                unspent_outputs = list_unspent(SPENDING_ADDRESS)

                # Create and sign the raw transaction with OP_RETURN
                raw_tx = create_raw_transaction(unspent_outputs, SPENDING_ADDRESS, Decimal('0.001'), data_hex)
                signed_tx = sign_raw_transaction(raw_tx)

                # Send the transaction to the blockchain
                final_op_txid = send_raw_transaction(signed_tx)
            except Exception as e:
                logging.error(f"Error during final OP_RETURN: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Error writing final data to blockchain: {str(e)}")

            # Now update the record with the final hash, size, and txid
            record["final_file_hash"] = req.final_file_hash
            record["final_file_size"] = req.final_file_size
            record["txid"] = txid  # Save the transaction ID
            record["newtxid"] = final_op_txid  # Save the final OP_RETURN transaction ID

            logging.debug(f"Updated record with final file info and txid: {record}")

            found = True
            break

    if not found:
        logging.error(f"No record found to finalize for cert_id {req.cert_id}.")
        raise HTTPException(status_code=404, detail="Matching file record not found to finalize")

    # Save the records back to the JSON
    try:
        save_file_records(records)
        logging.info(f"Final file hash, size, and txid recorded successfully for cert_id {req.cert_id}.")
    except Exception as e:
        logging.error(f"Error saving final file record: {e}")
        raise HTTPException(status_code=500, detail="Error saving final file record")

    return {
        "message": "Final file hash and size recorded successfully, data written to blockchain",
        "txid": txid,
        "final_op_txid": final_op_txid,
        "final_file_hash": req.final_file_hash  # Make sure to include this in the response

    }

@app.post("/verify_audio")
def verify_audio(req: ImageVerificationRequest):
    records = load_file_records()

    # Search for matching records based on the final file hash and size
    for cert_id, file_list in records.items():
        for record in file_list:
            if req.file_hash == record.get("final_file_hash", ""):
                # Verify the current file size against the stored final file size
                if req.file_size == record["final_file_size"]:
                    txid = record.get("txid", "Not available")  # Retrieve
                    return {
                        "message": "Audio verification successful. The audio is authentic and unaltered.",
                        "original_file_hash": record.get("original_file_hash", "Not available"),
                        "original_file_size": record.get("original_file_size", "Not available"),
                        "original_file_name": record.get("file_name", "Not available"),
                        "username": record.get("username", "Not available"),
                        "txid": txid
                    }
                else:
                    return {
                        "message": "File size mismatch. The audio may have been altered.",
                        "original_file_hash": record.get("original_file_hash", "Not available"),
                        "original_file_size": record.get("original_file_size", "Not available"),
                        "original_file_name": record.get("file_name", "Not available"),
                        "username": record.get("username", "Not available")
                    }

    # If no match is found, return 404
    raise HTTPException(status_code=404, detail="No matching record found for the given file hash")

@app.post("/verify_image")
def verify_image(req: ImageVerificationRequest):
    records = load_file_records()

    # Search for matching records under all cert_ids
    for cert_id, file_list in records.items():
        for record in file_list:
            if record["username"] == req.username and req.file_hash == record.get("final_file_hash", ""):
                # Extract original hash, size, and filename if available
                original_file_hash = record.get("original_file_hash", "Not available")
                original_file_size = record.get("original_file_size", "Not available")
                original_file_name = record.get("file_name", "Not available")  # Add this line
                txid = record.get("txid", "Not available")  # Retrieve

                # Check if txid is available
                txid_link = ''
                if txid != "Not available":
                    txid_link = f'<a href="http://rpc.nanocheeze.com/tx/{txid}" target="_blank">{txid}</a>'
                else:
                    txid_link = 'Not available'


                # Verify file size
                if req.file_size == record["final_file_size"]:
                    return {
                        "message": "Image verification successful. The image is authentic and unaltered.",
                        "original_file_hash": original_file_hash,
                        "original_file_size": original_file_size,
                        "original_file_name": original_file_name,
                        "txid": txid_link
                    }
                else:
                    return {
                        "message": "File size mismatch. The image may have been altered.",
                        "original_file_hash": original_file_hash,
                        "original_file_size": original_file_size,
                        "original_file_name": original_file_name,
                        "txid": txid_link
                    }

    raise HTTPException(status_code=404, detail="No matching record found for the given username and file hash")



@app.get("/get_cert_txid/{cert_id}")
def get_cert_txid(cert_id: str):
    certs = load_certs()
    if cert_id not in certs:
        raise HTTPException(status_code=404, detail="Cert ID not found")
    cert_txid = certs[cert_id].get("txid", "Not available")
    return {"cert_txid": cert_txid}




# Run the server
if __name__ == "__main__":
    # Run the FastAPI app using uvicorn with SSL parameters
    uvicorn.run(app, host="0.0.0.0", port=8211,
                ssl_certfile="certificate.pem",  # Path to your SSL certificate
                ssl_keyfile="private.key")
