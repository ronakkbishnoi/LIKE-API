from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import os
from datetime import datetime
import time
import threading
from collections import defaultdict
import logging
from concurrent.futures import ThreadPoolExecutor

# --- Application Setup ---
app = Flask(__name__)
# Suppress insecure request warnings for verify=False
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Statistics Tracking ---
class Statistics:
    def __init__(self):
        self.requests_today = 0
        self.tokens_generated = 0
        self.tokens_failed = 0
        self.last_reset_date = datetime.now().date()
        self.lock = threading.Lock()
    
    def increment_requests(self):
        with self.lock:
            self._check_date_reset()
            self.requests_today += 1
    
    def increment_tokens_generated(self):
        with self.lock:
            self.tokens_generated += 1
    
    def increment_tokens_failed(self):
        with self.lock:
            self.tokens_failed += 1
    
    def _check_date_reset(self):
        current_date = datetime.now().date()
        if current_date != self.last_reset_date:
            self.requests_today = 0
            self.last_reset_date = current_date
    
    def get_stats(self):
        with self.lock:
            self._check_date_reset()
            return {
                "requests_today": self.requests_today,
                "tokens_generated": self.tokens_generated,
                "tokens_failed": self.tokens_failed,
                "last_reset_date": self.last_reset_date.isoformat()
            }

# Initialize statistics
stats = Statistics()

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def log_info(message):
    logger.info(message)

def log_error(message):
    logger.error(message)

def log_debug(message):
    logger.debug(message)

def log_warning(message):
    logger.warning(message)

# --- Credential and Token Management ---

class CredentialManager:
    """Manages loading, caching, and rotation of credentials for sending likes."""
    def __init__(self, likes_per_batch=110):
        self.credentials_cache = {}
        self.server_indices = defaultdict(int)
        self.lock = threading.Lock()
        self.LIKES_PER_BATCH = likes_per_batch
        self.credential_files = {
            "IND": "ind.json",
            "BR": "br.json",
            "US": "br.json",
            "SAC": "br.json",
            "NA": "br.json"
        }
        self.all_tokens = {}  # Store all tokens by server and uid
        self.token_lock = threading.RLock()
        self.token_refresh_thread = None
        self.stop_refresh = False

    def load_credentials(self, server_name):
        """Loads credentials for a server from JSON files if not already in cache."""
        if server_name in self.credentials_cache:
            return self.credentials_cache[server_name]

        try:
            filename = self.credential_files.get(server_name, "bd.json")
            
            with open(filename, "r") as f:
                credentials = json.load(f)
                self.credentials_cache[server_name] = credentials
                log_info(f"Loaded {len(credentials)} credentials for server {server_name}.")
                return credentials
        except FileNotFoundError:
            log_error(f"Credential file for server {server_name} not found.")
            return None
        except Exception as e:
            log_error(f"Error loading credentials for server {server_name}: {e}")
            return None

    def get_next_batch(self, server_name):
        """
        Gets the next batch of credentials for sending likes, implementing rotation logic.
        """
        with self.lock:
            credentials = self.load_credentials(server_name)
            if not credentials:
                log_warning(f"No credentials available for server {server_name}.")
                return []
                
            if len(credentials) < self.LIKES_PER_BATCH:
                log_warning(f"Not enough credentials for server {server_name} to form a full batch of {self.LIKES_PER_BATCH}. Using all available {len(credentials)} credentials.")
                return credentials

            start_index = self.server_indices[server_name]
            
            # If a full batch isn't available from the current position, reset to the beginning.
            if start_index + self.LIKES_PER_BATCH > len(credentials):
                log_info(f"End of credential list reached for {server_name}. Resetting index to start.")
                start_index = 0
                self.server_indices[server_name] = 0

            end_index = start_index + self.LIKES_PER_BATCH
            batch = credentials[start_index:end_index]
            
            # Update the index for the next request.
            self.server_indices[server_name] = end_index
            
            return batch

    def initialize_all_tokens(self):
        """Pre-generate all JWT tokens for all accounts at startup."""
        log_info("Starting initialization of all JWT tokens...")
        
        with ThreadPoolExecutor(max_workers=5) as executor:  # Reduced workers to avoid rate limiting
            futures = []
            
            for server_name, credentials in self.credentials_cache.items():
                if server_name not in self.all_tokens:
                    self.all_tokens[server_name] = {}
                
                for cred in credentials:
                    uid = cred['uid']
                    password = cred['password']
                    futures.append(
                        executor.submit(self._generate_and_store_token_with_retry, server_name, uid, password, max_retries=2)
                    )
            
            # Wait for all tokens to be generated
            for future in futures:
                try:
                    future.result(timeout=60)  # Increased timeout for retries
                except Exception as e:
                    log_error(f"Error generating token: {e}")
        
        log_info("Completed initialization of all JWT tokens.")
        
        # Start the token refresh scheduler
        self.start_token_refresh()

    def _generate_and_store_token_with_retry(self, server_name, uid, password, max_retries=2):
        """Generate a token with retry logic and store it in the cache."""
        for attempt in range(max_retries + 1):
            token = _generate_new_token(uid, password)
            if token:
                with self.token_lock:
                    if server_name not in self.all_tokens:
                        self.all_tokens[server_name] = {}
                    self.all_tokens[server_name][uid] = {
                        'token': token,
                        'generated_at': time.time(),
                        'expires_at': time.time() + 8 * 3600  # 8 hours expiration
                    }
                stats.increment_tokens_generated()
                log_info(f"Generated token for UID {uid} on server {server_name} (attempt {attempt + 1})")
                return True
            
            if attempt < max_retries:
                wait_time = (attempt + 1) * 2  # Exponential backoff: 2, 4 seconds
                log_warning(f"Token generation failed for UID {uid}, retrying in {wait_time} seconds...")
                time.sleep(wait_time)
        
        stats.increment_tokens_failed()
        log_error(f"Failed to generate token for UID {uid} on server {server_name} after {max_retries + 1} attempts")
        return False

    def refresh_all_tokens(self):
        """Refresh all tokens that are about to expire."""
        log_info("Starting scheduled token refresh...")
        current_time = time.time()
        tokens_refreshed = 0
        
        with ThreadPoolExecutor(max_workers=5) as executor:  # Reduced workers to avoid rate limiting
            futures = []
            
            for server_name, tokens in self.all_tokens.items():
                credentials = self.credentials_cache.get(server_name, [])
                cred_dict = {cred['uid']: cred for cred in credentials}
                
                for uid, token_info in tokens.items():
                    # Refresh tokens that will expire in the next hour (after 7 hours)
                    if current_time > (token_info['generated_at'] + 7 * 3600):
                        if uid in cred_dict:
                            password = cred_dict[uid]['password']
                            futures.append(
                                executor.submit(self._generate_and_store_token_with_retry, server_name, uid, password, max_retries=2)
                            )
                            tokens_refreshed += 1
            
            # Wait for all tokens to be refreshed
            for future in futures:
                try:
                    future.result(timeout=60)  # Increased timeout for retries
                except Exception as e:
                    log_error(f"Error refreshing token: {e}")
        
        log_info(f"Completed scheduled token refresh. Refreshed {tokens_refreshed} tokens.")

    def start_token_refresh(self):
        """Start the background thread for token refresh."""
        if self.token_refresh_thread and self.token_refresh_thread.is_alive():
            return
        
        self.stop_refresh = False
        
        def refresh_scheduler():
            log_info("Token refresh scheduler started. Will check for token refresh every hour.")
            
            while not self.stop_refresh:
                try:
                    # Check every hour for tokens that need refreshing
                    time.sleep(3600)  # Sleep for 1 hour
                    
                    if not self.stop_refresh:
                        self.refresh_all_tokens()
                except Exception as e:
                    log_error(f"Error in token refresh scheduler: {e}")
                    time.sleep(300)  # Sleep for 5 minutes on error
        
        self.token_refresh_thread = threading.Thread(target=refresh_scheduler, daemon=True)
        self.token_refresh_thread.start()
        log_info("Token refresh scheduler started.")

    def stop_token_refresh(self):
        """Stop the token refresh scheduler."""
        self.stop_refresh = True
        if self.token_refresh_thread:
            self.token_refresh_thread.join(timeout=5)
        log_info("Token refresh scheduler stopped.")

    def get_token(self, server_name, uid):
        """Get a token from the cache."""
        with self.token_lock:
            if server_name in self.all_tokens and uid in self.all_tokens[server_name]:
                token_info = self.all_tokens[server_name][uid]
                # Check if token is still valid (has at least 1 hour left)
                if time.time() < (token_info['expires_at'] - 3600):
                    return token_info['token']
        
        # If token is not available or expired, try to generate a new one with retries
        credentials = self.load_credentials(server_name)
        if credentials:
            for cred in credentials:
                if cred['uid'] == uid:
                    # Try to generate token with retries
                    for attempt in range(3):  # Try up to 3 times
                        token = _generate_new_token(uid, cred['password'])
                        if token:
                            with self.token_lock:
                                if server_name not in self.all_tokens:
                                    self.all_tokens[server_name] = {}
                                self.all_tokens[server_name][uid] = {
                                    'token': token,
                                    'generated_at': time.time(),
                                    'expires_at': time.time() + 8 * 3600
                                }
                            stats.increment_tokens_generated()
                            return token
                        
                        if attempt < 2:  # Wait before retrying (except after last attempt)
                            time.sleep((attempt + 1) * 2)  # Exponential backoff
                    
                    stats.increment_tokens_failed()
        return None

# --- JWT Generation and Caching ---
import my_pb2
import output_pb2

SESSION = requests.Session()
# Note: Storing keys in code is not recommended for production environments.
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

credential_manager = CredentialManager(likes_per_batch=110)

def _generate_new_token(uid, password):
    """Helper function containing the logic to generate a new JWT token."""
    log_info(f"Attempting to generate new JWT token for UID: {uid}")
    token_data = getGuestAccessToken(uid, password)
    if not token_data or "access_token" not in token_data or not token_data["access_token"]:
        log_error(f"Failed to get Garena access token for UID: {uid}")
        return None

    access_token = token_data["access_token"]
    open_id = token_data["open_id"]

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    game_data = my_pb2.GameData()
    game_data.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    game_data.game_name = "Free Fire"
    game_data.game_version = 1
    game_data.version_code = "1.111.1"
    game_data.os_info = "iOS 18.4"
    game_data.device_type = "Handheld"
    game_data.user_id = str(uid)
    game_data.open_id = open_id
    game_data.access_token = access_token
    game_data.platform_type = 4
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    serialized_data = game_data.SerializeToString()
    padded_data = pad(serialized_data, AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(padded_data)
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive", "Accept-Encoding": "gzip", "Content-Type": "application/octet-stream",
        "Expect": "100-continue", "X-GA": "v1 1", "X-Unity-Version": "2018.4.11f1", "ReleaseVersion": "OB50",
    }

    try:
        # Add a small delay to avoid rate limiting
        time.sleep(0.1)
        
        response = SESSION.post(url, data=encrypted_data, headers=headers, timeout=30, verify=False)
        if response.status_code == 200:
            jwt_msg = output_pb2.Garena_420()
            jwt_msg.ParseFromString(response.content)
            if jwt_msg.token:
                log_info(f"Successfully generated new token for UID: {uid}")
                return jwt_msg.token
            else:
                log_error(f"Token generation succeeded but response contained no token for UID: {uid}")
                return None
        else:
            log_error(f"MajorLogin API returned status {response.status_code} for UID {uid}: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        log_error(f"Error during JWT request for UID {uid}: {e}")
        return None

def getGuestAccessToken(uid, password):
    headers = {
        "Host": "100067.connect.garena.com", "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "uid": str(uid), "password": str(password), "response_type": "token", "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    try:
        # Add a small delay to avoid rate limiting
        time.sleep(0.1)
        
        response = SESSION.post("https://100067.connect.garena.com/oauth/guest/token/grant",
                                headers=headers, data=data, verify=False, timeout=10)
        response.raise_for_status()
        data_response = response.json()
        if "error" in data_response:
             log_error(f"Auth error for UID {uid}: {data_response.get('error')}")
             return {"error": "auth_error"}
        return {"access_token": data_response.get("access_token"), "open_id": data_response.get("open_id")}
    except requests.exceptions.RequestException as e:
        log_error(f"Error getting guest access token for UID {uid}: {e}")
        return {"error": "request_failed"}

# --- Core Application Logic ---

def encrypt_message(plaintext):
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        log_error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        log_error(f"Error creating protobuf message: {e}")
        return None

async def send_request(session, encrypted_uid, token, url, semaphore):
    async with semaphore:
        try:
            edata = bytes.fromhex(encrypted_uid)
            headers = {
                'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)", 'Connection': "Keep-Alive",
                'Accept-Encoding': "gzip", 'Authorization': f"Bearer {token}", 'Content-Type': "application/x-www-form-urlencoded",
                'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': "OB50"
            }
            async with session.post(url, data=edata, headers=headers, timeout=30) as response:
                if response.status != 200:
                    log_error(f"Request failed with status code: {response.status}")
                    return response.status, token
                return await response.text(), token
        except asyncio.TimeoutError:
            log_error(f"Request timed out for token: {token[:20]}...if         return "timeout", token
        except Exception as e:
            log_error(f"Exception in send_request: {e}")
            return f"error: {str(e)}", token

async def send_multiple_requests(uid, server_name, url):
    try:
        protobuf_message = create_protobuf_message(uid, server_name)
        if not protobuf_message: 
            return None, 0, 0
        
        encrypted_uid = encrypt_message(protobuf_message)
        if not encrypted_uid: 
            return None, 0, 0

        credential_batch = credential_manager.get_next_batch(server_name)
        if not credential_batch:
            log_error(f"Could not get a batch of credentials for server {server_name}.")
            return None, 0, 0

        # Use semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(50)  # Limit to 50 concurrent requests
        
        tasks = []
        tokens_used = 0
        
        async with aiohttp.ClientSession() as session:
            for cred in credential_batch:
                token = credential_manager.get_token(server_name, cred['uid'])
                
                if token:
                    tokens_used += 1
                    tasks.append(send_request(session, encrypted_uid, token, url, semaphore))
                else:
                    log_warning(f"Could not get token for UID: {cred['uid']}. Skipping.")

            if not tasks:
                log_error("No valid JWT tokens could be found for the batch.")
                return None, 0, 0
            
            log_info(f"Sending a batch of {len(tasks)} like requests for UID {uid}.")
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Count successful requests
            successful_requests = 0
            for result in results:
                if isinstance(result, tuple) and not isinstance(result[0], (int, str)) and "error" not in str(result[0]).lower():
                    successful_requests += 1
            
            return results, tokens_used, time.time() + 7 * 3600  # Next refresh in 7 hours

    except Exception as e:
        log_error(f"Exception in send_multiple_requests: {e}")
        return None, 0, 0

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.uid = int(uid)
        message.value = 1
        return message.SerializeToString()
    except Exception as e:
        log_error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    return encrypt_message(protobuf_data) if protobuf_data else None

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)", 'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip", 'Authorization': f"Bearer {token}", 'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': "OB50"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=30)
        binary_content = response.content
        return decode_protobuf(binary_content)
    except Exception as e:
        log_error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        log_error(f"Error decoding Protobuf data: {e}")
        return None

# --- Keep Alive Endpoint for Render ---
@app.route('/up', methods=['GET'])
def keep_alive():
    return jsonify({"status": "alive", "timestamp": datetime.now().isoformat()})

# --- Check API Status Endpoint ---
@app.route('/check', methods=['GET'])
def check_status():
    """Endpoint to check API status and statistics"""
    try:
        # Get statistics
        statistics = stats.get_stats()
        
        # Check if we can load credentials for at least one server
        server_status = {}
        for server_name in credential_manager.credential_files.keys():
            credentials = credential_manager.load_credentials(server_name)
            server_status[server_name] = {
                "credentials_loaded": len(credentials) if credentials else 0,
                "tokens_available": len(credential_manager.all_tokens.get(server_name, {})) if server_name in credential_manager.all_tokens else 0
            }
        
        # Check if token refresh thread is alive
        token_refresh_active = credential_manager.token_refresh_thread and credential_manager.token_refresh_thread.is_alive()
        
        # Calculate token generation success rate
        total_attempts = statistics["tokens_generated"] + statistics["tokens_failed"]
        success_rate = (statistics["tokens_generated"] / total_attempts * 100) if total_attempts > 0 else 0
        
        return jsonify({
            "status": "online",
            "timestamp": datetime.now().isoformat(),
            "statistics": statistics,
            "server_status": server_status,
            "token_refresh_active": token_refresh_active,
            "total_servers": len(credential_manager.credential_files),
            "token_success_rate": f"{success_rate:.2f}%"
        })
    except Exception as e:
        log_error(f"Error in /check endpoint: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# --- API Endpoint ---

@app.route('/like', methods=['GET'])
def handle_requests():
    # Track request count
    stats.increment_requests()
    
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        # Use one credential for initial check
        initial_credentials = credential_manager.load_credentials(server_name)
        if not initial_credentials:
            return jsonify({"error": f"Failed to load credentials for {server_name}."}), 500

        token = credential_manager.get_token(server_name, initial_credentials[0]['uid'])
        if not token:
            return jsonify({"error": "Failed to get JWT token."}), 500

        encrypted_uid = enc(uid)
        if not encrypted_uid:
            return jsonify({"error": "Encryption of UID failed."}), 500

        # Get player data before sending likes
        before_proto = make_request(encrypted_uid, server_name, token)
        if not before_proto:
            return jsonify({"error": "Failed to retrieve initial player info."}), 500
        
        data_before = json.loads(MessageToJson(before_proto))
        before_like = int(data_before.get('AccountInfo', {}).get('Likes', 0))
        log_info(f"Likes before command for UID {uid}: {before_like}")

        # Determine correct URL based on server
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"

        # Send the batch of likes
        results, tokens_used, next_refresh_time = asyncio.run(send_multiple_requests(uid, server_name, url))
        
        # If no results, try once more
        if not results:
            log_warning("First attempt failed, retrying...")
            time.sleep(2)
            results, tokens_used, next_refresh_time = asyncio.run(send_multiple_requests(uid, server_name, url))

        # Get player data after sending likes
        after_proto = make_request(encrypted_uid, server_name, token)
        if not after_proto:
            return jsonify({"error": "Failed to retrieve player info after sending likes."}), 500
        
        data_after = json.loads(MessageToJson(after_proto))
        after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
        
        like_given = after_like - before_like
        
        # Calculate next refresh time in readable format
        next_refresh_readable = datetime.fromtimestamp(next_refresh_time).isoformat() if next_refresh_time > 0 else "Unknown"
        
        result = {
            "LikesGivenByAPI": like_given,
            "LikesbeforeCommand": before_like,
            "LikesafterCommand": after_like,
            "PlayerNickname": data_after.get('AccountInfo', {}).get('PlayerNickname', ''),
            "PlayerRegion": data_after.get('AccountInfo', {}).get('region', ''),
            "PlayerLevel": data_after.get('AccountInfo', {}).get('level', ''),
            "UID": data_after.get('AccountInfo', {}).get('UID', 0),
            "TokensUsed": tokens_used,
            "NextTokenRefreshTime": next_refresh_readable,
            "status": 1 if like_given > 0 else 2
        }
        return jsonify(result)

    except Exception as e:
        log_error(f"Unhandled error in /like endpoint: {e}")
        return jsonify({"error": "An internal server error occurred.", "details": str(e)}), 500

# Initialize the application
def initialize_app():
    """Initialize the application by loading credentials and generating tokens."""
    log_info("Initializing application...")
    
    # Load all credentials
    for server_name in credential_manager.credential_files.keys():
        credential_manager.load_credentials(server_name)
    
    # Generate all tokens
    credential_manager.initialize_all_tokens()
    
    log_info("Application initialization completed.")

import os

if __name__ == '__main__':
    initialize_app()
    port = int(os.environ.get("PORT", 5000))  # Render assigns port dynamically
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False, threaded=True)lse
