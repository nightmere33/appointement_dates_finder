import time
import requests
import datetime
import json
import logging
import sqlite3
import threading
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from typing import List, Optional

# ===== LOGGING CONFIG =====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('appointment_monitor.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ===== CONFIG =====
BOT_TOKEN = "8107645453:AAHrB9qphlEdujfkTOAhHEcAkUqPuJsOKmk"

# ===== CREDENTIALS =====
USERNAME = "Green_mariaz14064@gmx.com"
PASSWORD = "Shevel2025"
CASE_ID = "0616A463-0E2A-4DCA-B3C6-574C9ACA6343"

# ===== TOR BROWSER PROXY =====
TOR_PROXIES = {
    'http': 'socks5h://127.0.0.1:9150',
    'https': 'socks5h://127.0.0.1:9150'
}

class UserManager:
    def __init__(self, db_path="users.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                chat_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def add_user(self, chat_id, username=None, first_name=None):
        """Add a user to the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO users (chat_id, username, first_name)
            VALUES (?, ?, ?)
        ''', (chat_id, username, first_name))
        conn.commit()
        conn.close()
    
    def get_all_users(self):
        """Get all registered users."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT chat_id FROM users')
        users = [row[0] for row in cursor.fetchall()]
        conn.close()
        return users
    
    def user_exists(self, chat_id):
        """Check if user exists."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM users WHERE chat_id = ?', (chat_id,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists

class WorkingAppointmentMonitor:
    def __init__(self, bot_token: str, username: str, password: str, case_id: str):
        self.bot_token = bot_token
        self.user_manager = UserManager()
        self.username = username
        self.password = password
        self.case_id = case_id
        self.base_url = "https://inpol.mazowieckie.pl/api/reservations/queue/c93674d6-fb24-4a85-9dac-61897dc8f060/dates"
        self.last_alert_dates = set()
        self.session = requests.Session()
        self.auth_token = None
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Set basic headers
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "pl-PL,pl;q=0.9,en;q=0.8",
            "Origin": "https://inpol.mazowieckie.pl",
            "Content-Type": "application/json",
            "RecaptchaActionName": "reservations_queue_dates",
        })

    def setup_selenium_with_tor(self):
        """Setup Selenium to use Tor Browser with longer timeouts."""
        chrome_options = Options()
        chrome_options.add_argument('--proxy-server=socks5://127.0.0.1:9150')
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        
        # Enable performance logging for network monitoring
        chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
        
        # Set page load timeout
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(60)
        driver.implicitly_wait(10)
        
        # FIXED: Correct JavaScript syntax
        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        
        return driver

    def wait_for_element(self, driver, by, value, timeout=30):
        """Wait for element to be present and visible."""
        return WebDriverWait(driver, timeout).until(
            EC.visibility_of_element_located((by, value))
        )

    def find_element_with_multiple_selectors(self, driver, selectors, by=By.CSS_SELECTOR):
        """Try multiple selectors to find an element."""
        for selector in selectors:
            try:
                if by == By.CSS_SELECTOR:
                    element = driver.find_element(By.CSS_SELECTOR, selector)
                elif by == By.XPATH:
                    element = driver.find_element(By.XPATH, selector)
                elif by == By.CLASS_NAME:
                    element = driver.find_element(By.CLASS_NAME, selector)
                elif by == By.TAG_NAME:
                    element = driver.find_element(By.TAG_NAME, selector)
                
                if element.is_displayed() and element.is_enabled():
                    return element
            except:
                continue
        return None

    def debug_page_state(self, driver):
        """Debug method to log current page state."""
        try:
            logging.info("[DEBUG] Current URL: " + driver.current_url)
            logging.info("[DEBUG] Page title: " + driver.title)
            
            # Check for common elements
            elements_to_check = [
                "mat-select[name='location']",
                "mat-select[name='queueName']", 
                ".btn--accordion",
                "direct-case-appointment"
            ]
            
            for selector in elements_to_check:
                try:
                    elements = driver.find_elements(By.CSS_SELECTOR, selector)
                    logging.info(f"[DEBUG] Found {len(elements)} elements for selector: {selector}")
                except:
                    logging.info(f"[DEBUG] No elements found for selector: {selector}")
                    
        except Exception as e:
            logging.error(f"[DEBUG] Error debugging page state: {e}")

    def get_auth_token_from_storage(self, driver):
        """Extract JWT token from browser's local storage with more keys."""
        try:
            # Try many possible storage keys
            storage_keys = [
                "auth_token", "token", "access_token", "jwt_token", "authToken", "accessToken",
                "id_token", "user_token", "session_token", "bearer_token", "oauth_token",
                "auth", "authentication", "jwt", "access", "user", "session",
                "ng2-ui-auth_token", "angular2-jwt_token", "adal.token.keys"
            ]
            
            for key in storage_keys:
                try:
                    token = driver.execute_script(f"return window.localStorage.getItem('{key}');")
                    if token and len(token) > 100:  # JWT tokens are typically long
                        logging.info(f"[AUTH] Found auth token with key: {key}")
                        return f"Bearer {token}"
                except:
                    continue
                    
            logging.warning("[AUTH] No auth token found in local storage")
            return None
            
        except Exception as e:
            logging.error(f"[AUTH] Error getting token from storage: {e}")
            return None

    def get_auth_token_from_session_storage(self, driver):
        """Extract JWT token from session storage."""
        try:
            storage_keys = [
                "auth_token", "token", "access_token", "jwt_token", "authToken", "accessToken"
            ]
            
            for key in storage_keys:
                try:
                    token = driver.execute_script(f"return window.sessionStorage.getItem('{key}');")
                    if token and len(token) > 100:
                        logging.info(f"[AUTH] Found auth token in session storage with key: {key}")
                        return f"Bearer {token}"
                except:
                    continue
                    
            return None
            
        except Exception as e:
            logging.error(f"[AUTH] Error getting token from session storage: {e}")
            return None

    def get_auth_token_from_angular(self, driver):
        """Try to extract auth token from Angular context."""
        try:
            # Try to access Angular services or common patterns
            scripts = [
                "return window.localStorage.getItem('ngx-auth-token');",
                "return window.sessionStorage.getItem('ngx-auth-token');",
                "return JSON.parse(localStorage.getItem('auth')).access_token;",
                "return JSON.parse(localStorage.getItem('user')).token;",
                "return JSON.parse(localStorage.getItem('currentUser')).token;",
                "return window.__APOLLO_CLIENT__?.token;",
            ]
            
            for script in scripts:
                try:
                    token = driver.execute_script(script)
                    if token and len(token) > 100:
                        logging.info("[AUTH] Found auth token via script")
                        return f"Bearer {token}"
                except:
                    continue
                    
            return None
            
        except Exception as e:
            logging.error(f"[AUTH] Error getting token from Angular: {e}")
            return None

    def get_auth_token_from_network_logs(self, driver):
        """Extract auth token from network logs."""
        try:
            # Get performance logs
            logs = driver.get_log('performance')
            auth_token = None
            
            for log in logs:
                try:
                    message = json.loads(log['message'])['message']
                    if message['method'] == 'Network.requestWillBeSent':
                        request = message['params']['request']
                        url = request.get('url', '')
                        
                        # Look for the dates API URL
                        if 'reservations/queue' in url and 'dates' in url:
                            headers = request.get('headers', {})
                            if 'Authorization' in headers:
                                auth_token = headers['Authorization']
                                logging.info("[AUTH] Found Authorization header in network logs")
                                break
                except:
                    continue
                    
            return auth_token
            
        except Exception as e:
            logging.error(f"[AUTH] Error getting token from network logs: {e}")
            return None

    def trigger_api_call_manually(self, driver):
        """Manually trigger the API call by reselecting the queue."""
        try:
            logging.info("[API] Manually triggering API call by reselecting queue...")
            
            # Find and click queue dropdown again
            queue_selectors = [
                "mat-select[name='queueName']",
                "//mat-select[@name='queueName']", 
            ]
            
            queue_dropdown = self.find_element_with_multiple_selectors(driver, queue_selectors)
            if queue_dropdown:
                # First deselect by clicking outside
                body = driver.find_element(By.TAG_NAME, "body")
                body.click()
                time.sleep(2)
                
                # Then reselect the queue
                driver.execute_script("arguments[0].click();", queue_dropdown)
                time.sleep(2)
                
                # Select the same option again
                queue_option_selectors = [
                    "//mat-option[.//span[contains(text(), 'F - applications for TEMPORARY STAY')]]",
                    "//mat-option[contains(., 'F - applications')]",
                ]
                
                queue_option = self.find_element_with_multiple_selectors(driver, queue_option_selectors, By.XPATH)
                if queue_option:
                    driver.execute_script("arguments[0].click();", queue_option)
                    logging.info("[API] Reselected queue to trigger API call")
                    time.sleep(5)
                    return True
            
            return False
            
        except Exception as e:
            logging.error(f"[API] Error triggering API call: {e}")
            return False

    def perform_angular_interaction(self, driver) -> bool:
        """Perform the necessary Angular Material interactions to activate the dates API."""
        try:
            logging.info("[ANGULAR] Starting Angular Material interactions...")
            
            # Debug current state
            self.debug_page_state(driver)
            
            # First, let's wait for the page to fully load the Angular components
            time.sleep(5)
            
            # Step 1: Find and click the expand button (keyboard_arrow_up icon)
            # The button is inside a button with class "btn btn--accordion"
            expand_selectors = [
                "button.btn--accordion",
                "//button[contains(@class, 'btn--accordion')]",
                "//button[.//mat-icon[contains(text(), 'keyboard_arrow_up')]]",
                "//span[.//mat-icon[contains(text(), 'keyboard_arrow_up')]]/..",
                ".accordion__icon",
            ]
            
            expand_button = self.find_element_with_multiple_selectors(driver, expand_selectors)
            if expand_button:
                logging.info("[ANGULAR] Found expand button, clicking...")
                # Scroll into view first
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", expand_button)
                time.sleep(1)
                
                # Try multiple click methods
                try:
                    expand_button.click()
                except:
                    driver.execute_script("arguments[0].click();", expand_button)
                
                logging.info("[ANGULAR] Clicked expand button")
                time.sleep(3)
                
                # Wait for the content to expand
                WebDriverWait(driver, 10).until(
                    EC.visibility_of_element_located((By.CSS_SELECTOR, "mat-select[name='location']"))
                )
                logging.info("[ANGULAR] Dropdowns should now be visible")
            else:
                logging.error("[ANGULAR] Could not find expand button!")
                # Try to find the dropdowns anyway in case they're already visible
                logging.info("[ANGULAR] Trying to find dropdowns without expanding...")
            
            # Step 2: Find and interact with the location dropdown
            location_selectors = [
                "mat-select[name='location']",
                "//mat-select[@name='location']",
                "//mat-form-field[.//mat-label[contains(text(), 'Please select a location')]]//mat-select",
            ]
            
            location_dropdown = self.find_element_with_multiple_selectors(driver, location_selectors)
            if location_dropdown:
                # Check if dropdown is visible and enabled
                if location_dropdown.is_displayed() and location_dropdown.is_enabled():
                    # Scroll into view and click using JavaScript
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", location_dropdown)
                    time.sleep(1)
                    driver.execute_script("arguments[0].click();", location_dropdown)
                    logging.info("[ANGULAR] Opened location dropdown")
                    time.sleep(3)
                    
                    # Wait for options to appear and select "Al. Jerozolimskie 28, 00-024 Warszawa"
                    location_option_selectors = [
                        "//mat-option[.//span[contains(text(), 'Al. Jerozolimskie 28')]]",
                        "//mat-option[contains(., 'Al. Jerozolimskie 28')]",
                        "//mat-option[contains(., 'Jerozolimskie')]",
                        "mat-option:first-of-type",
                    ]
                    
                    location_option = self.find_element_with_multiple_selectors(driver, location_option_selectors, By.XPATH)
                    if location_option:
                        driver.execute_script("arguments[0].click();", location_option)
                        logging.info("[ANGULAR] Selected location option")
                        time.sleep(3)
                    else:
                        logging.warning("[ANGULAR] Could not find location option, taking screenshot for debug")
                        driver.save_screenshot("location_options_debug.png")
                        # Try to get the first available option as fallback
                        try:
                            first_option = WebDriverWait(driver, 5).until(
                                EC.presence_of_element_located((By.CSS_SELECTOR, "mat-option"))
                            )
                            driver.execute_script("arguments[0].click();", first_option)
                            logging.info("[ANGULAR] Selected first available location option as fallback")
                            time.sleep(3)
                        except:
                            logging.error("[ANGULAR] Could not select any location option")
                else:
                    logging.error("[ANGULAR] Location dropdown is not visible or enabled")
                    driver.save_screenshot("location_dropdown_not_visible.png")
                    return False
            else:
                logging.error("[ANGULAR] Could not find location dropdown")
                driver.save_screenshot("location_dropdown_debug.png")
                return False
            
            # Step 3: Find and interact with the queue dropdown
            queue_selectors = [
                "mat-select[name='queueName']",
                "//mat-select[@name='queueName']", 
                "//mat-form-field[.//mat-label[contains(text(), 'Please select a queue')]]//mat-select",
            ]
            
            queue_dropdown = self.find_element_with_multiple_selectors(driver, queue_selectors)
            if queue_dropdown:
                if queue_dropdown.is_displayed() and queue_dropdown.is_enabled():
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", queue_dropdown)
                    time.sleep(1)
                    driver.execute_script("arguments[0].click();", queue_dropdown)
                    logging.info("[ANGULAR] Opened queue dropdown")
                    time.sleep(3)
                    
                    # Select the queue option (F - applications for TEMPORARY STAY)
                    queue_option_selectors = [
                        "//mat-option[.//span[contains(text(), 'F - applications for TEMPORARY STAY')]]",
                        "//mat-option[contains(., 'F - applications')]",
                        "//mat-option[contains(., 'TEMPORARY STAY')]",
                        "mat-option:nth-of-type(2)",
                    ]
                    
                    queue_option = self.find_element_with_multiple_selectors(driver, queue_option_selectors, By.XPATH)
                    if queue_option:
                        driver.execute_script("arguments[0].click();", queue_option)
                        logging.info("[ANGULAR] Selected queue option")
                        time.sleep(5)
                        
                        # Manually trigger API call by reselecting
                        self.trigger_api_call_manually(driver)
                        
                    else:
                        logging.warning("[ANGULAR] Could not find queue option, taking screenshot")
                        driver.save_screenshot("queue_options_debug.png")
                        # Try to get the first available queue option as fallback
                        try:
                            first_queue_option = WebDriverWait(driver, 5).until(
                                EC.presence_of_element_located((By.CSS_SELECTOR, "div[role='listbox'] mat-option"))
                            )
                            driver.execute_script("arguments[0].click();", first_queue_option)
                            logging.info("[ANGULAR] Selected first available queue option as fallback")
                            time.sleep(5)
                            
                            # Manually trigger API call by reselecting
                            self.trigger_api_call_manually(driver)
                            
                        except:
                            logging.error("[ANGULAR] Could not select any queue option")
                            return False
                else:
                    logging.error("[ANGULAR] Queue dropdown is not visible or enabled")
                    driver.save_screenshot("queue_dropdown_not_visible.png")
                    return False
            else:
                logging.error("[ANGULAR] Could not find queue dropdown")
                driver.save_screenshot("queue_dropdown_debug.png")
                return False
            
            # Additional wait for the API to be activated
            logging.info("[ANGULAR] Waiting for dates API to activate...")
            time.sleep(10)
            
            # Take a final screenshot to verify the state
            driver.save_screenshot("final_state_debug.png")
            
            return True
            
        except Exception as e:
            logging.error(f"[ANGULAR] Interaction failed: {e}")
            if driver:
                driver.save_screenshot("angular_error.png")
            return False

    def automated_login_with_selenium(self) -> Optional[dict]:
        """Use Selenium to automatically login and perform Angular interactions."""
        driver = None
        try:
            logging.info("[SELENIUM] Starting automated login...")
            driver = self.setup_selenium_with_tor()
            
            # Step 1: Go to login page
            logging.info("[SELENIUM] Loading login page...")
            driver.get("https://inpol.mazowieckie.pl/")
            
            WebDriverWait(driver, 45).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            logging.info("[SELENIUM] Page loaded successfully")
            time.sleep(5)
            
            # Step 2: Login
            logging.info("[SELENIUM] Looking for login form...")
            
            email_selectors = [
                "input[type='email']",
                "input[name='email']",
                "input[name='username']",
                "input[id*='email']",
                "input[placeholder*='email']",
                "#email",
                ".email",
                "input",
            ]
            
            email_field = self.find_element_with_multiple_selectors(driver, email_selectors)
            if not email_field:
                driver.save_screenshot("login_page_debug.png")
                logging.error("[SELENIUM] Could not find email field")
                return None
            
            email_field.clear()
            email_field.send_keys(self.username)
            logging.info("[SELENIUM] Filled email")
            time.sleep(2)
            
            password_selectors = [
                "input[type='password']",
                "input[name='password']",
                "input[id*='password']",
                "input[placeholder*='password']",
                "#password",
                ".password",
            ]
            
            password_field = self.find_element_with_multiple_selectors(driver, password_selectors)
            if not password_field:
                logging.error("[SELENIUM] Could not find password field")
                return None
            
            password_field.clear()
            password_field.send_keys(self.password)
            logging.info("[SELENIUM] Filled password")
            time.sleep(2)
            
            # Login button selectors
            login_button_selectors = [
                "button.btn--submit",
                "button.btn",
                "//button[contains(text(), 'Sign In')]",
                "//button[contains(text(), 'Sign in')]",
                "//button[contains(text(), 'Login')]",
                "//button[contains(text(), 'Log in')]",
                "//button[contains(text(), 'Zaloguj')]",
                "button[type='submit']",
                "input[type='submit']",
            ]
            
            login_button = self.find_element_with_multiple_selectors(driver, login_button_selectors)
            if not login_button:
                driver.save_screenshot("login_button_debug.png")
                logging.error("[SELENIUM] Could not find login button")
                return None
            
            logging.info("[SELENIUM] Found login button, clicking...")
            driver.execute_script("arguments[0].click();", login_button)
            logging.info("[SELENIUM] Clicked login button")
            time.sleep(10)
            
            # Check if login successful
            if "cases" in driver.current_url or "home" in driver.current_url:
                logging.info("[SELENIUM] Login successful!")
                
                # Navigate to case page
                case_url = f"https://inpol.mazowieckie.pl/home/cases/{self.case_id}"
                driver.get(case_url)
                time.sleep(5)
                
                # Perform Angular interactions
                if not self.perform_angular_interaction(driver):
                    logging.warning("[SELENIUM] Angular interactions may have failed, but continuing...")
                
                # Get all cookies
                cookies = {}
                for cookie in driver.get_cookies():
                    cookies[cookie['name']] = cookie['value']
                
                logging.info(f"[SELENIUM] Got {len(cookies)} cookies")
                
                # Try multiple methods to get auth token
                auth_token = None
                
                # Method 1: Try to extract from local storage with more keys
                auth_token = self.get_auth_token_from_storage(driver)
                
                # Method 2: Try to extract from session storage
                if not auth_token:
                    auth_token = self.get_auth_token_from_session_storage(driver)
                
                # Method 3: Try to execute JavaScript to get token from Angular context
                if not auth_token:
                    auth_token = self.get_auth_token_from_angular(driver)
                
                # Method 4: Try to get from network logs
                if not auth_token:
                    auth_token = self.get_auth_token_from_network_logs(driver)
                
                if auth_token:
                    logging.info(f"[AUTH] Successfully extracted auth token: {auth_token[:50]}...")
                else:
                    logging.warning("[AUTH] Could not extract auth token")
                
                # Prepare authentication data
                auth_data = {
                    'cookies': cookies,
                    'referer': driver.current_url,
                    'user_agent': driver.execute_script("return navigator.userAgent;"),
                    'auth_token': auth_token
                }
                
                return auth_data
            else:
                logging.error(f"[SELENIUM] Login failed - current URL: {driver.current_url}")
                driver.save_screenshot("login_failed.png")
                return None
                
        except Exception as e:
            logging.error(f"[SELENIUM] Automated login failed: {e}")
            if driver:
                driver.save_screenshot("selenium_error.png")
            return None
        finally:
            if driver:
                driver.quit()

    def get_fresh_authentication(self) -> bool:
        """Get fresh authentication using Selenium automation."""
        logging.info("[AUTH] Getting fresh authentication via Selenium...")
        
        max_attempts = 2
        for attempt in range(max_attempts):
            logging.info(f"[AUTH] Attempt {attempt + 1}/{max_attempts}")
            
            auth_data = self.automated_login_with_selenium()
            if auth_data:
                # Update session with new cookies
                for cookie_name, cookie_value in auth_data['cookies'].items():
                    self.session.cookies.set(cookie_name, cookie_value)
                
                # Update headers
                self.session.headers["Referer"] = auth_data['referer']
                self.session.headers["User-Agent"] = auth_data['user_agent']
                
                # Set auth token if found
                if auth_data.get('auth_token'):
                    self.auth_token = auth_data['auth_token']
                    self.session.headers["Authorization"] = self.auth_token
                    logging.info("[AUTH] Added Authorization header")
                
                logging.info("[AUTH] Successfully updated authentication")
                return True
            else:
                if attempt < max_attempts - 1:
                    wait_time = 10
                    logging.info(f"[AUTH] Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
        
        logging.error("[AUTH] All authentication attempts failed")
        return False

    def test_tor_connection(self) -> bool:
        """Test if Tor connection is working."""
        try:
            response = self.session.get(
                'https://httpbin.org/ip', 
                proxies=TOR_PROXIES, 
                timeout=10
            )
            logging.info(f"[TOR] Connected via IP: {response.json().get('ip', 'Unknown')}")
            return True
        except Exception as e:
            logging.error(f"[TOR] Connection failed: {e}")
            return False

    def fetch_available_dates(self) -> Optional[List[str]]:
        """Fetch available appointment dates."""
        try:
            # Make sure we have the auth header
            if self.auth_token and "Authorization" not in self.session.headers:
                self.session.headers["Authorization"] = self.auth_token
            
            response = self.session.post(
                self.base_url, 
                proxies=TOR_PROXIES, 
                timeout=20
            )
            
            if response.status_code == 200:
                dates = response.json()
                logging.info(f"[SUCCESS] Found {len(dates)} available dates")
                return dates
            elif response.status_code in [401, 403]:
                logging.warning(f"[AUTH] {response.status_code} - Authentication needed")
                return None
            else:
                logging.error(f"[ERROR] HTTP {response.status_code}: {response.text}")
                return None
                
        except Exception as e:
            logging.error(f"[ERROR] Network error: {e}")
            return None

    def send_telegram_message(self, text: str, chat_id: str = None) -> bool:
        """Send a message to specified Telegram chat ID or all registered users."""
        success = True
        
        if chat_id:
            # Send to specific chat ID
            chat_ids = [chat_id]
        else:
            # Send to all registered users
            chat_ids = self.user_manager.get_all_users()
        
        for target_chat_id in chat_ids:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            payload = {
                "chat_id": target_chat_id,
                "text": text,
                "parse_mode": "HTML"
            }

            try:
                response = requests.post(url, data=payload, timeout=10)
                response.raise_for_status()
                logging.info(f"[SUCCESS] Telegram message sent to chat ID: {target_chat_id}!")
            except Exception as e:
                logging.error(f"[ERROR] Telegram send failed to {target_chat_id}: {e}")
                success = False
        
        return success

    def format_dates_list(self, dates: List[str]) -> str:
        """Format dates with Poland flag and group by month with simple separators."""
        try:
            # Parse and sort dates
            parsed_dates = []
            for date_str in dates:
                date_obj = datetime.datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                parsed_dates.append(date_obj)
            
            parsed_dates.sort()
            
            # Group dates by month
            months = {}
            for date_obj in parsed_dates:
                month_key = date_obj.strftime("%Y-%m")  # Year-Month as key
                if month_key not in months:
                    months[month_key] = []
                months[month_key].append(date_obj.strftime("🇵🇱 %d/%m/%Y"))
            
            # Build formatted string with month separators
            formatted_parts = []
            for month_key in sorted(months.keys()):
                formatted_parts.extend(months[month_key])
                formatted_parts.append("───────")  # Separator line
            
            # Remove the last separator
            if formatted_parts and formatted_parts[-1] == "───────":
                formatted_parts.pop()
                
            return "\n".join(formatted_parts)
            
        except Exception as e:
            logging.error(f"[ERROR] Formatting dates: {e}")
            return "\n".join(dates)

    def format_message(self, new_dates: List[str]) -> str:
        """Format a Telegram message with dates grouped by month."""
        try:
            dates_list = self.format_dates_list(new_dates)
            
            message = (
                "🏛️ <b>Lokalizacja:</b> Mazowieckie, Polska\n"
                "📋 <b>Usługa:</b> Zezwolenie na pobyt\n\n"
                f"{dates_list}\n\n"
                f"📊 <i>Łącznie dostępnych terminów: {len(new_dates)}</i>\n"
                "⚡ <i>Szybko rezerwuj!</i>\n"
                f"🔗 <a href='https://inpol.mazowieckie.pl/'>Rezerwuj teraz</a>"
            )
            return message
        except Exception as e:
            logging.error(f"[ERROR] Formatting message: {e}")
            return f"Nowe terminy: {', '.join(new_dates)}"

    def handle_telegram_commands(self):
        """Handle incoming Telegram commands in a separate thread."""
        last_update_id = 0
        
        while self.is_monitoring:
            try:
                url = f"https://api.telegram.org/bot{self.bot_token}/getUpdates"
                params = {'offset': last_update_id + 1, 'timeout': 30}
                response = requests.get(url, params=params, timeout=35)
                data = response.json()
                
                if data['ok']:
                    for update in data['result']:
                        last_update_id = update['update_id']
                        
                        if 'message' in update and 'text' in update['message']:
                            message = update['message']
                            chat_id = message['chat']['id']
                            text = message['text']
                            username = message['chat'].get('username')
                            first_name = message['chat'].get('first_name', 'User')
                            
                            if text.startswith('/start'):
                                self.user_manager.add_user(chat_id, username, first_name)
                                welcome_msg = (
                                    f"👋 Witaj {first_name}!\n\n"
                                    "✅ Zostałeś zarejestrowany w systemie monitorowania terminów.\n"
                                    "📅 Otrzymasz powiadomienia gdy tylko pojawią się nowe terminy.\n\n"
                                    "🔔 Bądź gotowy do szybkiej rezerwacji!\n\n"
                                    "ℹ️ Użyj /help aby zobaczyć dostępne komendy."
                                )
                                self.send_telegram_message(welcome_msg, chat_id)
                                logging.info(f"New user registered: {first_name} (ID: {chat_id})")
                            
                            elif text.startswith('/status'):
                                status_msg = (
                                    "📊 <b>Status monitora terminów</b>\n\n"
                                    f"🔍 Aktywne monitorowanie: {'✅ Tak' if self.is_monitoring else '❌ Nie'}\n"
                                    f"📅 Ostatnie znane terminy: {len(self.last_alert_dates)}\n"
                                    f"👥 Zarejestrowani użytkownicy: {len(self.user_manager.get_all_users())}\n\n"
                                    "⚡ Bot automatycznie powiadamia o nowych terminach!"
                                )
                                self.send_telegram_message(status_msg, chat_id)
                            
                            elif text.startswith('/help'):
                                help_msg = (
                                    "📋 <b>Dostępne komendy:</b>\n\n"
                                    "/start - Zarejestruj się do powiadomień\n"
                                    "/status - Sprawdź status monitora\n"
                                    "/help - Wyświetl tę wiadomość\n\n"
                                    "🔔 Bot automatycznie powiadamia o nowych terminach!"
                                )
                                self.send_telegram_message(help_msg, chat_id)
            
            except Exception as e:
                logging.error(f"[TELEGRAM] Command handler error: {e}")
                time.sleep(5)
    
    def start_telegram_handler(self):
        """Start the Telegram command handler in a separate thread."""
        self.is_monitoring = True
        handler_thread = threading.Thread(target=self.handle_telegram_commands)
        handler_thread.daemon = True
        handler_thread.start()
        logging.info("[TELEGRAM] Command handler started")

    def monitor_available_dates(self, check_interval: int = 300) -> None:
        """Monitor for new available appointment dates."""
        logging.info("[START] Working Appointment Monitor started...")
        logging.info(f"[INFO] Refresh interval: {check_interval} seconds")
        
        # Start Telegram command handler
        self.start_telegram_handler()
        
        if not self.test_tor_connection():
            logging.error("[ERROR] Tor connection failed!")
            return

        # Get initial authentication
        if not self.get_fresh_authentication():
            logging.error("[ERROR] Initial authentication failed!")
            return

        check_count = 0
        consecutive_failures = 0
        max_failures_before_reauth = 2
        
        while True:
            try:
                check_count += 1
                logging.info(f"[CHECK] Check #{check_count}...")
                
                dates = self.fetch_available_dates()
                
                if dates is None:
                    consecutive_failures += 1
                    logging.info(f"[AUTH] Failed ({consecutive_failures}/{max_failures_before_reauth})")
                    
                    if consecutive_failures >= max_failures_before_reauth:
                        logging.info("[AUTH] Re-authenticating...")
                        if self.get_fresh_authentication():
                            consecutive_failures = 0
                            logging.info("[AUTH] Re-authentication successful!")
                        else:
                            logging.error("[AUTH] Re-authentication failed!")
                    
                elif not dates:
                    consecutive_failures = 0
                    logging.info("[INFO] No dates available")
                else:
                    consecutive_failures = 0
                    current_dates = set(dates)
                    new_dates = list(current_dates - self.last_alert_dates)
                    
                    if new_dates:
                        logging.info(f"[FOUND] {len(new_dates)} new date(s)!")
                        message = self.format_message(new_dates)
                        
                        if self.send_telegram_message(message):
                            self.last_alert_dates = current_dates
                            logging.info(f"[SUCCESS] Alert sent to {len(self.user_manager.get_all_users())} users for {len(new_dates)} dates")
                        else:
                            logging.error("[ERROR] Failed to send Telegram alert")
                    else:
                        if check_count % 5 == 0:
                            logging.info(f"[INFO] No new dates. Tracking {len(self.last_alert_dates)} known dates")
                
                logging.info(f"[WAIT] Waiting {check_interval} seconds...")
                time.sleep(check_interval)

            except KeyboardInterrupt:
                logging.info("[STOP] Monitor stopped by user")
                break
            except Exception as e:
                logging.error(f"[ERROR] Unexpected error: {e}")
                consecutive_failures += 1
                time.sleep(check_interval)

def monitor():
    monitor = WorkingAppointmentMonitor(
        BOT_TOKEN, 
        USERNAME,
        PASSWORD,
        CASE_ID
    )
    monitor.monitor_available_dates(check_interval=300)

if __name__ == "__main__":
    monitor()