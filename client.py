import requests

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from urllib.parse import urljoin


class OmadaClient:
    def __init__(self, base_url, client_id, client_secret, omadac_id, username, password, verify_ssl=False, debug=False):
        self.base_url = base_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.omadac_id = omadac_id
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.debug = debug

        self.csrf_token = None
        self.session_id = None
        self.authorization_code = None
        self.access_token = None
        self.refresh_token = None

        logger.info(f"Initialized OmadaClient for Omada Controller at {self.base_url}")

    def _log_debug(self, message, data=None):
        if self.debug:
            if data:
                logger.debug(f"{message}: {data}")
            else:
                logger.debug(message)

    def login(self):
        login_url = urljoin(
            self.base_url,
            f'/openapi/authorize/login?client_id={self.client_id}&omadac_id={self.omadac_id}'
        )
        body = {
            "username": self.username,
            "password": self.password
        }

        self._log_debug("Sending login request to", login_url)
        response = requests.post(login_url, json=body, verify=self.verify_ssl)
        self._log_debug("Login response", response.text)

        if response.status_code != 200:
            logger.error(f'Login failed with status code {response.status_code}')
            response.raise_for_status()

        data = response.json()
        if data.get("errorCode") != 0:
            logger.error(f'Login error: {data.get("msg")}')
            raise RuntimeError(f'Login failed: {data.get("msg")}')

        result = data.get("result", {})
        self.csrf_token = result.get("csrfToken")
        self.session_id = result.get("sessionId")

        if not self.csrf_token or not self.session_id:
            logger.error("Login response missing csrfToken or sessionId")
            raise RuntimeError("Missing csrfToken or sessionId in login response")

        logger.info("Login successful")
        return True

    def get_authorization_code(self, response_type="code"):
        if not self.csrf_token or not self.session_id:
            raise RuntimeError("You must login first to get csrfToken and sessionId")

        auth_code_url = urljoin(
            self.base_url,
            f'/openapi/authorize/code?client_id={self.client_id}&omadac_id={self.omadac_id}&response_type={response_type}'
        )
        headers = {
            "Content-Type": "application/json",
            "Csrf-Token": self.csrf_token,
            "Cookie": f"TPOMADA_SESSIONID={self.session_id}"
        }

        self._log_debug("Requesting authorization code from", auth_code_url)
        response = requests.post(auth_code_url, headers=headers, verify=self.verify_ssl)
        self._log_debug("Authorization code response", response.text)

        if response.status_code != 200:
            logger.error(f'Get authorization code failed with status code {response.status_code}')
            response.raise_for_status()

        data = response.json()
        if data.get("errorCode") != 0:
            logger.error(f'Get authorization code error: {data.get("msg")}')
            raise RuntimeError(f'Failed to get authorization code: {data.get("msg")}')

        auth_code = data.get("result")
        if not auth_code:
            logger.error("Authorization code not received in response")
            raise RuntimeError("No authorization code received")

        logger.info("Authorization code obtained successfully")
        self.authorization_code = auth_code
        return self.authorization_code

    def get_access_token(self):
        if not self.client_id or not self.client_secret or not self.authorization_code:
            raise RuntimeError("You must get an authorization code first to get access token")

        access_token_url = urljoin(
            self.base_url,
            f'/openapi/authorize/token?grant_type=authorization_code&code={self.authorization_code}'
        )

        body = {
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        self._log_debug("Requesting access token from", access_token_url)
        response = requests.post(access_token_url, json=body, verify=self.verify_ssl)
        self._log_debug("Access token response", response.text)

        if response.status_code != 200:
            logger.error(f'Access token request failed with status code {response.status_code}')
            response.raise_for_status()

        data = response.json()
        if data.get("errorCode") != 0:
            logger.error(f'Access token error: {data.get("msg")}')
            raise RuntimeError(f'Access token failed: {data.get("msg")}')

        result = data.get("result", {})
        self.access_token = result.get("accessToken")
        self.refresh_token = result.get("refreshToken")

        if not self.access_token or not self.refresh_token:
            logger.error("Missing access_token or refresh_token in response")
            raise RuntimeError("Missing access_token or refresh_token in Access token response")

        logger.info("Access token obtained successfully")
        return self.access_token

    def get_sites(self, page_size=1, page=1):
        if not self.access_token:
            raise RuntimeError("Access token is not set. Obtain it first.")

        url = urljoin(
            self.base_url,
            f"/openapi/v1/{self.omadac_id}/sites?pageSize={page_size}&page={page}"
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"AccessToken={self.access_token}"
        }

        self._log_debug("Requesting sites from", url)
        response = requests.get(url, headers=headers, verify=self.verify_ssl)
        self._log_debug("Sites response", response.text)

        if response.status_code != 200:
            logger.error(f"Get sites failed with status code {response.status_code}")
            response.raise_for_status()

        data = response.json()
        if data.get("errorCode") != 0:
            logger.error(f"Get sites error: {data.get('msg')}")
            raise RuntimeError(f"Failed to get sites: {data.get('msg')}")

        sites = data.get("result", [])
        logger.info(f"Fetched {len(sites)} site(s) from page {page}")
        return sites

    def get_site_id(self, site_name):
        sites = self.get_sites()
        for site in sites.get('data', []):
            if site['name'] == site_name:
                site_id = site['siteId']
                logger.info(f"Fetched site named '{site_name}' (site_id={site_id})")
                return site_id

        logger.info(f"Could not find site named '{site_name}'")
        return None

    def get_group_profiles(self, site_id):
        if not self.access_token:
            raise RuntimeError("Access token is not set. Obtain it first.")

        url = urljoin(
            self.base_url,
            f"/openapi/v1/{self.omadac_id}/sites/{site_id}/profiles/groups"
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"AccessToken={self.access_token}"
        }

        response = requests.get(url, headers=headers, verify=self.verify_ssl)
        if response.status_code != 200:
            logger.error(f"Get group profiles failed with status code {response.status_code}")
            response.raise_for_status()

        data = response.json()
        if data.get("errorCode") != 0:
            logger.error(f"Get group profiles error: {data.get('msg')}")
            raise RuntimeError(f"Failed to get group profiles: {data.get('msg')}")

        groups = data.get("result", [])
        logger.info(f"Fetched {len(groups)} group profile(s) for site '{site_id}'")

        return groups

    def get_group_profile(self, site_id, profile_name):
        profiles = self.get_group_profiles(site_id=site_id)
        for profile in profiles:
            if profile['name'] == profile_name:
                profile_id = profile['groupId']
                logger.info(f"Fetched profile named '{profile_name}' for site '{site_id}' (profile_id={profile_id})")
                return profile

        logger.info(f"Could not find profile named '{profile_name}' for site '{site_id}'")
        return None

    def get_group_profile_id(self, site_id, profile_name):
        profile = self.get_group_profile(site_id=site_id, profile_name=profile_name)
        return profile.get('groupId', None)
