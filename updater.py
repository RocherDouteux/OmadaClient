import logging
import os

from dotenv import load_dotenv
from client import OmadaClient
from helpers import resolve_fqdns_to_ipv4

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

logger = logging.getLogger(__name__)


def main():
    load_dotenv()

    base_url = os.getenv("OMADA_BASE_URL")
    username = os.getenv("OMADA_USER")
    password = os.getenv("OMADA_PASSWORD")
    client_id = os.getenv("APP_CLIENT_ID")
    client_secret = os.getenv("APP_CLIENT_SECRET")
    omadac_id = os.getenv("OMADAC_ID")

    client = OmadaClient(
        base_url=base_url,
        username=username,
        password=password,
        client_id=client_id,
        client_secret=client_secret,
        omadac_id=omadac_id,
        verify_ssl=False,
        debug=False
    )
    client.login()

    auth_code = client.get_authorization_code()
    acces_token = client.get_access_token()

    logger.warning("Omada auth code: {}".format(auth_code))
    logger.warning("Omada access token: {}".format(acces_token))

    home_site_id = client.get_site_id('HOME')
    if home_site_id is None:
        logger.warning("No home site found")
    else:
        mog_group_profil_id = client.get_group_profile_id(site_id=home_site_id, profile_name='Mogstation')

        new_ip_list = resolve_fqdns_to_ipv4(["secure.square-enix.com"])

        formatted_ip_list = [
            {"ip": ip, "mask": 32, "description": fqdn}
            for fqdn, ips in new_ip_list.items()
            for ip in ips
        ]

        client.modify_group_iplist(
            site_id=home_site_id, group_type=0,
            group_id=mog_group_profil_id, new_ip_list=formatted_ip_list
        )


if __name__ == '__main__':
    main()
