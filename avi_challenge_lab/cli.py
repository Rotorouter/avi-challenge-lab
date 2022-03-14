"""Example cli using argparse."""
import argparse
import os
import subprocess
import sys
from typing import List, Dict

from ruamel import yaml
import logging
from avi_challenge_lab.log import initialize_logging


from avi.sdk.avi_api import ApiSession
import requests

log = logging.getLogger(__name__)
initialize_logging()


def is_required(default) -> bool:
    """Determine if default is not set in os.environ.

    Args:
        default ([str]): The environment variable name to determine if set in os.environ

    Returns:
        [boolean]: Whether or not default is not in os.environ.
    """
    return default not in os.environ


def parse_args(input_args) -> argparse.Namespace:
    """Argparse module used to collect arguments to be used by script.

    Args:
        args (list): List of arguments and values.

    Returns:
        class (:class:`~argparse.ArgumentParser.parse_args`): Class object containing arguments and values.
    """
    env = os.environ.get
    parser = argparse.ArgumentParser(description="Provision a Virtual Service on Avi.")
    parser.add_argument(
        "-ce",
        "--cloudflare-email",
        type=str,
        required=is_required("CLOUDFLARE_EMAIL"),
        help="Email address associated to the Account ID for Cloudflare DNS.",
        default=env("CLOUDFLARE_EMAIL"),
    )
    parser.add_argument(
        "-ct",
        "--cloudflare-token",
        type=str,
        required=is_required("CLOUDFLARE_TOKEN"),
        help="Token for Cloudflare DNS API calls.",
        default=env("CLOUDFLARE_TOKEN"),
    )
    parser.add_argument(
        "-cu",
        "--cloudflare-zone-id",
        type=str,
        required=is_required("CLOUDFLARE_ZONE_ID"),
        help="Zone (domain) ID for Cloudflare DNS.",
        default=env("CLOUDFLARE_ZONE_ID"),
    )
    parser.add_argument(
        "-f",
        "--controller-fqdn",
        type=str,
        required=is_required("AVI_CONTROLLER_FQDN"),
        help="The fully qualified domain name of your lead Avi controller instance.",
        default=env("AVI_CONTROLLER_FQDN"),
    )
    parser.add_argument(
        "-i",
        "--avi-vs-settings",
        type=str,
        required=is_required("AVI_VS_SETTINGS"),
        help="YAML input file with Virtual Service settings.",
        default="vs.yml",
    )
    parser.add_argument(
        "-n",
        "--avi-controller-username",
        type=str,
        required=is_required("AVI_CONTROLLER_USERNAME"),
        help="Admin username for the Avi controller.",
        default=env("AVI_CONTROLLER_USERNAME"),
    )
    parser.add_argument(
        "-p",
        "--avi-controller-password",
        type=str,
        required=is_required("AVI_CONTROLLER_PASSWORD"),
        help="Admin password for the Avi controller.",
        default=env("AVI_CONTROLLER_PASSWORD"),
    )
    parser.add_argument(
        "-t",
        "--avi-controller-token",
        type=str,
        required=False,
        help="API token to access the Avi controller.",
        default=env("AVI_CONTROLLER_TOKEN"),
    )
    return parser.parse_args(input_args)


def create_cloudflare_cname(
    vs_config: dict, cfapi: str, cloudflare_email: str, cloudflare_token: str, cloudflare_zone_id: str
) -> Dict:
    """Create a CNAME record in Cloudflare, which will point traffic for our site to the Route 53 name of an Avi VS.

    Args:
        vs_config (dict): Contents of the VS config file, to include the hostname and domain of the VS entry.
        cfapi (str): Base URL for the Cloudflare API.
        cloudflare_email (str): Email address associated with the Cloudflare account.
        cloudflare_token (str): API token with `Zone:DNS:Edit` permissions to the given zone.
        cloudflare_zone_id (str): Numeric zone ID.

    Returns:
        str: HTTP response code.
    """
    url = f"{cfapi}/{cloudflare_zone_id}/dns_records"
    headers = {
        "X-Auth-Email": cloudflare_email,
        "Authorization": f"Bearer {cloudflare_token}",
        "Content-type": "application/json",
    }
    site_fqdn = vs_config["hostname"] + "." + vs_config["domain"]
    content = vs_config["hostname"] + "." + vs_config["aws_domain"]
    if vs_config["letsencrypt_cert"]:
        proxied = False
    else:
        proxied = True
    data = {
        "type": "CNAME",
        "name": site_fqdn,
        "content": content,
        "ttl": 1,
        "proxied": proxied,
    }
    response = requests.post(url, headers=headers, json=data)

    return dict(response.json)


def create_letsencrypt_cert(vs_config: dict, cloudflare_email: str, cloudflare_token: str) -> List:
    """Provision a Let's Encrypt SSL certificate, using the Cloudflare DNS-challenge pattern.

    Args:
        vs_config (dict): Contents of the VS config file, to include the hostname and domain of the VS entry.
        cloudflare_email (str): Email address associated with the Cloudflare account.
        cloudflare_token (str): API token with `Zone:DNS:Edit` permissions to the given zone.

    Returns:
        list: A list containing the chained certificate at [0] and the key contents at [1]
    """
    # Insert the correct token into the cloudflare.ini
    cloudflare_ini_file_template = open("template_cloudflare.ini", "r")
    cloudflare_ini_file = open("cloudflare.ini", "w")
    for line in cloudflare_ini_file_template:
        cloudflare_ini_file.write(line.replace("CLOUDFLARE_TOKEN", cloudflare_token))
    cloudflare_ini_file_template.close()
    cloudflare_ini_file.close()

    # TODO: This calls shell commands. Rewrite it using the `certbot` ACME library to keep everything in Python.
    site_fqdn = vs_config["hostname"] + "." + vs_config["domain"]
    cli_command = f"certbot certonly -n --dns-cloudflare --dns-cloudflare-credentials cloudflare.ini --agree-tos --email {cloudflare_email} -d {site_fqdn}"
    os.system(cli_command)

    # Read in the cert and key contents
    cert_file = open(f"/etc/letsencrypt/live/{site_fqdn}/fullchain.pem", "r")
    key_file = open(f"/etc/letsencrypt/live/{site_fqdn}/privkey.pem", "r")
    cert_content = cert_file.read()
    key_content = key_file.read()
    ssl_content = [cert_content, key_content]

    cert_file.close()
    key_file.close()

    return ssl_content


def create_cert_and_key(avi_api: dict, controller: str, ssl_content: list, vs_config: dict) -> str:
    """Create a certificate and key object for use by an SSL profile.

    Args:
        avi_api (dict): API session object describing the connection to the controller.
        controller (str): FQDN or IP address for the lead controller
        ssl_content (list): List containing the cert contents [0] and key contents [1]
        vs_config (dict): Configuration settings

    Returns:
        Dict: URL for the certificate and key object.
    """
    avi_api_version = vs_config["avi_api_version"]
    # Strip the chain from the cert
    server_cert_text = ssl_content[0].split("-----END CERTIFICATE-----\n")[0]
    server_cert = f"{server_cert_text}-----END CERTIFICATE-----\n"
    data = {
        "name": f"{vs_config['hostname']}.{vs_config['domain']}-sslkeyandcertificate",
        "certificate": server_cert,
        "certificate_base64": False,
        "enable_ocsp_stapling": False,
        "format": "SSL_PEM",
        "key": ssl_content[1],
        "key_base64": False,
        "type": "SSL_CERTIFICATE_TYPE_VIRTUALSERVICE",
    }
    sslkeyandcertificate_object = avi_api.post("sslkeyandcertificate", data=data, api_version=avi_api_version)
    sslkeyandcertificate_url = sslkeyandcertificate_object.json()["url"]

    return sslkeyandcertificate_url


def create_pool(avi_api: dict, vs_config: dict) -> str:
    """Make a pool object, containing the settings from the config file.

    Args:
        avi_api (dict): API session object describing the connection to the controller.
        controller (str): FQDN or IP address for the lead controller
        vs_config (dict): Configuration settings

    Returns:
        str: Reference URL of the pool created
    """
    avi_api_version = vs_config["avi_api_version"]
    pool_config = vs_config["pool"]
    pool_config["name"] = f"{vs_config['hostname']}-pool"

    pool_object = avi_api.post("pool", data=pool_config, api_version=avi_api_version)
    pool_url = pool_object.json()["url"]

    return pool_url


def create_vs(avi_api: dict, pool_url: str, vs_config: dict) -> Dict:
    """Create the Avi Virtual Server

    Args:
        avi_api (dict): avi_api (dict): API session object describing the connection to the controller.
        pool_url (str): URL of a provisioned pool.
        vs_config (dict): Configuration settings

    Returns:
        Dict: _description_
    """
    avi_api_version = vs_config["avi_api_version"]
    virtual_server_config = vs_config["virtual_server"]
    virtual_server_config["name"] = f"{vs_config['hostname']}.{vs_config['domain']}"

    # Set the SSL profile conditionally on whether we're making a new cert and profile.
    if vs_config["letsencrypt_cert"]:
        ssl_profile_name = f"{vs_config['hostname']}.{vs_config['domain']}-sslprofile"
    else:
        ssl_profile_name = "System-Standard"
    ssl_profile_object = avi_api.get_object_by_name("sslprofile", ssl_profile_name)
    ssl_profile_url = ssl_profile_object.json()["url"]

    virtual_server_object = avi_api.post("virtualservice", data=virtual_server_config, api_version=avi_api_version)
    virtual_server_response_code = virtual_server_object.status_code

    return virtual_server_response_code


def main(args=parse_args(sys.argv[1:])) -> None:
    """Provision a Virtual Service on a given Avi controller, create a Cloudflare CNAME, and create and apply a Let's Encrypt certificate.

    Args:
        args (_type_, optional): Our CLI arguments.
    """
    requests.urllib3.disable_warnings()

    input_file = args.avi_vs_settings
    cloudflare_email = args.cloudflare_email
    cloudflare_token = args.cloudflare_token
    cloudflare_zone_id = args.cloudflare_zone_id
    username = args.avi_controller_username
    password = args.avi_controller_password
    # token = args.avi_controller_token

    # Parse the config file
    with open(input_file, "r") as file_data:
        yaml_data = file_data.read()
        vs_config = yaml.safe_load(yaml_data)
        file_data.close()

    # Setup our session to the controller
    controller = f"{vs_config['controller']}.{vs_config['domain']}"
    avi_api = ApiSession.get_session(
        controller,
        username,
        password,
    )

    # Create a new SSL profile in Avi with the cert and key, and apply it to the Virtual Service
    # FIXME: create_cert_and_key() returns 500 errors.
    if vs_config["letsencrypt_cert"]:
        ssl_content = create_letsencrypt_cert(
            vs_config=vs_config, cloudflare_email=cloudflare_email, cloudflare_token=cloudflare_token
        )
        ssl_cert_and_key_url = create_cert_and_key(
            avi_api=avi_api, controller=controller, ssl_content=ssl_content, vs_config=vs_config
        )
        ssl_profile_url = create_ssl_profile(
            avi_api=avi_api, controller=controller, ssl_cert_and_key_url=ssl_cert_and_key_url, vs_config=vs_config
        )

    # Make an Avi pool object.
    pool_url = create_pool(avi_api=avi_api, vs_config=vs_config)

    # Make an Avi Virtual Service.
    virtual_server_response_code = create_vs(avi_api=avi_api, pool_url=pool_url, vs_config=vs_config)

    # Register a CNAME for our site in CloudFlare DNS, assuming all went well.
    if virtual_server_response_code == 201:
        cfapi = "https://api.cloudflare.com/client/v4/zones"
        create_cloudflare_cname(
            vs_config=vs_config,
            cfapi=cfapi,
            cloudflare_email=cloudflare_email,
            cloudflare_token=cloudflare_token,
            cloudflare_zone_id=cloudflare_zone_id,
        )
    else:
        print("Something went wrong. Please check the job output.")


if __name__ == "__main__":
    main()
