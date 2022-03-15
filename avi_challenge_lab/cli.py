"""Example cli using argparse."""
import argparse
import os
import sys
from typing import List, Dict
import logging
from shutil import copyfile

from ruamel import yaml
import requests
from avi.sdk.avi_api import ApiSession
from log import initialize_logging

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


def get_dependent_object_urls(avi_api: dict, cloudflare_email: str, cloudflare_token: str, vs_config: dict) -> Dict:
    """Add a url key to each type of object which will be referenced by the pool or VS

    Args:
        avi_api (dict): API session object describing the connection to the controller.
        vs_config (dict): Configuration settings

    Returns:
        Dict: vs_config enriched with "url" keys for each object
    """

    # Add an FQDN key for the VS for ease of use
    vs_config["fqdn"] = f"{vs_config['hostname']}.{vs_config['domain']}"

    # Replace the "network" key with "nw_ref" for each of the pool members.
    for server in vs_config["pool"]["servers"]:
        server["nw_ref"] = avi_api.get_object_by_name("vimgrnwruntime", server["network"])["url"]
        server.pop("network", None)

    # Replace the friendly names of the health monitors with their URL ref.
    vs_config["pool"]["health_monitor_refs"] = []
    for monitor in vs_config["pool"]["health_monitors"]:
        monitor_ref = avi_api.get_object_by_name("healthmonitor", monitor)["url"]
        vs_config["pool"]["health_monitor_refs"].append(monitor_ref)
    vs_config["pool"].pop("health_monitors", None)

    # Replace the friendly name of the analytics profile with its url_ref
    vs_config["virtual_server"]["analytics_profile_ref"] = avi_api.get_object_by_name(
        "analyticsprofile", vs_config["virtual_server"]["analytics_profile"]
    )["url"]
    vs_config["virtual_server"].pop("analytics_profile", None)

    # Replace the friendly name of the application profile with its url_ref
    vs_config["virtual_server"]["application_profile_ref"] = avi_api.get_object_by_name(
        "applicationprofile", vs_config["virtual_server"]["application_profile"]
    )["url"]
    vs_config["virtual_server"].pop("application_profile", None)

    # Get the URL for the System-Standard SSL Profile.
    vs_config["virtual_server"]["ssl_profile_ref"] = avi_api.get_object_by_name("sslprofile", "System-Standard")["url"]

    if vs_config["letsencrypt_cert"]:
        ssl_content = create_letsencrypt_cert(
            vs_config=vs_config, cloudflare_email=cloudflare_email, cloudflare_token=cloudflare_token
        )
        ssl_cert_and_key_url = create_cert_and_key(avi_api=avi_api, ssl_content=ssl_content, vs_config=vs_config)
        vs_config["virtual_server"]["ssl_key_and_certificate_refs"] = ssl_cert_and_key_url
    else:
        vs_config["virtual_server"]["ssl_key_and_certificate_refs"] = avi_api.get_object_by_name(
            "sslkeyandcertificate", "System-Default-Cert-EC"
        )["url"]

    return vs_config


def create_pool(avi_api: dict, vs_config: dict) -> str:
    """Make a pool object, containing the settings from the config file.

    Args:
        avi_api (dict): API session object describing the connection to the controller.
        vs_config (dict): Configuration settings

    Returns:
        str: Reference URL of the pool created
    """
    avi_api_version = vs_config["avi_api_version"]
    pool_config = vs_config["pool"]
    pool_config["name"] = f"{vs_config['fqdn']}-pool"

    pool_object = avi_api.post("pool", data=pool_config, api_version=avi_api_version)
    pool_url = pool_object.json()["url"]

    return pool_url


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
    copyfile("template_cloudflare.ini", "cloudflare.ini")
    with open("cloudflare.ini", "w", encoding="utf-8") as cloudflare_ini_file:
        for line in cloudflare_ini_file:
            line.write(line.replace("CLOUDFLARE_TOKEN", cloudflare_token))
        cloudflare_ini_file.close()

    # TODO: This calls shell commands. Rewrite it using the `certbot` ACME library to keep everything in Python.
    cli_command = f"certbot certonly -n --dns-cloudflare --dns-cloudflare-credentials cloudflare.ini --agree-tos --email {cloudflare_email} -d {vs_config['fqdn']}"
    os.system(cli_command)

    # Read in the cert and key contents
    with open(f"/etc/letsencrypt/live/{vs_config['fqdn']}/fullchain.pem", "r", encoding="utf-8") as cert_file:
        cert_content = cert_file.read()
        cert_file.close()
    with open(f"/etc/letsencrypt/live/{vs_config['fqdn']}/privkey.pem", "r", encoding="utf-8") as key_file:
        key_content = key_file.read()
        key_file.close()

    ssl_content = [cert_content, key_content]

    return ssl_content


def create_cert_and_key(avi_api: dict, ssl_content: list, vs_config: dict) -> str:
    """Create a certificate and key object for use by an SSL profile.

    Args:
        avi_api (dict): API session object describing the connection to the controller.
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
        "name": f"{vs_config['fqdn']}-sslkeyandcertificate",
        "certificate": server_cert,
        "certificate_base64": False,
        "enable_ocsp_stapling": False,
        "format": "SSL_PEM",
        "key": ssl_content[1],
        "key_base64": False,
        "type": "SSL_CERTIFICATE_TYPE_VIRTUALSERVICE",
    }

    # FIXME: This returns 500 errors (unhandled exception).
    sslkeyandcertificate_object = avi_api.post("sslkeyandcertificate", data=data, api_version=avi_api_version)
    sslkeyandcertificate_url = sslkeyandcertificate_object.json()["url"]

    return sslkeyandcertificate_url


def create_vsvip(avi_api: dict, vs_config: dict) -> str:
    """Create a VIP object for the Virtual Service

    Args:
        avi_api (dict): avi_api (dict): API session object describing the connection to the controller.
        vs_config (dict): Configuration settings.

    Returns:
        str: URL for the vsvip object
    """
    avi_api_version = vs_config["avi_api_version"]
    subnet_uuid = avi_api.get_object_by_name("vimgrnwruntime", vs_config["vip_network"])["uuid"]
    data = {
        "name": f"{vs_config['fqdn']}-vsvip",
        "vip": [
            {
                "avi_allocated_vip": True,
                "avi_allocated_fip": True,
                "auto_allocate_ip": True,
                "auto_allocate_ip_type": "V4_ONLY",
                "auto_allocate_floating_ip": True,
                "subnet_uuid": subnet_uuid,
            }
        ],
        "dns_info": [
            {
                "fqdn": f"{vs_config['hostname']}.{vs_config['aws_domain']}",
                "type": "DNS_RECORD_A",
                "algorithm": "DNS_RECORD_RESPONSE_CONSISTENT_HASH",
            }
        ],
    }
    vsvip_url = avi_api.post("vsvip", data=data, api_version=avi_api_version).json()["url"]

    return vsvip_url


def create_vs(avi_api: dict, pool_url: str, vs_config: dict) -> Dict:
    """Create the Avi Virtual Server

    Args:
        avi_api (dict): avi_api (dict): API session object describing the connection to the controller.
        pool_url (str): URL of a provisioned pool.
        vs_config (dict): Configuration settings

    Returns:
        Dict: The HTTP response code of the POST to create the
    """
    avi_api_version = vs_config["avi_api_version"]
    virtual_server_config = vs_config["virtual_server"]
    virtual_server_config["name"] = f"{vs_config['hostname']}.{vs_config['domain']}"
    virtual_server_config["pool_ref"] = pool_url
    virtual_server_config["vsvip_ref"] = create_vsvip(avi_api=avi_api, vs_config=vs_config)

    virtual_server_object = avi_api.post("virtualservice", data=virtual_server_config, api_version=avi_api_version)

    print(f"Response code from VS creation is {virtual_server_object.status_code}.")
    return virtual_server_object.status_code


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
    content = f"{vs_config['hostname']}.{vs_config['aws_domain']}"
    if vs_config["letsencrypt_cert"]:
        proxied = False
    else:
        proxied = True
    data = {
        "type": "CNAME",
        "name": vs_config["fqdn"],
        "content": content,
        "ttl": 1,
        "proxied": proxied,
    }
    response = requests.post(url, headers=headers, json=data)

    return response.json()["result"]


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

    # Parse the config file
    with open(input_file, "r", encoding="utf-8") as file_data:
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

    # Lookup the URLs for dependent objects so we can populate the pool and VS dicts
    vs_config = get_dependent_object_urls(
        avi_api=avi_api, cloudflare_email=cloudflare_email, cloudflare_token=cloudflare_token, vs_config=vs_config
    )

    # Make an Avi pool object.
    pool_url = create_pool(avi_api=avi_api, vs_config=vs_config)

    # Make an Avi Virtual Service.
    virtual_server_response_code = create_vs(avi_api=avi_api, pool_url=pool_url, vs_config=vs_config)

    # Register a CNAME for our site in CloudFlare DNS, assuming all went well.
    if virtual_server_response_code == 201:
        cfapi = "https://api.cloudflare.com/client/v4/zones"
        cname_result = create_cloudflare_cname(
            vs_config=vs_config,
            cfapi=cfapi,
            cloudflare_email=cloudflare_email,
            cloudflare_token=cloudflare_token,
            cloudflare_zone_id=cloudflare_zone_id,
        )
        print(f"It seems everything worked. Please verify that the DNS for {cname_result['name']}")
        print(f"points to the AWS Route53 name {cname_result['content']}. Please also verify that")
        print(f"http://{cname_result['name']} redirects to https://{cname_result['name']} and that")
        print("the certificates are valid.")
    else:
        print("Something went wrong. Please check the job output.")


if __name__ == "__main__":
    main()
