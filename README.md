# Avi Challenge Lab
This is a lightweight demo project project which will:
- Configure an Avi (NSX ALB) controller AWS ec2 instance, using release version `20.1.8-9194`.
- Configure the `cloud` in the controller cluster VPC environment where it lives, and create the hooks into the ec2 and related AWS services to create service engines, register Route53 names, etc.
- Create a pool and HTTP/S virtual service (with HTTP redirected to HTTPS).
- Create a Route53 entry for the Virtual Service.
- Verify the service engines are successfully spun up in the `Default-Group` SE group.
- Create a CNAME record in Cloudflare DNS which points a friendly name to the Route 53 name.
- Create a Let's Encrypt SSL certificate, and apply it to the Virtual Service.

## Prerequisites
- Username and password to use an AWS console.
- A provisioned access key ID and secret key contents.
- A provisioned VPC in which to place the elements.
- Provisioned IAM policies to support permissions to create the necessary elements.
- The `poetry` utility installed on your development machine: https://python-poetry.org/
- `docker-daemon` installed and configured on your development machine.
- A publicly registered DNS domain, with Cloudflare authoritative for the domain.
- Permissions and credentials to register DNS records in Cloudflare for the given domain.

## Deployment Procedures
#### Manual Steps
- Deploy a 3-node Avi Controller cluster, with reachability to the Internet and credentials. See https://avinetworks.com/docs/latest/installing-avi-vantage-in-amazon-web-services/ for instructions. Controllers should be deployed from the AWS Marketplace using version `20.1.8-9194`. Each controller instance should have an elastic IP allocated.
- Configure the lead controller for an AWS cloud: 
    - From the web UI go to `Infrastructure >> Clouds`.
    - Create a new cloud, of type AWS.
    - Select the region where the controller ec2 instances are deployed. Enter the `Access Key ID` the `Secret Access Key` provided. Under Register `Virtual Service Names` select the check box for `Amazon Route 53`. Click `Next`.
    - Under `VPC` select the VPC where the controller is installed. Select the appropriate availability zones, and subnets in which to install the SE management ENIs. Click `Complete`.
- Copy `.env-example` to `.env` and edit `.env` to include the keys, tokens, etc. needed.
- Edit `avi_challenge_lab/vs.yml` to contain other details for the Virtual Service to provision.
- Generate an API token through the UI to use during the session.

#### Automated Steps
- Build the container with `docker-compose build cli`.
- Execute the job with `docker run --env-file .env -it avi-challenge-lab_cli:latest cli.py`.
- To troubleshoot, run an interactive session of the container: `docker run --env-file .env -it --entrypoint /bin/bash avi-challenge-lab_cli:latest`.

## TODO
Steps for improvement, to make the demo production-worthy.
- Create a playbook or script to upload the bare-minimum IAM role definitions and create a user account with those IAM roles to use in the rest of the demo. The user account name can be specified in a YAML or JSON file used as a configuration file for the playbook or script. The password should be passed in by environment variable though, to avoid storing it on the filesystem of the container.
- Add a set of Ansible or Terraform playbooks to build the controller from scratch in AWS. These should get bundled up into a separate container from the VS build-out container. We want to use a different tool from the VS provisioning container (Python) for this in order to demonstrate Avi's presence in multiple tooling ecosystems.
    - Use a YAML or JSON file as input. Build the container at demo-time so that the YAML/JSON is present in the container filesystem. Only sensitive info like keys, etc. should be provided at runtime by user-provided environment variables.
    - Add any necessary IAM roles.
    - Take an AMI image name, AZ, DNS server(s), AWS credentials, number of instances, hostname prefix (for the `Name` tags) etc. as input to build the controller ec2 instances. If possible configure a 3-controller cluster with at least 1 controller in a different (same region) AZ from the lead controller.
    - Take an `admin_network` to build in as the source for the security group created as part of buildout. SG should obviously also not be constructed as to break connectivity between any service engines and the controllers. :)
    - Create a new ssh keypair. Echo the private key contents on the CLI so the end-user has them.
    - Spin up the instances, and loop/sleep to configure the first (lead) instance when fully available.
    - Set admin password for each controller instance via ssh (using the ssh key set provisioned during spin-up, and an admin password passed in by the user as an environment variable).
    - Set DNS server(s), NTP, and other "global" configs in the lead controller. Create an SE group.
    - Add the AWS cloud settings. Configure the cloud to use the SE group we added as a template. The cloud should have the option enabled to register virtual service names in Route 53, should include the Availability Zones and their corresponding SE management networks which we specified in our YAML input config file.
    - Configure clustering among the 3 controller ec2 instances. The 2nd and 3rd controllers will be the followers. Verify that the cluster comes up and that the followers pick up settings like the cloud which would not otherwise be present if clustering were not working. Demonstrate this to the customer via the UI, but also have tests in the container to verify.
    - Disable the default `admin` account and add a local-admin account with a username and password supplied by the user.
    - Probably other stuff I can't think of right now. :P
- AWS Networks where the servers live are currently hard-coded. Add a function to look up the networks by name from the `vs.yml` config file.
- Health monitor UUID is currently hardcoded in the pool settings. Add a function to look it up via a name provided in `vs.yml`.
- Add functions to look up the UUIDs of various hard-coded objects in the VS settings.
- Add a 3rd set of playbooks and a container to spin up lightweight web server ec2 instances in each AZ where the SEs live.
    - If you use an AMI image for a modern Debian-based linux then `busybox` should already be installed.
    - Allocate a new SSH keypair during the run and use that for the server instances.
    - Install some fun but inoffensive static content in the directory busybox serves from. Ideally with the server name and internal IP to verify that load balancing is working as expected.
- Add commands to `tasks.py` in this repo so you can use `invoke <foo>` to run each of the container steps. Maybe even a single `invoke deploy-all` to run everything.
- Unit and integration tests written for all of the above. This would probably require converting the `Dockerfile` in each to do a multi-stage build.

