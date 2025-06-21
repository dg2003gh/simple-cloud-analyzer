#!/usr/bin/env python

import boto3

from botocore.exceptions import BotoCoreError, ClientError
from colorama import Fore, init
from modules.clouds.provider import Provider


# Initialize colorama
init(autoreset=True)


"""
Analyze an AWS account looking for Security failures.
"""


class AWSAnalyzer(Provider):
    def __init__(self, regions: list[str], *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.__check_regions(regions)
        self.run_all_checks()

    def __check_regions(self, regions: list[str]):
        if [r for r in regions if r.strip()]:
            self.regions = regions
        else:
            ec2 = boto3.client("ec2")
            regions_resp = ec2.describe_regions(AllRegions=False)
            self.regions = [r["RegionName"] for r in regions_resp["Regions"]]

    def check_ec2(self, region):
        """
        Check every security group searching for open ports to world.
        Also check open critical ports.
        """
        self.utils.section("EC2 Security Group Analysis", region)
        try:
            ec2 = boto3.client("ec2", region_name=region)
            for sg in ec2.describe_security_groups()["SecurityGroups"]:
                for perm in sg.get("IpPermissions", []):
                    from_port, to_port = perm.get("FromPort"), perm.get("ToPort")
                    proto = perm.get("IpProtocol")
                    opened = range(from_port or 0, (to_port or 0) + 1)

                    # IPv4
                    for r in perm.get("IpRanges", []):
                        if r.get("CidrIp") == self.IPV4_INTERNET_IP:
                            for p in self.ports:
                                if p in opened:
                                    msg = f"SG {sg['GroupId']}:{sg['GroupName']} → port {p}/{proto} open to 0.0.0.0/0"
                                    print(Fore.RED + "[SG][IPv4] " + msg)
                                    self.logger.warning(msg)
                                    self.report_generator.add_finding(
                                        "SG",
                                        "IPv4",
                                        sg["GroupId"],
                                        msg,
                                        region,
                                    )

                    # IPv6
                    for r in perm.get("Ipv6Ranges", []):
                        if r.get("CidrIpv6") == self.IPV6_INTERNET_IP:
                            for p in self.ports:
                                if p in opened:
                                    msg = f"SG {sg['GroupId']}:{sg['GroupName']} → port {p}/{proto} open to ::/0"
                                    print(Fore.MAGENTA + "[SG][IPv6] " + msg)
                                    self.logger.warning(msg)
                                    self.report_generator.add_finding(
                                        "SG",
                                        "IPv6",
                                        sg["GroupId"],
                                        msg,
                                        region,
                                    )
        except (BotoCoreError, ClientError) as e:
            self.logger.error(f"[EC2][{region}] Error: {e}")

    def check_rds(self, region):
        """
        Check for public subnet deployed RDS instances.
        """
        self.utils.section("RDS Analysis", region)
        try:
            rds = boto3.client("rds", region_name=region)
            ec2 = boto3.client("ec2", region_name=region)

            public_subnets = set()
            for rt in ec2.describe_route_tables()["RouteTables"]:
                has_igw = any(
                    r.get("GatewayId", "").startswith("igw-")
                    for r in rt.get("Routes", [])
                )
                if not has_igw:
                    continue
                for assoc in rt.get("Associations", []):
                    subnet_id = assoc.get("SubnetId")
                    if subnet_id:
                        public_subnets.add(subnet_id)

            # Pre-fetch all security groups
            sg_map = {}
            for sg in ec2.describe_security_groups()["SecurityGroups"]:
                sg_map[sg["GroupId"]] = sg

            for inst in rds.describe_db_instances()["DBInstances"]:
                instance_id = inst["DBInstanceIdentifier"]
                subnet_ids = [
                    s["SubnetIdentifier"]
                    for s in inst.get("DBSubnetGroup", {}).get("Subnets", [])
                ]
                sg_ids = [
                    sg["VpcSecurityGroupId"] for sg in inst.get("VpcSecurityGroups", [])
                ]

                # Check if in public subnet
                if any(subnet in public_subnets for subnet in subnet_ids):
                    msg = f"RDS {instance_id} is deployed in a public subnet"
                    print(Fore.RED + "[RDS][PUBLIC SUBNET] " + msg)
                    self.logger.warning(msg)
                    self.report_generator.add_finding(
                        "RDS", "PublicSubnet", instance_id, msg, region
                    )

                # Check SG open to world
                for sg_id in sg_ids:
                    sg = sg_map.get(sg_id)
                    if not sg:
                        continue
                    for perm in sg.get("IpPermissions", []):
                        for ip_range in perm.get("IpRanges", []):
                            if ip_range.get("CidrIp") == self.IPV4_INTERNET_IP:
                                proto = perm.get("IpProtocol")
                                from_port = perm.get("FromPort")
                                to_port = perm.get("ToPort")
                                port_str = (
                                    f"{from_port}"
                                    if from_port == to_port
                                    else f"{from_port}-{to_port}"
                                )
                                msg = f"RDS {instance_id} SG {sg_id} allows {port_str}/{proto} from 0.0.0.0/0"
                                print(Fore.RED + "[RDS][OPEN SG] " + msg)
                                self.logger.warning(msg)
                                self.report_generator.add_finding(
                                    "RDS", "OpenSGIPv4", instance_id, msg, region
                                )
                        for ip_range in perm.get("Ipv6Ranges", []):
                            if ip_range.get("CidrIpv6") == self.IPV6_INTERNET_IP:
                                proto = perm.get("IpProtocol")
                                from_port = perm.get("FromPort")
                                to_port = perm.get("ToPort")
                                port_str = (
                                    f"{from_port}"
                                    if from_port == to_port
                                    else f"{from_port}-{to_port}"
                                )
                                msg = f"RDS {instance_id} SG {sg_id} allows {port_str}/{proto} from ::/0"
                                print(Fore.RED + "[RDS][OPEN SG] " + msg)
                                self.logger.warning(msg)
                                self.report_generator.add_finding(
                                    "RDS", "OpenSGIPv6", instance_id, msg, region
                                )

                # Check publicly accessible flag
                if inst.get("PubliclyAccessible"):
                    msg = f"{instance_id} is marked as publicly accessible"
                    print(Fore.RED + "[RDS][PUBLICLY ACCESSIBLE] " + msg)
                    self.logger.warning(msg)
                    self.report_generator.add_finding(
                        "RDS", "Public", instance_id, msg, region
                    )

        except (BotoCoreError, ClientError) as e:
            self.logger.error(f"[RDS][{region}] Error: {e}")

    def check_vpc(self, region):
        self.utils.section("VPC Route Table Analysis", region)
        try:
            ec2 = boto3.client("ec2", region_name=region)
            for rt in ec2.describe_route_tables()["RouteTables"]:
                uses_igw = any(
                    r.get("GatewayId", "").startswith("igw-")
                    for r in rt.get("Routes", [])
                )
                for assoc in rt.get("Associations", []):
                    if assoc.get("SubnetId") and uses_igw:
                        msg = f"Subnet {assoc['SubnetId']} in RT {rt['RouteTableId']} is public"
                        print(Fore.YELLOW + "[VPC] " + msg)
                        self.logger.warning(msg)
                        self.report_generator.add_finding(
                            "VPC", "Public Subnet", assoc["SubnetId"], msg, region
                        )
        except (BotoCoreError, ClientError) as e:
            self.logger.error(f"[VPC][{region}] Error: {e}")

    def check_ecs(self, region):
        self.utils.section("ECS Task Definition Analysis", region)
        try:
            ecs = boto3.client("ecs", region_name=region)
            clusters = ecs.list_clusters()["clusterArns"]
            task_defs = ecs.list_task_definitions()["taskDefinitionArns"]

            for cl in clusters:
                for td_arn in task_defs:
                    td = ecs.describe_task_definition(taskDefinition=td_arn)[
                        "taskDefinition"
                    ]
                    if td.get("networkMode") == "awsvpc" and "FARGATE" in td.get(
                        "requiresCompatibilities", []
                    ):
                        msg = f"{td_arn} in {cl} uses awsvpc → may have public IP"
                        print(Fore.CYAN + "[ECS] " + msg)
                        self.logger.warning(msg)
                        self.report_generator.add_finding(
                            "ECS", "awsvpc-public", td_arn, msg, region
                        )
        except (BotoCoreError, ClientError) as e:
            self.logger.error(f"[ECS][{region}] Error: {e}")

    def check_eks(self, region):
        self.utils.section("EKS Cluster Analysis", region)
        try:
            eks = boto3.client("eks", region_name=region)
            for c in eks.list_clusters()["clusters"]:
                info = eks.describe_cluster(name=c)["cluster"]
                if info["resourcesVpcConfig"].get("endpointPublicAccess"):
                    msg = f"Cluster {c} has public API endpoint"
                    print(Fore.RED + "[EKS] " + msg)
                    self.logger.warning(msg)
                    self.report_generator.add_finding(
                        "EKS", "Public API", c, msg, region
                    )
        except (BotoCoreError, ClientError) as e:
            self.logger.error(f"[EKS][{region}] Error: {e}")

    def check_ebs(self, region):
        self.utils.section("EBS Encryption Analysis", region)
        try:
            ec2 = boto3.client("ec2", region_name=region)
            for v in ec2.describe_volumes()["Volumes"]:
                if not v.get("Encrypted"):
                    msg = f"Volume {v['VolumeId']} is unencrypted"
                    print(Fore.YELLOW + "[EBS] " + msg)
                    self.logger.warning(msg)
                    self.report_generator.add_finding(
                        "EBS", "Unencrypted", v["VolumeId"], msg, region
                    )
        except (BotoCoreError, ClientError) as e:
            self.logger.error(f"[EBS][{region}] Error: {e}")

    def check_IAM(self):
        region = "global"
        self.utils.section("IAM Analysis", "global")
        try:
            iam = boto3.client("iam")
            users = iam.list_users()["Users"]

            for user in users:
                username = user["UserName"]

                # Admin policy check
                policies = iam.list_attached_user_policies(UserName=username)[
                    "AttachedPolicies"
                ]
                for policy in policies:
                    if policy["PolicyName"] == "AdministratorAccess":
                        msg = f"{username} has AdministratorAccess"
                        print(Fore.RED + "[IAM][ADMIN] " + msg)
                        self.logger.warning(msg)
                        self.report_generator.add_finding(
                            "IAM", "AdminPolicy", username, msg, region
                        )

                # Access key age check
                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                for key in keys:
                    age_days = (self.now - key["CreateDate"]).days
                    if age_days > 90:
                        msg = f"{username} key {key['AccessKeyId']} is {age_days} days old"
                        print(Fore.YELLOW + "[IAM][KEY] " + msg)
                        self.logger.warning(msg)
                        self.report_generator.add_finding(
                            "IAM", "OldAccessKey", username, msg, region
                        )

                # Password last used check
                pw_data = iam.get_user(UserName=username)["User"]
                pw_last_used = pw_data.get("PasswordLastUsed")
                if pw_last_used:
                    age_days = (self.now - pw_last_used).days
                    if age_days > 90:
                        msg = f"{username} password not used in {age_days} days"
                        print(Fore.MAGENTA + "[IAM][PW] " + msg)
                        self.logger.warning(msg)
                        self.report_generator.add_finding(
                            "IAM", "StalePassword", username, msg, region
                        )
                else:
                    msg = f"{username} has no password usage record"
                    print(Fore.LIGHTBLACK_EX + "[IAM][PW] " + msg)
                    self.logger.info(msg)
                    self.report_generator.add_finding(
                        "IAM", "NoPasswordRecord", username, msg, region
                    )
        except (BotoCoreError, ClientError) as e:
            self.logger.error(f"[IAM] Error: {e}")

    def run_all_checks(self):

        #####################
        # Regional services #
        #####################

        for region in self.regions:
            self.check_ec2(region)
            self.check_rds(region)
            self.check_vpc(region)
            self.check_ecs(region)
            self.check_eks(region)
            self.check_ebs(region)

        ###################
        # Global services #
        ###################

        self.check_IAM()
