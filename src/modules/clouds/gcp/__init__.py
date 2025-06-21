#!/usr/bin/env python


from google.cloud import compute_v1, container_v1, storage
from googleapiclient import discovery
from google.auth import default
from google.auth.transport.requests import Request
from colorama import Fore, init
from modules.clouds.provider import Provider

init(autoreset=True)


class GCPAnalyzer(Provider):
    SENSITIVE_PERMISSIONS = [
        "resourcemanager.projects.setIamPolicy",
        "iam.roles.create",
        "iam.roles.update",
        "iam.roles.delete",
        "iam.serviceAccounts.actAs",
        "compute.instances.start",
        "compute.instances.delete",
        "storage.objects.get",
        "storage.objects.list",
        "bigquery.jobs.create",
        "sql.instances.update",
        "sql.instances.delete",
        "cloudsql.instances.update",
        "cloudsql.instances.delete",
    ]

    def __init__(self, projects: list[str], *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.projects = projects
        self.run_all_checks()

    def check_compute_firewalls(self, project):
        self.utils.section("Compute Engine Firewall Analysis", project)
        try:
            client = compute_v1.FirewallsClient()
            for fw in client.list(project=project):
                for allowed in fw.allowed:
                    for ip_range in fw.source_ranges:
                        if (
                            ip_range == self.IPV4_INTERNET_IP
                            or ip_range == self.IPV6_INTERNET_IP
                        ):
                            msg = f"Firewall {fw.name} allows {allowed.I_p_protocol} from {ip_range}"
                            print(Fore.RED + "[GCE][FW] " + msg)
                            self.logger.warning(msg)
                            self.report_generator.add_finding(
                                "GCE", "OpenFirewall", fw.name, msg, project
                            )
        except Exception as e:
            self.logger.error(f"[GCE][{project}] Error: {e}")

    def check_cloudsql(self, project):
        self.utils.section("Cloud SQL Public Exposure", project)
        try:
            credentials, _ = default()
            credentials.refresh(Request())
            service = discovery.build("sqladmin", "v1beta4", credentials=credentials)

            request = service.instances().list(project=project)
            response = request.execute()

            instances = response.get("items", [])
            for inst in instances:
                ip_config = inst.get("settings", {}).get("ipConfiguration", {})
                if ip_config.get("ipv4Enabled", False):
                    for ip in inst.get("ipAddresses", []):
                        if ip.get("type") == "PRIMARY" and ip.get("ipAddress"):
                            msg = f"CloudSQL instance {inst['name']} has public IP {ip['ipAddress']}"
                            print(Fore.RED + "[SQL][PUBLIC] " + msg)
                            self.logger.warning(msg)
                            self.report_generator.add_finding(
                                "CloudSQL", "PublicIP", inst["name"], msg, project
                            )
        except Exception as e:
            self.logger.error(f"[CloudSQL][{project}] Error: {e}")

    def check_iam(self, project):
        self.utils.section("IAM Role Analysis", project)
        try:
            credentials, _ = default()
            credentials.refresh(Request())
            service = discovery.build("iam", "v1", credentials=credentials)

            request = service.roles().list(parent=f"projects/{project}", view="FULL")
            response = request.execute()

            for role in response.get("roles", []):
                role_name = role.get("name", "")
                permissions = role.get("includedPermissions", [])

                if any(p in self.SENSITIVE_PERMISSIONS for p in permissions):
                    msg = f"Project {project} has role {role_name} with sensitive permissions"
                    print(Fore.MAGENTA + "[IAM][SENSITIVE PERM] " + msg)
                    self.logger.warning(msg)
                    self.report_generator.add_finding(
                        "IAM", "SensitivePermission", role_name, msg, project
                    )

        except Exception as e:
            self.logger.error(f"[IAM][{project}] Error: {e}")

    def check_gke(self, project):
        self.utils.section("GKE Cluster Exposure", project)
        try:
            client = container_v1.ClusterManagerClient()
            clusters = (
                client.list_clusters(parent=f"projects/{project}/locations/-").clusters
                or []
            )
            for cluster in clusters:
                private_nodes_enabled = (
                    cluster.private_cluster_config is not None
                    and cluster.private_cluster_config.enable_private_nodes
                )
                if not private_nodes_enabled:
                    msg = f"GKE Cluster {cluster.name} is public"
                    print(Fore.RED + "[GKE][PUBLIC] " + msg)
                    self.logger.warning(msg)
                    self.report_generator.add_finding(
                        "GKE", "PublicCluster", cluster.name, msg, project
                    )
        except Exception as e:
            self.logger.error(f"[GKE][{project}] Error: {e}")

    def check_storage_buckets(self, project):
        self.utils.section("Cloud Storage Bucket Access", project)
        try:
            client = storage.Client(project=project)
            buckets = client.list_buckets()
            for bucket in buckets:
                policy = bucket.get_iam_policy()
                for binding in policy.bindings:
                    members = binding.get("members", [])
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        msg = (
                            f"Bucket {bucket.name} is public via role {binding['role']}"
                        )
                        print(Fore.RED + "[BUCKET][PUBLIC] " + msg)
                        self.logger.warning(msg)
                        self.report_generator.add_finding(
                            "Storage", "PublicBucket", bucket.name, msg, project
                        )
        except Exception as e:
            self.logger.error(f"[BUCKET][{project}] Error: {e}")

    def check_unencrypted_disks(self, project):
        self.utils.section("Persistent Disk Encryption (CMEK)", project)
        try:
            zone_client = compute_v1.ZonesClient()
            disk_client = compute_v1.DisksClient()
            zones = [zone.name for zone in zone_client.list(project=project)]
            for zone in zones:
                for disk in disk_client.list(project=project, zone=zone):
                    disk_encryption = disk.disk_encryption_key
                    if not disk_encryption or not disk_encryption.kms_key_name:
                        msg = f"Disk {disk.name} in {zone} is not encrypted with CMEK"
                        print(Fore.YELLOW + "[DISK][NO_CMEK] " + msg)
                        self.logger.warning(msg)
                        self.report_generator.add_finding(
                            "Disk", "NoCMEK", disk.name, msg, f"{project}/{zone}"
                        )
        except Exception as e:
            self.logger.error(f"[DISK][{project}] Error: {e}")

    def run_all_checks(self):
        for project in self.projects:
            self.check_compute_firewalls(project)
            self.check_cloudsql(project)
            self.check_iam(project)
            self.check_gke(project)
            self.check_storage_buckets(project)
            self.check_unencrypted_disks(project)
