###
#
# Boot an effectively-ephemeral wireguard EC2 VM backed by Ubuntu 24.04.
#
# By default, the VM is auto-upgraded on boot and set to shutdown after
# 12 hours. The VM has ingress from the public internet on a single UDP port
# (`local.wireguard_port` below) via Security Groups. This TF also generates
# a `wireproxy.conf` file suitable for use with the
# https://github.com/pufferffish/wireproxy project. Wireproxy is setup with
# a SOCKSv5 and HTTPS proxy listeners on `localhost:1080` and `localhost:1081`
# respectively. TCP `localhost:1122` is setup to port-forward to the EC2's SSH
# port. This also sets up the `whoami` Unix user, allowing access via all currently
# configured public SSH keys (output of `ssh-add -L`).
#
###

variable "account_id" {
  type = string
}

variable "region_name" {
  default = "us-west-2"
  type    = string
}

variable "subnet_id" {
  # defaults to the public subnet in AZ `a` in the default VPC.
  default = "default"
  type    = string
}

locals {
  # SSH
  whoami                 = "whoami"     # SSH User Name (via Wireproxy connection).
  # VM
  ec2_instance_type      = "m7a.medium" # can go smaller if there are cost concerns.
  rotation_minutes       = 10           # Minimum uptime before key recycle.
  vm_uptime_minutes      = 720          # can go for less time if there are cost concerns.
  # Network
  non_routeable_ip_range = "100.65.0"   # CGNAT
  wireguard_port         = "51820"      # The de facto UDP port.

}

terraform {
  required_version = "~> 1.9.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = "~> 2.3"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.0"
    }
    wireguard = {
      source  = "OJFord/wireguard"
      version = "~> 0.3"
    }
  }
}

provider "aws" {
  region              = var.region_name
  allowed_account_ids = [var.account_id]
}
provider "cloudinit" {}
provider "external" {}
provider "random" {}
provider "time" {}
provider "wireguard" {}

resource "time_rotating" "wireguard" { rotation_minutes = local.rotation_minutes }

resource "random_pet" "wireguard" {
  length = 2
  prefix = "wireproxy"
  keepers = {
    rotation_minutes = time_rotating.wireguard.id
  }
}

data "external" "ssh_public_keys" {
  program = ["bash", "-c", "ssh-add -L | jq -s -R '{public_keys: .}'"]
  query = {
    id = random_pet.wireguard.id
  }
}

resource "wireguard_asymmetric_key" "client" { bind = random_pet.wireguard.id }
resource "wireguard_asymmetric_key" "server" { bind = wireguard_asymmetric_key.client.id }
resource "wireguard_preshared_key" "wireguard" {}

data "cloudinit_config" "user_data" {
  gzip          = false
  base64_encode = false

  part {
    filename     = "cloud-config.yaml"
    content_type = "text/cloud-config"

    content = <<EOD
#cloud-config
${yamlencode({
    package_reboot_if_required = true
    package_update             = true
    package_upgrade            = true
    packages = [
      "apt-transport-http",
      "ca-certificates",
      "iptables",
      "net-tools",
      "wireguard",
    ]
    users = [{
      name          = local.whoami
      primary_group = "users"
      groups        = ["wheel"]
      lock_passwd   = true
      shell         = "/bin/bash"
      ssh_authorized_keys : data.external.ssh_public_keys.result.public_keys
      sudo : [
        "ALL=(ALL) NOPASSWD:ALL"
      ]
    }]
    write_files = [{
      path        = "/etc/wireguard/predown.sh"
      owner       = "root:root"
      permissions = "0700"
      append      = true
      content : join("\n", [
        "export PUBLIC_IFACE=$(ip link | awk -F': ' '/^[0-9]/{print$2}' | grep '^en')",
        "iptables -t nat -D POSTROUTING -s ${local.non_routeable_ip_range}.2 -o $${PUBLIC_IFACE} -j MASQUERADE",
        "iptables -D INPUT -i wg0 -j ACCEPT",
        "iptables -D FORWARD -i $${PUBLIC_IFACE} -o wg0 -j ACCEPT",
        "iptables -D FORWARD -i wg0 -o $${PUBLIC_IFACE} -j ACCEPT",
        "iptables -D INPUT -i $${PUBLIC_IFACE} -p udp --dport ${local.wireguard_port} -j ACCEPT",
      ])
      }, {
      path  = "/etc/wireguard/postup.sh"
      owner = "root:root"
      permissions : "0700"
      append : true
      content : join("\n", [
        "export PUBLIC_IFACE=$(ip link | awk -F': ' '/^[0-9]/{print$2}' | grep '^en')",
        "iptables -t nat -I POSTROUTING 1 -s ${local.non_routeable_ip_range}.2 -o $${PUBLIC_IFACE} -j MASQUERADE",
        "iptables -I INPUT -i wg0 -j ACCEPT",
        "iptables -I FORWARD 1 -i $${PUBLIC_IFACE} -o wg0 -j ACCEPT",
        "iptables -I FORWARD 1 -i wg0 -o $${PUBLIC_IFACE} -j ACCEPT",
        "iptables -I INPUT -i $${PUBLIC_IFACE} -p udp --dport ${local.wireguard_port} -j ACCEPT",
      ])
      }, {
      path        = "/etc/wireguard/wg0.conf"
      owner       = "root:root"
      permissions = "0600"
      content : join("\n", [
        "[Interface]",
        "Address = ${local.non_routeable_ip_range}.1",
        "ListenPort = ${local.wireguard_port}",
        "PrivateKey = ${wireguard_asymmetric_key.server.private_key}",
        "PostUp = /etc/wireguard/postup.sh",
        "PreDown = /etc/wireguard/predown.sh",
        "SaveConfig = false",
        "",
        "[Peer]",
        "PublicKey = ${wireguard_asymmetric_key.client.public_key}",
        "PresharedKey = ${wireguard_preshared_key.wireguard.key}",
        "AllowedIPs = ${local.non_routeable_ip_range}.2",
      ])
    }]
    runcmd = [
      "ufw allow ${local.wireguard_port}/udp",
      "ufw enable",
      "sudo bash -c \"echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf && sysctl -p\"",
      "sudo systemctl enable wg-quick@wg0.service",
      "sudo systemctl start wg-quick@wg0.service",
    ]
})}
EOD
}
part {
  filename     = "hello-script.sh"
  content_type = "text/x-shellscript"
  content      = "shutdown -h +${local.vm_uptime_minutes}"
}
}

resource "local_file" "wireproxy_conf" {
  filename        = "${path.module}/wireproxy.conf"
  file_permission = "0755"
  content         = <<EOF
[Interface]
Address = ${local.non_routeable_ip_range}.2/32
MTU = 1420
PrivateKey = ${wireguard_asymmetric_key.client.private_key}
DNS = 8.8.8.8

[Peer]
PublicKey = ${wireguard_asymmetric_key.server.public_key}
PresharedKey = ${wireguard_preshared_key.wireguard.key}
Endpoint = ${aws_instance.wireguard.public_ip}:${local.wireguard_port}
PersistentKeepalive = 25

[Socks5]
BindAddress = 127.0.0.1:1080

[http]
BindAddress = 127.0.0.1:1081

[TCPClientTunnel]
BindAddress = 127.0.0.1:1122
Target = ${local.non_routeable_ip_range}.1:22
EOF
}

data "aws_ssm_parameter" "ubuntu_2404" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

data "aws_ami" "ubuntu_2404" {
  filter {
    name   = "image-id"
    values = [data.aws_ssm_parameter.ubuntu_2404.value]
  }
  most_recent = true
  owners      = ["099720109477"] # Canonical's AWS Account ID.
}

data "aws_region" "current" {}

data "aws_subnet" "default" {
  default_for_az    = true
  availability_zone = "${data.aws_region.current.name}a"
}

data "aws_subnet" "named" {
  count = var.subnet_id == "default" ? 0 : 1
  id    = var.subnet_id
}

data "aws_subnet" "wireguard" {
  id = compact(concat(data.aws_subnet.named.*.id, data.aws_subnet.default.*.id))[0]
}

data "aws_vpc" "from_subnet" {
  id = data.aws_subnet.wireguard.vpc_id
}

resource "aws_security_group" "wireguard" {
  name   = "wireguard"
  vpc_id = data.aws_vpc.from_subnet.id
  ingress {
    from_port        = local.wireguard_port
    to_port          = local.wireguard_port
    protocol         = "udp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

data "aws_iam_policy_document" "assume_wireguard" {
  statement {
    sid     = "AllowEC2"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "wireguard" {
  statement {
    sid       = "WireguardVM"
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "ec2:DescribeRegions",
    ]
  }
}

resource "aws_iam_role" "wireguard" {
  name               = "wireguard"
  assume_role_policy = data.aws_iam_policy_document.assume_wireguard.json
  inline_policy {
    name   = "wireguard"
    policy = data.aws_iam_policy_document.wireguard.json
  }
}

resource "aws_iam_instance_profile" "wireguard" {
  name = random_pet.wireguard.id
  role = aws_iam_role.wireguard.name
}

resource "aws_launch_template" "wireguard" {
  name          = random_pet.wireguard.id
  image_id      = data.aws_ami.ubuntu_2404.id
  instance_type = local.ec2_instance_type
  user_data     = base64encode(data.cloudinit_config.user_data.rendered)

  instance_initiated_shutdown_behavior = "terminate"

  iam_instance_profile {
    name = aws_iam_instance_profile.wireguard.id
  }
  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 8
    http_tokens                 = "required"
    instance_metadata_tags      = "enabled"
  }
  network_interfaces {
    security_groups = [aws_security_group.wireguard.id]
    subnet_id       = data.aws_subnet.wireguard.id
  }
  tag_specifications {
    resource_type = "instance"
    tags          = { Name = random_pet.wireguard.id }
  }
}

resource "aws_instance" "wireguard" {
  launch_template {
    name    = aws_launch_template.wireguard.name
    version = aws_launch_template.wireguard.latest_version
  }
}

output "instnace_id" {
  value = aws_instance.wireguard.id
}

output "public_ip" {
  value = aws_instance.wireguard.public_ip
}
