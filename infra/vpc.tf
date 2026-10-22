# Network is pre-provisioned in the account (not managed here): look up the
# existing VPC and its public subnets by Name tag. Both public subnets share a
# route table with a 0.0.0.0/0 route to the VPC's internet gateway.
data "aws_vpc" "primary" {
  tags = { Name = "Primary_VPC" }
}

# The ECS task runs here.
data "aws_subnet" "public_1a" {
  vpc_id = data.aws_vpc.primary.id
  tags   = { Name = "Public_Subnet_1A" }
}

# An ALB requires subnets in at least two AZs, so it also spans 1B.
data "aws_subnet" "public_1b" {
  vpc_id = data.aws_vpc.primary.id
  tags   = { Name = "Public_Subnet_1B" }
}

# ALB ingress open to all IPs on 80 (redirects to HTTPS) and 443. To add an
# allowlist, set cidr_blocks to var.allowed_cidrs here and in the WAF (waf.tf).
resource "aws_security_group" "alb" {
  name = "${var.app_name}-alb"
  # Stale wording, kept on purpose: changing a security group's description forces
  # its replacement, and this one is attached to the ALB.
  description = "ALB ingress from the campus allowlist only"
  vpc_id      = data.aws_vpc.primary.id

  ingress {
    description = "HTTP from anywhere (redirects to HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.app_name}-alb" }
}

resource "aws_security_group" "task" {
  name        = "${var.app_name}-task"
  description = "Fargate task ingress from ALB only"
  vpc_id      = data.aws_vpc.primary.id

  ingress {
    description     = "app port from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.app_name}-task" }
}
