terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "3.26.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.0.1"
    }
  }
  required_version = ">= 1.1.0"

  backend "s3" {
    bucket = "ccqw-scratch-terraform-tfstates-us-east-1"
    key    = "terraform-opa-actions-example.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "github-actions-ssh-sg" {
  name        = "github-actions-ssh-sg"
  description = "allow SSH inbound traffic"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  // allow internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "github-actions-ssh-sg"
    Team = "ccqw"
  }
}

resource "aws_instance" "amazon-linux" {
  ami                    = "ami-03ededff12e34e59e"
  instance_type          = "t3.micro"
  vpc_security_group_ids = ["${aws_security_group.github-actions-ssh-sg.id}"]

  tags = {
    Name = "al2-test"
    Team = "ccqw"
  }
}

resource "aws_instance" "rhel" {
  ami                    = "ami-0b0af3577fe5e3532"
  instance_type          = "t3.micro"
  vpc_security_group_ids = ["${aws_security_group.github-actions-ssh-sg.id}"]

  tags = {
    Name = "rhel-test"
    Team = "ccqw"
  }
}

resource "aws_s3_bucket" "b" {
  bucket = "ccqw-terraform-opa-actions-example-test-bucket"
  acl    = "private"

  tags = {
    Name = "ccqw-terraform-opa-actions-example-test-bucket"
    Team = "ccqw"
  }
}
