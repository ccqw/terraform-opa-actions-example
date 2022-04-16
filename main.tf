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

  cloud {
    organization = "swidjaja531"

    workspaces {
      name = "gh-actions"
    }
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
  }
}

resource "aws_instance" "amazon-linux" {
  ami                    = "ami-03ededff12e34e59e"
  instance_type          = "t3.micro"
  vpc_security_group_ids = ["${aws_security_group.github-actions-ssh-sg.id}"]

  tags = {
    Name = "al2-test"
  }
}

resource "aws_instance" "rhel" {
  ami                    = "ami-0b0af3577fe5e3532"
  instance_type          = "t3.micro"
  vpc_security_group_ids = ["${aws_security_group.github-actions-ssh-sg.id}"]

  tags = {
    Name = "rhel-test"
  }
}
