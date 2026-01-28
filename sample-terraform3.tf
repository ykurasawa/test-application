provider "aws" {
  region     = "us-east-1"
  access_key = "hardcoded-access-key"  # ハードコードされた認証情報（NG）
  secret_key = "hardcoded-secret-key"
}

resource "aws_instance" "example3" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"

  security_groups = [aws_security_group.allow_all.name]

  tags = {
    Name = "InsecureInstance"
  }
}

resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # すべてのIPにSSHを開放（NG）
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "unsecured_bucket" {
  bucket = "my-insecure-bucket3"
  acl    = "public-read"  # 誰でも読み取り可能（NG）

  # サーバーサイド暗号化なし（NG）
  # ロギングなし（NG）
}
