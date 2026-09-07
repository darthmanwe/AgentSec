resource "aws_s3_bucket" "public" {
  bucket = "agentsec-fixture-bucket"
  acl    = "public-read"
}

resource "aws_security_group_rule" "open_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
