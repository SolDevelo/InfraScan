resource "aws_instance" "app_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro" # Antipattern: Old Generation
  
  tags = {
    Name = "ExampleAppServerInstance"
  }
}

resource "aws_instance" "db_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "r5.24xlarge" # Antipattern: Expensive Instance
}

resource "aws_ebs_volume" "example" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = false # Antipattern: Unencrypted EBS
  type              = "io1" # Antipattern: Provisioned IOPS
}
