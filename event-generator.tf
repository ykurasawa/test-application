provider "aws" {
  region = "us-east-1"
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "sysdig_log_group" {
  name              = "/ecs/event-generator"
  retention_in_days = 365
}

# IAM Role for Lambda
resource "aws_iam_role" "serverless_patcher_role" {
  name = "serverless_patcher_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# Lambda Function
resource "aws_lambda_function" "serverless_patcher" {
  function_name = "serverless_patcher"
  role          = aws_iam_role.serverless_patcher_role.arn
  package_type  = "Image"
  image_uri     = "quay.io/sysdig/serverless-patcher:5.3.2"
  environment {
    variables = {
      SYSDIG_COLLECTOR_HOST = "your-sysdig-collector"
      SYSDIG_COLLECTOR_PORT = "6443"
      SYSDIG_ACCESS_KEY     = "your-access-key"
    }
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "sysdig_event_generator" {
  name = "sysdig-event-generator"
}

# Security Group
resource "aws_security_group" "event_generator" {
  name        = "event-generator"
  description = "Security group for the event generator service"
  vpc_id      = "your-vpc-id"
}

# Task Role
resource "aws_iam_role" "ecs_task_role" {
  name = "ecs_task_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# ECS Task Definition
resource "aws_ecs_task_definition" "event_generator" {
  family                   = "event-generator"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.ecs_task_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name  = "event-generator"
      image = "docker.io/falcosecurity/event-generator:latest"
      entryPoint = ["/bin/event-generator"]
      command = ["run", "syscall", "--sleep", "10m", "--loop"]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-region        = "us-east-1"
          awslogs-group         = "/ecs/event-generator"
          awslogs-stream-prefix = "app"
        }
      }
      essential = true
    }
  ])
}

# ECS Service
resource "aws_ecs_service" "event_generator" {
  name            = "event-generator-service"
  cluster         = aws_ecs_cluster.sysdig_event_generator.id
  task_definition = aws_ecs_task_definition.event_generator.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    assign_public_ip = true
    security_groups  = [aws_security_group.event_generator.id]
    subnets          = ["your-subnet-id"]
  }
}
