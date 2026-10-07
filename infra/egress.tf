# Temporary: needed for address verification rollout, tighten later
resource "aws_security_group_rule" "payments_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.payment_service.id
}
