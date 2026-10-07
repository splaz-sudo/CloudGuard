export type ResourceType =
  | "internet"
  | "ec2"
  | "iam_user"
  | "iam_role"
  | "s3_bucket"
  | "rds"
  | "lambda"
  | "secret"
  | "security_group"
  | "vpc"
  | "unknown";

const TYPE_ALIASES: Record<string, ResourceType> = {
  internet: "internet",
  ec2: "ec2",
  instance: "ec2",
  iam_user: "iam_user",
  "iam-user": "iam_user",
  iam_role: "iam_role",
  "iam-role": "iam_role",
  s3: "s3_bucket",
  s3_bucket: "s3_bucket",
  "s3-bucket": "s3_bucket",
  rds: "rds",
  lambda: "lambda",
  secret: "secret",
  security_group: "security_group",
  "security-group": "security_group",
  sg: "security_group",
  vpc: "vpc",
};

/**
 * Map any API-provided type / node-id prefix onto a known ResourceType.
 * Never returns a value outside TYPE_META, so rendering cannot crash on
 * unexpected asset types or node ids.
 */
export function normalizeResourceType(raw: string | undefined | null): ResourceType {
  if (!raw) return "unknown";
  const key = raw.toLowerCase();
  if (TYPE_ALIASES[key]) return TYPE_ALIASES[key];
  if (/^i-[0-9a-z]/.test(key)) return "ec2";
  return "unknown";
}

