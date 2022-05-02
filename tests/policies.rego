package terraform.analysis

import input as tfplan

########################
# Parameters for Policy
########################

# there are of course many more
taggable_resources := {"aws_s3_bucket", "aws_instance"}

minimum_tags := {"Name", "Team", "Unit"}

invalid_ingress_cidrs := [
    "0.0.0.0/0",
    "10.0.0.0/8"
]


#########
# Policies
#########

# invalid security group ingress
deny[msg] {
    changeset := input.resource_changes[_]
    changeset.type == "aws_security_group"
    in := changeset.change.after.ingress[_]
    invalid_cidr := invalid_ingress_cidrs[_]
    contains(in.cidr_blocks[_], invalid_cidr)
    msg := sprintf("%s :: security group contains invalid ingress CIDR %s", [changeset.address, invalid_cidr])
}

## s3 public acl
deny[msg] {
    changeset := input.resource_changes[_]
    changeset.type == "aws_s3_bucket"
    inp := changeset.change.after
    re_match(`public-.*`, (inp.acl))
    msg := sprintf("%s.%s :: s3 bucket has a public type ACL '%s'", [changeset.type, changeset.name, inp.acl])
}

# s3 bucket naming convention
deny[msg] {
    changeset := input.resource_changes[_]
    changeset.type == "aws_s3_bucket"
    inp := changeset.change.after
    pattern := "ccqw-terraform-opa-actions-example-violation.*"
    not re_match(pattern, (inp.bucket))
    msg := sprintf("%s :: s3 bucket name '%s' does not conform to required pattern '%s'", [changeset.address, inp.bucket, pattern])
}

# taggable resources have required tags
deny[msg] {
    changeset := input.resource_changes[_]
    changeset.type == taggable_resources[_]
    inp := changeset.change.after
    keys := {key | inp.tags[key]}
    leftover := minimum_tags - keys
    not leftover == set()
    msg := sprintf("%s :: resource missing required tags %s", [changeset.address, leftover])
}

