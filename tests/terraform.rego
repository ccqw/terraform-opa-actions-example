package terraform.analysis

import input as tfplan

########################
# Parameters for Policy
########################

# acceptable score for automated authorization
blast_radius := 30

# weights assigned for each operation on each resource-type
weights := {
    "aws_autoscaling_group": {"delete": 100, "create": 10, "modify": 1},
    "aws_instance": {"delete": 10, "create": 1, "modify": 1, "tags": 10},
    "aws_s3_bucket": {"acl": 10, "tags": 10, "name":10},
    "aws_security_group": {"tags": 10, "name":10}
}

# Consider exactly these resource types in calculations
resource_types := {"aws_autoscaling_group", "aws_instance", "aws_security_group", "aws_iam", "aws_launch_configuration", "aws_s3_bucket"}

minimum_tags = {"Name", "Team"}

#########
# Policy
#########

# Authorization holds if score for the plan is acceptable and no changes are made to IAM
default authz = false
authz {
    score < blast_radius
    not touches_iam
}

# Compute the score for a Terraform plan as the weighted sum of deletions, creations, modifications
score = s {
    all := [ x |
            some resource_type
            crud := weights[resource_type];
            del := crud["delete"] * num_deletes[resource_type];
            new := crud["create"] * num_creates[resource_type];
            mod := crud["modify"] * num_modifies[resource_type];
            acl_chg := crud["acl"] * s3_acl_change[resource_type];
            s3name := crud["name"] * s3_name_change[resource_type];
            tags_chg := crud["tags"] * s3_tags_change[resource_type];
            x := del + new + mod + acl_chg + s3name + tags_chg
    ]
    s := sum(all)
}

# Whether there is any change to IAM
touches_iam {
    all := resources["aws_iam"]
    count(all) > 0
}

####################
# Terraform Library
####################

# list of all resources of a given type
resources[resource_type] = all {
    some resource_type
    resource_types[resource_type]
    all := [name |
        name:= tfplan.resource_changes[_]
        name.type == resource_type
    ]
}

# number of creations of resources of a given type
num_creates[resource_type] = num {
    some resource_type
    resource_types[resource_type]
    all := resources[resource_type]
    creates := [res |  res:= all[_]; res.change.actions[_] == "create"]
    num := count(creates)
}

# number of deletions of resources of a given type
num_deletes[resource_type] = num {
    some resource_type
    resource_types[resource_type]
    all := resources[resource_type]
    deletions := [res |  res:= all[_]; res.change.actions[_] == "delete"]
    num := count(deletions)
}

# number of modifications to resources of a given type
num_modifies[resource_type] = num {
    some resource_type
    resource_types[resource_type]
    all := resources[resource_type]
    modifies := [res |  res:= all[_]; res.change.actions[_] == "update"]
    num := count(modifies)
}

deny[msg] {
    changeset := input.resource_changes[_]
    changeset.type == "aws_security_group"
    in := changeset.change.after.ingress[_]
    contains(changeset.change.after.ingress[_].cidr_blocks, "0.0.0.0/0")
    msg := sprintf("violation-sg-ingress_%v", [changeset.name])
}

violation["violation-s3-bucket-public-acl"] {
   s3_acl_change[resource_types[_]] > 0
}

violation["violation-s3-bucket-name"] {
   s3_name_change[resource_types[_]] > 0
}

violation["violation-missing-required-tags"] {
   s3_tags_change[resource_types[_]] > 0
}

s3_acl_change[resource_type] = num {
    some resource_type
    resource_types[resource_type]
    all := resources[resource_type]
    modifies := [res |  res:= all[_]; re_match(`public-.*`, (res.change.after.acl)); res.change.after.website != null]
    num := count(modifies)
}

s3_name_change[resource_type] = num {
    some resource_type
    resource_types[resource_type]
    all := resources[resource_type]
    modifies := [res |  res:= all[_]; not re_match(`ccqw-terraform-opa-actions-example.*`, (res.change.after.bucket))]
    num := count(modifies)
}

s3_tags_change[resource_type] = num {
    some resource_type
    resource_types[resource_type]
    all := resources[resource_type]
    modifies := [res |  res:= all[_]; not tags_contain_proper_keys(res.change.after.tags)]
    num := count(modifies)
}

# helper functions
tags_contain_proper_keys(tags) {
    keys := {key | tags[key]}
    leftover := minimum_tags - keys
    leftover == set()
}

contains(arr, elem) {
  arr[_] = elem
}
