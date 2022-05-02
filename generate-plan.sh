#! /usr/bin/env bash
terraform plan --out tfplan.binary
if ! $(terraform show -json tfplan.binary >tfplan.json); then
    echo
    echo "*********************"
    echo failed to generate json
else
    echo
    echo "*********************"
    echo generated json from terraform plan 👍🏻
fi
