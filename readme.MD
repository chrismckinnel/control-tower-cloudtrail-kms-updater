# Table of Contents
- [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Repository Cloudformation Templates and Parameters](#repository-cloudformation-templates-and-parameters)

## Introduction

Control Tower does not use KMS to encrypt the trails by default, and Security Hub CIS
benchmarks complain that it is non-compliant.

This repository contains Cloudformation template to create a CloudWatch event rule 
which deploys and triggers a lambda function that will update the KMS CMK key policy 
and CloudTrail with the KMS key whenever a new member account is created (via 
CreateManagedAccount event from CloudTrail).

## Repository Cloudformation Templates and Parameters

`cloudformation.yaml` - This Cloudformation template is deployed in the Master Account 
to create a cloudwatch event rule and lambda function.

The following table shows the paramaters required for `cloudformation.yaml`:

Parameter | Description
------------ | -------------
LogArchiveAccountId | 12 digit AWS Account id of AWS Security Account
CloudTrailName | The name of the CloudTrail trail to update with the KMS key
CloudTrailLambdaS3Bucket | The name of the S3 bucket where the CloudTrail update lambda zip file lives
CloudTrailLambdaZipFile | The name of the CloudTrail update lambda zip file
