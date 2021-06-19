import json
import boto3


CLOUDTRAIL_NAME = 'aws-controltower-BaselineCloudTrail'
LOGGING_ACCOUNT_ID = None # log account number (should live in ssm or similar)


def handler(event, context):
    target_account_id = get_target_account_id(event=event)
    current_account_id = get_current_account_id(event=event)
    kms_key_id = get_kms_key_id()

    update_kms_key_policy(
        current_account_id=current_account_id,
        target_account_id=target_account_id,
        kms_key_id=kms_key_id
    )
    update_cloudtrails(
        current_account_id=current_account_id,
        target_account_id=target_account_id,
        kms_key_id=kms_key_id
    )


def update_kms_key_policy(current_account_id, target_account_id, kms_key_id):
    kms_client = get_boto_client(
        target_account_id=LOGGING_ACCOUNT_ID,
        service_name='kms'
    )
    response = kms_client.get_key_policy(
        KeyId=kms_key_id,
        PolicyName='default'
    )
    key_policy = json.loads(response['Policy'])
    key_policy = get_updated_key_policy(
        key_policy=key_policy,
        target_account_id=target_account_id,
        kms_client=kms_client,
        kms_key_id=kms_key_id
    )
    kms_client.put_key_policy(
        KeyId=kms_key_id,
        PolicyName='default',
        Policy=json.dumps(key_policy)
    )


def get_updated_key_policy(key_policy, target_account_id, kms_client, kms_key_id):

    index = get_cloudtrail_encrypt_statement_index(
        key_policy=key_policy
    )
    string_like = key_policy['Statement'][index]['Condition']['StringLike']
    encryption_context = string_like['kms:EncryptionContext:aws:cloudtrail:arn']
    new_encryption_context = get_cloudtrail_encryption_context(
        target_account_id=target_account_id
    )
    if encryption_context == new_encryption_context:
        return key_policy

    if isinstance(encryption_context, str):
        string_like['kms:EncryptionContext:aws:cloudtrail:arn'] = [
            encryption_context,
            get_cloudtrail_encryption_context(
                target_account_id=target_account_id
            )
        ]
        key_policy['Statement'][index]['Condition']['StringLike'] = string_like
    else:
        if new_encryption_context in encryption_context:
            return key_policy

        string_like['kms:EncryptionContext:aws:cloudtrail:arn'].append(
            new_encryption_context
        )
    return key_policy


def get_cloudtrail_encrypt_statement_index(key_policy):
    for index, statement in enumerate(key_policy['Statement']):
        if statement['Sid'] == 'Enable CloudTrail Encrypt Permissions':
            return index


def get_cloudtrail_encryption_context(target_account_id):
    return f'arn:aws:cloudtrail:*:{target_account_id}:trail/*'


def update_cloudtrails(current_account_id, target_account_id, kms_key_id):
    if target_account_id != current_account_id:
        cloudtrail_client = get_boto_client(
            target_account_id=target_account_id,
            service_name='cloudtrail'
        )
    else:
        cloudtrail_client = boto3.client('cloudtrail')

    response = cloudtrail_client.get_trail(
        Name=CLOUDTRAIL_NAME
    )

    if 'Trail' in response:
        response = cloudtrail_client.update_trail(
            Name=CLOUDTRAIL_NAME,
            KmsKeyId=kms_key_id
        )
    print(response)


def get_boto_client(target_account_id, service_name):
    session = boto3.Session()
    sts_client = boto3.client('sts')
    session_name = "aws-landing-zone-role"
    role_to_assume = (
        "arn:aws:iam::%s:role/AWSControlTowerExecution" %
        target_account_id
    )

    response = sts_client.assume_role(
        RoleArn=role_to_assume,
        RoleSessionName=session_name
    )
    credentials = response['Credentials']
    return session.client(
        service_name,
        region_name='ap-southeast-2',
        aws_access_key_id=credentials.get('AccessKeyId'),
        aws_secret_access_key=credentials.get('SecretAccessKey'),
        aws_session_token=credentials.get('SessionToken')
    )


def get_target_account_id(event):
    service_event_details = event['detail']['serviceEventDetails']
    account = service_event_details['createManagedAccountStatus']['account']
    return account['accountId']


def get_current_account_id(event):
    return event['detail']['userIdentity']['accountId']


def get_kms_key_id():
    ssm_client = get_boto_client(
        target_account_id=LOGGING_ACCOUNT_ID,
        service_name='ssm'
    )
    response = ssm_client.get_parameter(Name='/cloudtrail/kms-key-arn')
    return response['Parameter']['Value']


if __name__ == '__main__':
    event = {
        'detail': {
            'serviceEventDetails': {
                'createManagedAccountStatus': {
                    'account': {
                        'accountId': ''
                    }
                }
            },
            'userIdentity': {
                'accountId': ''
            }
        }
    }
    handler(event=event, context={})