import os
import urllib.request as ur, json
import boto3
from collections import defaultdict
    
s3_client  = boto3.resource('s3')
sns_client = boto3.client('sns')
url = "https://awspolicygen.s3.amazonaws.com/js/policies.js"
AWS_BUCKET_NAME = 'policy-js-s3a'
SNS_Topic_Arn = 'arn:aws:sns:us-east-2:284551147522:NotifyPolicyChangesSNS'
bucket = s3_client.Bucket(AWS_BUCKET_NAME)

added_action_list = defaultdict(list)
removed_action_list = defaultdict(list)

policy_prefixes = ["access-analyzer", "account", "acm", "acm-pca", "apigateway", "application-autoscaling", "appconfig", "applicationinsights", "appsync", "athena", "autoscaling", "autoscaling-plans", "aws-marketplace-management", "aws-marketplace", "aws-portal", "budgets", "ce", "cloudformation", "cloudfront", "cloudtrail", "cloudwatch", "codecommit", "codedeploy", "codepipeline", "cognito-identity", "cognito-idp", "cognito-sync", "config", "cur", "detective", "directconnect", "dlm", "dynamodb", "ebs", "ec2", "ecr", "ecs", "eks", "elasticfilesystem", "elasticloadbalancing", "es", "events", "execute-api", "firehose", "fms", "frauddetector", "glacier­­­­", "glue", "guardduty", "health", "iam", "imagebuilder", "inspector", "kafka", "kinesis", "kinesisanalytics", "kinesisvideo", "kms", "lakeformation", "lambda", "logs", "mediaconvert", "mediastore", "organizations", "pricing", "quicksight", "ram", "rds-data", "rds-db", "rds", "resource-explorer", "resource-groups", "route53", "route53domains", "route53resolver", "s3", "sagemaker", "savingsplans", "secretsmanager", "securityhub", "servicecatalog", "servicediscovery", "servicequotas", "ses", "shield", "sns", "sqs", "ssm", "ssmmessages", "sso-directory", "states", "storagegateway", "sts", "support", "synthetics", "tag", "trustedadvisor", "waf-regional", "waf", "wafv2", "wellarchitected", "xray"]

def lambda_handler(event, context):
    bucket_data = {}
    response = ur.urlopen(url).read()
    data = json.loads(response[23:])
    file_list = [f for f in bucket.objects.all()]
    for file in file_list:
        bucket_data = json.loads(file.get()['Body'].read().decode(encoding="utf-8", errors="ignore"))
    
    if not bucket_data:
        save_to_s3(data)
    else:
        if len(data['serviceMap']) == len(bucket_data['serviceMap']):
            
            for service,local_service in zip(data['serviceMap'],bucket_data['serviceMap']):
                
                    live_data = data['serviceMap'][service]['Actions']
                    local_data = bucket_data['serviceMap'][local_service]['Actions']
                  
                    
                    # Action is added
                    if len(live_data) != len(local_data) and len(live_data) > len(local_data):
                        temporary_list = list(set(live_data) - set(local_data))
                        if data['serviceMap'][service]['StringPrefix'] in policy_prefixes:
                            added_action_list[service].append(temporary_list)
                        
                    # Action is removed
                    if len(live_data) != len(local_data) and len(live_data) < len(local_data):
                        temporary_list_r = list(set(local_data) - set(live_data))
                        if data['serviceMap'][service]['StringPrefix'] in policy_prefixes:
                            removed_action_list[service].append(temporary_list_r)
                        
            if len(added_action_list) != 0 or len(removed_action_list) != 0:
                
                publish_message_to_sns(added_action_list,removed_action_list)
                
        
        elif len(data['serviceMap']) != len(bucket_data['serviceMap']):
            
            dict1 = data['serviceMap']
            dict2 = bucket_data['serviceMap']
            different_keys_in_live_data = {}
            different_keys_in_local_data = {}
            if len(dict1) > len(dict2):
                different_keys = dict1.keys() - dict2
                for val in different_keys:
                    added_action_list[val].append(dict1[val]['Actions'])
                    dict1.pop(val)
        
            different_keys_in_local_data = dict2.keys() - dict1
            for val in different_keys_in_local_data:
                dict2.pop(val)
        
            for service,local_service in zip(dict1,dict2):
                live_data = dict1[service]['Actions']
                local_data = dict2[local_service]['Actions']
        
                # Action is added
                if len(live_data) != len(local_data) and len(live_data) > len(local_data):
                    temporary_list = list(set(live_data) - set(local_data))
                    if data['serviceMap'][service]['StringPrefix'] in policy_prefixes:
                        added_action_list[service].append(temporary_list)
                    
                # Action is removed
                if len(live_data) != len(local_data) and len(live_data) < len(local_data):
                    temporary_list_r = list(set(local_data) - set(live_data))
                    if data['serviceMap'][service]['StringPrefix'] in policy_prefixes:
                        removed_action_list[service].append(temporary_list_r)
            
            if len(added_action_list) != 0 or len(removed_action_list) != 0:
                publish_message_to_sns(added_action_list,removed_action_list)
                # Changes are deteced.. Update s3 bucket with most recent downloaded json policy from the url
                # Un comment below line after testing...
    #print(data)
    #save_to_s3(data)
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }

def save_to_s3(data):
   
    path = 'policy.json'
    try:
        bucket.put_object(
            ContentType='application/json',
            Key=path,
            Body=json.dumps(data),
        )
    except Exception as ClientError:
        print(ClientError)
        
def publish_message_to_sns(added,removed):
    
    message_body = "Hello, the following new actions have been added to AWS.\n\n."
    if len(added) > 0:
        for k in added:
            #print('Service Name : {} \n Actions Added : {}'.format(k,added[k][0]))
            message_body += 'Service Name : {} \n Actions Added : {} \n\n'.format(k,added[k][0])
    
    if len(removed) > 0:
        for j in removed:
            #print('Service Name:{} , Actions Removed:{}'.format(j,removed[j][0]))
            message_body += 'Service Name : {} \n Actions Removed : {} \n\n'.format(j,removed[j][0])
            
    print(message_body)

    try:
        sns_client.publish(
        TargetArn=SNS_Topic_Arn,
        Subject=f'Alert New AWS API Call',
        Message=message_body
        )
    except Exception as ClientError:
        print(ClientError)
