# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from botocore.exceptions import ClientError

import base64
import boto3
import http.client
import json
import jwt
import os
import pprint
import time
import urllib.parse
import requests
import math

"""
Initializing SDK clients to facilitate reuse across executions
"""

DYNAMODB_CLIENT = boto3.client("dynamodb")

SM_CLIENT = boto3.client(
    service_name = "secretsmanager",
    region_name = os.environ.get("AWS_REGION")
)

def validate_request(params: dict) -> bool:
    """
    Helper function to validate request parameters - can be used to drop requests early during runtime.
    """
    validation = False

    if params["client_id"] == os.environ.get("ClientId") and params["client_secret"] == os.environ.get("ClientSecret"):
        validation = True

    return validation

def get_secret(secret_name):
    """
    Retrieves a secret from AWS Secrets Manager.

    Args:
        secret_name (str): The name of the secret to retrieve.

    Returns:
        str: The secret value.

    Raises:
        ClientError: If there's an error retrieving the secret.
    """

    try:
        get_secret_value_response = SM_CLIENT.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise Exception (f"Error retrieving secret '{secret_name}'") from e

    if 'SecretString' in get_secret_value_response:
        secret = get_secret_value_response['SecretString']
    else:
        binary_secret_data = get_secret_value_response['SecretBinary']
        secret = binary_secret_data.decode('utf-8')

    return secret

def get_private_key(config):
    """
    Retrieves the private key from AWS Secrets Manager and converts it to a JWK format.

    Args:
        config (dict): A dictionary containing the configuration settings.

    Returns:
        jwk.JWK: The private key in JWK format.
    """
    print("+++ RETRIEVING SECRET FROM SECRET MANAGER +++")
    private_key_secret = get_secret(config["secret_name"])

    try:
        # Attempt to parse the secret as JSON
        private_key_dict = json.loads(private_key_secret)
        private_key = jwt.jwk_from_dict(private_key_dict)
    except ValueError:
        # If the secret is not JSON, assume it's a PEM-encoded string
        private_key = jwt.jwk_from_pem(private_key_secret.encode('utf-8'))

    print("+++ KEY RETRIEVED +++")

    return private_key

def handler(event, context):
    #  All prints left in to observe behaviour in CloudWatch
    print("+++ FULL EVENT DETAILS +++")
    print(event)
    print("#####################")

    # Decode the cognito request and convert to utf-8
    encoded_message = event["body"]
    decoded_message = base64.b64decode(encoded_message)
    decoded_message = decoded_message.decode("utf-8")

    print("+++ DECODED COGNITO REQUEST +++")
    print(decoded_message)

    # Create parameter dictionary from request
    param_list = list(decoded_message.split("&"))
    param_dict = {}
    for item in param_list:
        key, value = item.split("=")
        param_dict[key] = value

    print("+++ DECODED PARAMETER LIST +++")
    print(param_dict)

    if not validate_request(param_dict):
        print("+++ VALIDATION FAILED - CANCELLING +++")
        return { "statusCode": 400 }

    print("+++ VALIDATION SUCCESSFUL - PROCEEDING +++")

    # Defining pkce toggle here because it is required in multiple different parts below
    pkce_toggle = False

    if os.environ.get("Pkce").lower() == "true":
        pkce_toggle = True
        print("+++ USING PKCE +++")

    # Fetching all details from original request and env vars
    config = {}
    config["auth_code"] = param_dict["code"]
    config["client_id"] = param_dict["client_id"]
    config["idp_issuer_url"] = os.environ.get("IdpIssuerUrl")
    config["idp_token_path"] = os.environ.get("IdpTokenPath")
    config["idp_token_endpoint"] = config["idp_issuer_url"] + config["idp_token_path"]
    config["secret_name"] = os.environ.get("SecretsManagerPrivateKey")
    config["original_response_uri"] = os.environ.get("ResponseUri")

    if pkce_toggle:
        config["code_table"] = os.environ.get("DynamoDbCodeTable")

    print("+++ CONFIGURATION ITEMS +++")
    print(config)

    # Get code_verifier associated with auth_token when using PKCE
    if pkce_toggle:
        code_result = DYNAMODB_CLIENT.get_item(
            TableName = config["code_table"],
            Key = {
                "auth_code": {
                    "S": config["auth_code"]
                }
            }
        )
        code_verifier = code_result["Item"]["code_verifier"]["S"]

        print("+++ CODE VERIFIER FOUND +++")
        print(code_verifier)

    # Get private key from Secrets Manager
    private_key = get_private_key(config["secret_name"])

    print("+++ SIGNING TOKEN +++")
    # Create the private key jwt
    instance = jwt.JWT()
    private_key_jwt = instance.encode({
        "iss": config["client_id"],
        "sub": config["client_id"],
        "aud": config["idp_token_endpoint"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 300
    },
        private_key,
        alg='RS256',
        # optional_headers = {"kid": private_key_dict["kid"]}
    )

    print("+++ PRIVATE KEY JWT +++")
    print(private_key_jwt)

    # Add client_assertion to the query string params
    param_dict["client_assertion"] = private_key_jwt
    param_dict["grant_type"] = "authorization_code"
    param_dict["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    param_dict["redirect_uri"] = config["original_response_uri"]

    # Add the api gw url from the authorize request and code verifier when using PKCE
    if pkce_toggle:
        param_dict["code_verifier"] = code_verifier

    # Remove client_secret_basic from authorization header since using private key JWT for token exchange
    param_dict.pop("client_secret")

    # Calculate and convert the remaining Lambda execution time (in milliseconds) to seconds and subtract a small buffer (e.g., 5 second)
    timeout_seconds = math.floor((context.get_remaining_time_in_millis() - 5000) / 1000)

    # Make sure the timeout is at least 1 second
    request_timeout = max(1, timeout_seconds)

    # Make the token request
    try:  
        payload = urllib.parse.urlencode(param_dict)
        print("+++ PAYLOAD +++")
        print(payload)

        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        response = requests.post(config["idp_token_endpoint"], data=payload, headers=headers, timeout=request_timeout)

        print("+++ IDP RESPONSE +++")
        print(f"Status: {response.status_code}, Reason: {response.reason}")

        # Return IdP response to Cognito
        data = response.text

        print(data)
    except requests.exceptions.RequestException as e:
        print("fError:{e}")

    return data

