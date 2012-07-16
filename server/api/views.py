"""
View code that handles the bulk of the API functionality
"""

import re
import boto
import json
import base64
import hmac, sha
from datetime import datetime, timedelta, tzinfo
from django.http import HttpResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt, csrf_protect

@csrf_exempt
def request_upload(request, filename=None):
    """Construct a response that allows the caller to direct upload to
    s3 storage. The returned JSON structure gives a client the ability
    to construct a POST request that allows for a 45 minute window to
    upload a 65 MB (max) zip file.

    Positional arguments:
    request -- the Django request object

    Keyword arguments:
    filename -- the filename specified to be uploaded (default: None)
    """

    # setup
    now = datetime.now()
    expiration = now + timedelta(minutes=45)
    key = "data/${filename}"
    acl = "private"

    # check the filename
    # ASSERT: Filename must be a zipfile

    # construct the policy document
    policy_document = {
        "expiration": now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        "conditions": [ 
            {"bucket": "s3-bucket"}, 
            ["starts-with", "$key", "data/"],
            {"acl": acl},
            {"success_action_redirect": "http://vave.votinginfoproject.org/api/upload-success"},
            ["starts-with", "$Content-Type", ""],
            ["content-length-range", 0, 68157440] # 65MB
        ]
    }

    policy = base64.b64encode(str(policy_document))
    signature = base64.b64encode(
        hmac.new(settings.AWS_SECRET_ACCESS_KEY, policy, sha).digest())

    # key -- A name for the S3 object that will store the uploaded file's data.
    # This name can be set in advance when you know what information the user
    # will upload, for example: uploads/monthly_report.txt. If you do not know
    # the name of the file a user will upload, the key value can include the
    # special variable ${filename} which will be replaced with the name of the
    # uploaded file. 

    # AWSAccessKeyId -- The Access Key Identifier credential for your Amazon Web
    # Service account.

    # acl -- The access control policy to apply to the uploaded file. If you do
    # not want the uploaded file to be made available to the general public, you
    # should use the value private. To make the uploaded file publicly available,
    # use the value public-read.

    # success_action_redirect -- The URL address to which the user's web browser
    # will be redirected after the file is uploaded. This URL should point to a
    # "Successful Upload" page on your web site, so you can inform your users that
    # their files have been accepted. S3 will add bucket, key and etag parameters
    # to this URL value to inform your web application of the location and hash
    # value of the uploaded file.

    # policy -- A Base64-encoded policy document that applies rules to file
    # uploads sent by the S3 POST form. This document is used to authorize the
    # form, and to impose conditions on the files that can be uploaded.

    # signature -- A signature value that authorizes the form and proves that
    # only you could have created it. This value is calculated by signing the
    # Base64-encoded policy document with your AWS Secret Key.

    # Content-Type -- The content type (mime type) that will be applied to the
    # uploaded file, for example image/jpeg for JPEG picture files. If you do
    # not know what type of file a user will upload, you can either prompt the
    # user to provide the appropriate content type, or write browser scripting
    # code that will automatically set this value based on the file's name.
    #
    # If you do not set the content type with this field, S3 will use the
    # default value application/octet-stream which may prevent some web
    # browsers from being able to display the file properly.

    # file -- The input field that allows a user to select a file to upload.
    # This field must be the last one in the form, as any fields below it are
    # ignored by S3.
    
    resp = {
        "key": key,
        "policy": policy,
        "signature": signature,
        "Content-Type": "application/zip",
        "success_action_redirect": "http://vave.votinginfoproject.org/api/upload-success/",
        "AWSAccessKeyId": settings.AWS_ACCESS_KEY_ID,
        "acl": acl
    }

    return HttpResponse(json.dumps(resp), mimetype="application/json")

def upload_success(request):
    """S3 will add bucket, key and etag parameters to this URL value to
    inform the application of the location and hash value of the
    uploaded file.
    """
    pass
