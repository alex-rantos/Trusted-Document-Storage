# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import hashlib
import os
import datetime as dt
from django.views.decorators.csrf import csrf_exempt
import boto3
from django.core import serializers
import json
from django.http import HttpResponse, JsonResponse, FileResponse, Http404
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, logout, authenticate
from .models import User
from .models import UploadFile
from .models import DownloadFile
from .models import Receipt


# Create your views here.
def signup_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            # return redirect('messages:list')
            return render(request, 'accounts/website.html', {'form': form})
    else:
        form = UserCreationForm()
        return render(request, 'accounts/signup.html', {'form': form})
    return render(request, 'accounts/signup.html', {'form': form})


def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            # login user
            user = form.get_user()
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            if 'next' in request.POST:
                return redirect(request.POST.get('next'))
            else:
                return render(request, 'accounts/interface.html', {'form': form})

    else:
        form = AuthenticationForm()
    return render(request, 'accounts/login.html', {'form': form})


def logout_view(request):
    if request.method == "POST":
        form = AuthenticationForm(data=request.POST)
        logout(request)
        # return redirect('messages:list')
        return render(request, 'accounts/login.html', {'form': form})


def send_view(request):
    return render(request, 'accounts/main.html')


def main_view(request):
    return render(request, 'accounts/website.html')


def login_user(request):
    if request.method == "GET":
        return render(request, 'login.html', {})
    if request.method == "POST":
        client_name = request.POST.get('username', '')
        client_pass = request.POST.get('password', '')
        client = authenticate(username=client_name, password=client_pass)
        msg = 'Username or password is wrong'

        if client is not None:
            login(request, client, backend='django.contrib.auth.backends.ModelBackend')
            return render(request, 'accounts/website.html', {'username': client_name})
        else:
            form = AuthenticationForm()
            return render(request, 'accounts/login.html', {'form': form, 'login_message':msg })


def test(request):
    data = {}
    user_list = User.objects.all()
    user = User.objects.filter(id=2)
    data['list'] = json.loads(serializers.serialize("json", user))
    return JsonResponse(data)


def send(request):
    if request.method == "POST":
        userId = request.POST.get('userId', None)
        files = request.FILES.get('img')
        #
        file_ = os.path.join("uploads", files.name)
        f = open(file_, "wb")
        for item in files.chunks():
            f.write(item)
        f.close()

        path = os.path.abspath(os.path.dirname(os.getcwd())) + '/client/uploads/' + files.name
        path = path.replace('\\', '/')

        user = User.objects.filter(id=userId)
        uploadFile = UploadFile(userID=user[0], state=1, filename=files.name, filePath=path)
        uploadFile.save()

        fileId = uploadFile.id
        #

        sqs = boto3.resource('sqs',
            aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
            aws_secret_access_key="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",
            region_name='us-east-1')
        queue = sqs.get_queue_by_name(QueueName='Queue_for_TTP.fifo')
        message = {'fileId': fileId}
        data = {'protocolStep': 1,
                'userId': userId,
                'message': message}
        msg = json.dumps(data)
        response = queue.send_message(MessageBody=msg, MessageGroupId="1",
                                      MessageDeduplicationId=dt.datetime.now().strftime('%j%H%M%S') + "_" + str(userId))

    return render(request, 'accounts/main.html', {'path': path})


def uploaded_file_view(request, userId):
    file_list = UploadFile.objects.filter(userID=userId)
    return render(request, 'accounts/uploaded_file_view.html', {'file_list': file_list})


def downloaded_file_view(request, userId):
    file_list = DownloadFile.objects.filter(userID=userId)
    return render(request, 'accounts/downloaded_file_view.html', {'file_list': file_list})


def receipt_view(request, userId):
    file_list = Receipt.objects.all()
    return render(request, 'accounts/receipt_view.html', {'file_list': file_list})


def all_file_view(request, userId):
    file_list = UploadFile.objects.filter(state='2')
    return render(request, 'accounts/all_file_view.html', {'file_list': file_list})


def request_download(request, fileId, userId):
    file = UploadFile.objects.filter(id=fileId)
    file = file[0]
    # step4
    sqs = boto3.resource('sqs',
            aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
            aws_secret_access_key="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",
            region_name='us-east-1')
    queue = sqs.get_queue_by_name(QueueName='Queue_for_TTP.fifo')
    message = {"fileId": fileId}
    data = {
        "protocolStep": 4,
        "userId": userId,
        "message": message
    }
    msg = json.dumps(data)
    response = queue.send_message(MessageBody=msg, MessageGroupId="1",
                                  MessageDeduplicationId=dt.datetime.now().strftime('%j%H%M%S') + "_" + str(userId))

    user = User.objects.filter(id=userId)
    fileInstance = UploadFile.objects.filter(id=fileId)
    downloadFile = DownloadFile(fileId=fileInstance[0], userID=user[0], state=1,
                                nro="Not received", nro_original="Null")
    downloadFile.save()
    download_id = downloadFile.id

    return render(request, 'accounts/wait.html', {'file': file, 'download_id': download_id})


def receive_first_msg():
    sqs = boto3.resource('sqs',
            aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
            aws_secret_access_key="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",
            region_name='us-east-1')
    queue = sqs.get_queue_by_name(QueueName='Queue_for_B.fifo')
    for message in queue.receive_messages(MessageAttributeNames=['Author']):
        dic = json.loads(message.body)
        if dic is not None:
            message.delete()
            return dic
        else:
            return None


def sign_by_KMS(keyId, msg):
    kms_client = boto3.client('kms',
            aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
            aws_secret_access_key="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",
            region_name='us-east-1')
    sign_response = kms_client.sign(
        KeyId=keyId,
        Message=msg,
        SigningAlgorithm='ECDSA_SHA_256'
    )
    sig = sign_response["Signature"]
    return sig


def download_file_from_S3(path):
    s3 = boto3.resource('s3',
            aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
            aws_secret_access_key="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",
            region_name='us-east-1')
    bucket_name = 'csc8113t3'
    local_file_name_list = path.split('/')
    local_file_name = local_file_name_list[-1]
    s3.Object(bucket_name, path).download_file(local_file_name)
    return local_file_name


def send_msg_to_SQS_step_6(fileId, n, sigB, userId):
    sqs = boto3.resource('sqs',
            aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
            aws_secret_access_key="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",
            region_name='us-east-1')
    queue = sqs.get_queue_by_name(QueueName='Queue_for_TTP.fifo')
    message = {"fileId": fileId, "nonce": n, "signature": sigB.hex()}
    data = {
        "protocolStep": 6,
        "userId": userId,
        "message": message
    }
    msg = json.dumps(data)
    response = queue.send_message(MessageBody=msg, MessageGroupId="1",
                                  MessageDeduplicationId=dt.datetime.now().strftime('%j%H%M%S') + "_" + str(userId))

    return response is not None

@csrf_exempt
def download(request):
    userId = request.POST.get('userId')
    fileId = request.POST.get('fileId')
    download_id = request.POST.get('download_id')
    i = 0
    response = receive_first_msg()
    if response is not None:
        protocol_step = response['protocolStep']

        # send protocol step 6
        #  receive message = {"cmkId": cmkIdB, "nonce": nonceB, "signature": SigA(H(M))}
        #                    {"cmkId":cmkIdB, "fileId":fileId, "nonce":nonceB, "signature":SigA(H(M))}
        #  send message = {"nonce": nonceB, "Signature": SigB(SigA(H(M)))}
        #                 {"fileId":fileId, "nonce":nonceB, "Signature":SigB(SigA(H(M)))}
        if protocol_step == 5:
            message_json = response['message']
            message = message_json
            cmkId = message['cmkId']
            nonce = message['nonce']
            sigA_str = message['signature']

            sigA_bty = bytes.fromhex(sigA_str)#sigA_str.encode(encoding='Latin-1')
            sigB_bty = sign_by_KMS(cmkId, sigA_bty)

            send_msg_to_SQS_step_6(fileId, nonce, sigB_bty, userId)
            i = 1

        # {"NRO":(SigA(H(M)), "filePath":filePathOnS3}
        elif protocol_step == 8:
            print(response)
            message_json = response['message']
            message = message_json
            print(message)
            NRO = message['NRO']
            if NRO is not None:
                NRO_received = "Received"
            else:
                NRO_received = "Not Received"
            file_path_on_S3 = message['filePath']
            download_file_from_S3(file_path_on_S3)

            # user = User.objects.filter(id=userId)
            # fileInstance = UploadFile.objects.filter(id=fileId)
            # downloadFile = DownloadFile(fileId=fileInstance[0], userID=user[0], state=2,
            #                             nro=NRO_received, nro_original=NRO)
            # downloadFile.save()
            data = {'state': 2, 'nro': NRO_received, 'nro_original': NRO}
            DownloadFile.objects.filter(id=download_id).update(**data)

            i = 2
        else:
            i = 0
    else:
        i = 0
    data = {"msg": i}
    return JsonResponse(data)


def downloadfile(request, fileId):
    # filename = "a.txt"
    file = UploadFile.objects.filter(id=fileId)
    file = file[0]
    file_name = file.filename
    try:
        file = open(file_name, 'rb')
        response = FileResponse(file)
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = 'attachment;filename= %s' % file_name
        return response
    except Exception:
        raise Http404


def request_abort(request, fileId, userId):
    file = UploadFile.objects.filter(id=fileId)
    file = file[0]

    sqs = boto3.resource('sqs',
            aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
            aws_secret_access_key="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",
            region_name='us-east-1')
    queue = sqs.get_queue_by_name(QueueName='Queue_for_TTP.fifo')
    data = {
        "protocolStep": "a",
        "userId": userId,
        "fileId": fileId
    }
    msg = json.dumps(data)
    response = queue.send_message(MessageBody=msg, MessageGroupId="1",
                                  MessageDeduplicationId=dt.datetime.now().strftime('%j%H%M%S') + "_" + str(userId))
    return render(request, 'accounts/abort_wait.html', {'file': file})


def abort(request):
    # userId = request.POST.get('userId')
    # fileId = request.POST.get('fileId')
    i = 0
    # response = receive_first_msg()
    # if response is not None:
    #     protocol_step = response['protocolStep']
    #     if protocol_step == "a":
    #         userId = response["userId"]
    #         fileId = response["fileId"]
    #         abort_code = response["abort"]
    #         if abort_code == 1:
    #             i = 2
    #         elif abort_code == 2:
    #             # set abort，delete record
    #             UploadFile.objects.filter(id=fileId).delete()
    #             i = 2
    #         elif abort_code == 3:
    #             # set abort，front page will not display record whose status = 3
    #             UploadFile.objects.filter(id=fileId).update(state='3')
    #             i = 2
    #         else:
    #             i = 0
    #     else:
    #         i = 0
    # else:
    #     i = 0
    data = {"msg": i}
    return JsonResponse(data)
