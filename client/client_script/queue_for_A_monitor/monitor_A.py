import boto3
import hashlib
import datetime as dt
import time
import json
import pymysql


def receive_first_msg():
    sqs = boto3.resource('sqs',
            aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
            aws_secret_access_key="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",
            region_name='us-east-1')
    queue = sqs.get_queue_by_name(QueueName='Queue_for_A.fifo')
    for message in queue.receive_messages(MessageAttributeNames=['Author']):
        dic = json.loads(message.body)
        if dic is not None:
            message.delete()
            return dic
        else:
            return None


def create_file_digest(file_path):
    BUF_SIZE = 2 ** 16
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256()
        # use buffer for faster digest calculation
        buffer = f.read(BUF_SIZE)
        while buffer:
            file_hash.update(buffer)
            buffer = f.read(BUF_SIZE)
    return file_hash.digest()


def sign_by_KMS(keyId, hash_code):
    kms_client = boto3.client('kms',
            aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
            aws_secret_access_key="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",
            region_name='us-east-1')
    sign_response = kms_client.sign(
        KeyId=keyId,
        Message=hash_code,
        MessageType='DIGEST',
        SigningAlgorithm='ECDSA_SHA_256'
    )
    sig = sign_response["Signature"]
    return sig


def upload_file_to_S3(path):
    # userId = str(userId)
    s3 = boto3.resource('s3',
            aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
            aws_secret_access_key="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",
            region_name='us-east-1')
    bucket_name = 'csc8113t3'
    # path = 'uploads/' + fileName
    rename = dt.datetime.now().strftime('%j%H%M%S') + '_' + path
    s3.Object(bucket_name, rename).upload_file(path)
    return rename


def send_msg_to_SQS_step_3(filePath, fileId, nonce, sigA, userId):
    sqs = boto3.resource('sqs',
            aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
            aws_secret_access_key="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",
            region_name='us-east-1')
    queue = sqs.get_queue_by_name(QueueName='Queue_for_TTP.fifo')
    #sigA = sigA.decode('ascii')
    message = {"filePath": filePath, "fileId": fileId, "nonce": nonce, "signature": sigA.hex()}
    data = {
        "protocolStep": 3,
        "userId": userId,
        "message": message
    }
    msg = json.dumps(data)
    response = queue.send_message(MessageBody=msg, MessageGroupId="1",
                                  MessageDeduplicationId=dt.datetime.now().strftime('%j%H%M%S') + "_" + str(userId))

    return response is not None

#
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.mysql',
#         'NAME': 'cloud_project',
#         'USER': 'admin',
#         'PASSWORD': 'admin1234',
#         'HOST': 'cdatabase.cz74fbbtgnlq.us-east-1.rds.amazonaws.com',
#         'PORT': '3306'
#     }
# }


while True:
    connect = pymysql.connect(host='cdatabase.cz74fbbtgnlq.us-east-1.rds.amazonaws.com', user='admin', password='admin1234', database='cloud_project',
                              charset='utf8')
    cursor = connect.cursor()
    response = receive_first_msg()
    if response is not None:
        protocol_step = response['protocolStep']
        userId = response['userId']

        # send protocol_3
        # receive message = {"cmkId":cmkIdA, "nonce":nonceA, "fileId":fileId}
        # send message = {"filePath" :filePathOnS3, "fileId" :fileId, "nonce":nonceA,"signature":SigA(H(M))}
        if protocol_step == 2:
            message = response['message']
            cmkId = message['cmkId']
            nonce = message['nonce']
            fileId = message['fileId']

            cursor.execute("SELECT filePath from accounts_uploadfile WHERE id=% s", fileId)
            ret = cursor.fetchone()
            cursor.close()
            connect.close()
            local_file_path = ret[0]

            hashcode = create_file_digest(local_file_path)
            sigA = sign_by_KMS(cmkId, hashcode)
            filePath = upload_file_to_S3(local_file_path)
            send_msg_to_SQS_step_3(filePath, fileId, nonce, sigA, userId)
            print(filePath, fileId, nonce, sigA, hashcode)

        # receive protocol_7
        # {"fileId":fileId,"downloaderId":downloaderId", "NRR":SigB(SigA(H(M)))}
        elif protocol_step == 7:
            message = response['message']
            NRR = message['NRR']
            if NRR is not None:
                NRR_received = "Received"
            else:
                NRR_received = "Not Received"
            fileId = message['fileId']
            downloaderId = message['downloaderId']

            sql = 'INSERT INTO accounts_receipt(fileId_id,userId_id,nrr,nrr_originial) VALUES (%s, %s, %s, %s)'
            fileId_id = fileId
            userId_id = downloaderId
            nrr = NRR_received
            nrr_originial = NRR
            values = (fileId_id, userId_id, nrr, nrr_originial)
            try:
                cursor.execute(sql, values)
                connect.commit()
                cursor.close()
                connect.close()
                print("------------receive NRR success------------")
            except Exception as e:
                connect.rollback()
                cursor.close()
                connect.close()
                print("------------receive NRR fail------------")

        # v[NRS→A]: {"fileId":fileId, "verified":True/False}
        elif protocol_step == "v":
            message = response['message']
            v = message['verified']
            fileId = message['fileId']
            if v is True:
                cursor.execute("UPDATE accounts_uploadfile SET state = 2 WHERE id =% s", fileId)
                cursor.close()
                connect.commit()
                connect.close()
                print("------------uploads success------------")
            else:
                cursor.execute("UPDATE accounts_uploadfile SET state = 0 WHERE id =% s", fileId)
                cursor.close()
                connect.commit()
                connect.close()
                print("------------uploads fail------------")

        elif protocol_step == "a":
            userId = response["userId"]
            fileId = response["fileId"]
            abort_code = response["abort"]
            if abort_code == 1:
                print("abort code 1")
                cursor.execute("UPDATE accounts_uploadfile SET state = 3 WHERE id =% s", fileId)
                cursor.close()
                connect.commit()
                connect.close()
            elif abort_code == 2:
                # set abort，delete record
                print("abort code 2")
                cursor.execute("UPDATE accounts_uploadfile SET state = 3 WHERE id =% s", fileId)
                cursor.execute("UPDATE accounts_downloadfile SET state = 3 WHERE state != 2 AND id =% s", fileId)
                cursor.close()
                connect.commit()
                connect.close()
            elif abort_code == 3:
                print("abort code 3")
                # set abort，front page will not display record whose status = 3
                cursor.execute("UPDATE accounts_uploadfile SET state = 3 WHERE id =% s", fileId)
                cursor.close()
                connect.commit()
                connect.close()
            else:
                print("abort_code is wrong")

            print("------------Abort finished------------")
        else:
            print("protocol_step is incorrect.")
    else:
        print("msg null")
    print("polling...")
    time.sleep(5)
