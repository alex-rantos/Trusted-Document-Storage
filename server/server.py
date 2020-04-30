#Python Class for TTP Side for a fair exchange protocol.

#Stock Cryptographic libraries
import hashlib

#AWS Libraries
import boto3
import botocore
# PROBLEM SOLVED with exceptions: botocore.exceptions.ClientError as e:

#Sys import
import sys
import os

#JSON Libraries
import json

#DB Interface
from mysql_db import MySQL_DB

#Time Libraries
import time
import datetime as dt

#NOTES:
#Server's structure is implemented as version 1, to manage Queues
#Key Management Encrypt/Decrypt to be added.
#DB manipulation to be added.
#S3 files manipulation to be added.
class Server:

    def __init__(self):   
        try:  
            #AWS SQS Client Connection
            self.sqs = boto3.resource('sqs',
                aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
                aws_secret_access_key="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",
                region_name='us-east-1')
            
            # Get the queue to Send to A or B, queue of Server as well. Remove TEST in queue names
            self.queue_for_a = self.sqs.get_queue_by_name(QueueName='Queue_for_A.fifo')
            self.queue_for_b = self.sqs.get_queue_by_name(QueueName='Queue_for_B.fifo')
            self.queue_for_TTP = self.sqs.get_queue_by_name(QueueName='Queue_for_TTP.fifo')
            #initialize DB
            self.db = MySQL_DB()
        except botocore.exceptions.ClientError as e:
            print(e.response['Error']['Message'] + " -- Reinstantiate TTP.")
            sys.exit()
            
            
    def run(self):
        #Loop for TTP Queue Polling. With for loop we can get up to 10 messages.
        #Thus process MAXIMUM: 10 messages every idle_factor seconds.
        while True:
            print('Polling.. (calling receive)')
            for message in self.queue_for_TTP.receive_messages():    
              dic = json.loads(message.body)
              deletion = False
              if dic is None:
                print('Queue Empty.')
              if dic is not None:
                if dic["protocolStep"]==1: #protocol step is String type
                  deletion = self.perform_step2(dic)
                elif dic["protocolStep"]==3:
                  deletion = self.perform_document_upload(dic)
                elif dic["protocolStep"]==4:
                  deletion = self.perform_step5(dic)
                elif dic["protocolStep"]==6:
                  deletion = self.perform_step7and8(dic)
                elif dic["protocolStep"]=='a':
                  deletion = self.perform_abort(dic)
                else: 
                  print('Did not receive appropriate protocol steps.')
              if deletion == True:
                  print('Deleting message')
                  message.delete()
            idle_factor = self.traffic() #
            time.sleep(idle_factor) #Wait X seconds depending on traffic and then receive message

          
#Step 2: Step 2 takes place after receiving step 1 from A.
#Check if userID exists in UsersTable (if A already exists, take cmkID(A), else create cmkID(A)
#generate nonce, return fileId as well (received from step 1)
    def perform_step2(self,dic):
        print('Starting step 2..')
        curr_userId = dic["userId"]
        dic2 = dic["message"]
        fileId = dic2["fileId"]
        
        cmkId = self.key_for_user(curr_userId)
        if cmkId == None or cmkId == -1:
            print("DB error")
            return False
        if cmkId != None:
            nonce = str(os.urandom(16))#.decode('latin-1') #Returns a string of n random bytes, considered secure
            print('Nonce: '+ nonce)
            step2msgdic = {
              "cmkId": cmkId,
              "nonce": nonce,
              "fileId": fileId
            }
            step2dic = {
              "protocolStep": 2,
              "userId": curr_userId,
              "message": step2msgdic  
            }
            self.db.insertInto("insertOngUp",(fileId,curr_userId,nonce))
            json_msg = json.dumps(step2dic)
            # Send message to A (using current time as MessageDeduplicationId)
            response_a = self.queue_for_a.send_message(MessageBody=json_msg, MessageGroupId="1",
                                           MessageDeduplicationId=dt.datetime.now().strftime('%j%H%M%S'))
            print("MessageId & MD5 of message Body:")
            print(response_a.get('MessageId'))
            print(response_a.get('MD5OfMessageBody'))
            print('Finished step 2..')
            return True


#Perform Document Upload takes place after receiving message from protocol step 3,
#Message Inputs are filePathOnS3, fileId, nonce, signature
#Verifications are performed
    def perform_document_upload(self,dic):
        print('Starting File Upload..')
        curr_userId = dic["userId"]
        dic2 = dic["message"]
        filePath = dic2["filePath"]
        fileId = dic2["fileId"]
        nonce = dic2["nonce"]
        signature = dic2["signature"]
        signature_byte = bytes.fromhex(signature)

        #Get ongoing upload Nonce and compare it with currently received
        OngUpNonce = self.db.getUploadNonce(fileId) #None if it does not exist on Ongoing Uploads
        #Download DOC, hash it 
        hDoc = self.download_doc_return_hash(filePath)
        #Signature Verify
        verification_bool = self.signature_verification(curr_userId,hDoc,signature_byte)
        if (hDoc == None or verification_bool == None or OngUpNonce == None):
            return False
        if (verification_bool==True and OngUpNonce==nonce):
           self.db.completeUpload(fileId,filePath,signature)
           booleanForCurrentFile = True
        else:
            booleanForCurrentFile = False
            print("Did not pass verification. Doc Discarded")

        #send protocol step v to A
        stepVmsgdic = {
          "fileId": fileId,
          "verified": booleanForCurrentFile
        }
        stepVdic = {
          "protocolStep": 'v',
          "userId": curr_userId,
          "message": stepVmsgdic  
        }
        json_msg = json.dumps(stepVdic)
        # Send message to A (using current time as MessageDeduplicationId)
        response_a = self.queue_for_a.send_message(MessageBody=json_msg, MessageGroupId="1",
                                       MessageDeduplicationId=dt.datetime.now().strftime('%j%H%M%S'))
        print("MessageId & MD5 of message Body:")
        print(response_a.get('MessageId'))
        print(response_a.get('MD5OfMessageBody'))
        print('Finished file Upload. Sent protocol v.')
        return True
            
    def perform_step5(self,dic):
        print('Starting step 5..')
        curr_userId = dic["userId"]
        dic2 = dic["message"]
        fileId = dic2["fileId"]
        
        fileExists = self.db.fileExists(fileId)
        if fileExists == True:
            cmkId = self.key_for_user(curr_userId)
            if cmkId == None:
                return False
            nonce = str(os.urandom(16)) #Returns a string of n random bytes, considered secure
            signature = self.db.getNro(fileId)
            downloadId = curr_userId + "_" + fileId
            #add to ongoing
            step5msgdic = {
            "cmkId": cmkId,
            "nonce": nonce,
            "signature": signature
            }
            step5dic = {
            "protocolStep": 5,
            "userId": curr_userId,
            "message": step5msgdic       
            }
            if (self.db.downloadExists(downloadId)):
                self.db.updateNonce(downloadId,nonce)
            else:    
                self.db.insertInto("insertOngDown",(downloadId,curr_userId,fileId,nonce))
            json_msg = json.dumps(step5dic)
            
            # Send message to B
            response_b = self.queue_for_b.send_message(MessageBody=json_msg, MessageGroupId="1",
                                            MessageDeduplicationId=dt.datetime.now().strftime('%j%H%M%S'))
            print("MessageId & MD5 of message Body:")
            print(response_b.get('MessageId'))
            print(response_b.get('MD5OfMessageBody'))
            print('Finished step 5.')
            return True
        else:
            print('File does not exist.')
            return True

    def perform_step7and8(self,dic):
        print('Starting step 7 and 8..')  
        curr_userId = dic["userId"] 
        dic2 = dic["message"]
        fileId = dic2["fileId"]
        nonce = dic2["nonce"]
        signature = dic2["signature"]
        signature_byte = bytes.fromhex(signature)#.encode(encoding='Latin-1')
        
        NRO = ""
        fileExists = self.db.fileExists(fileId)
        if fileExists == True:
            #Get ongoing upload Nonce and compare it with currently received
            OngDownNonce = self.db.getDownloadNonce(fileId,curr_userId) #None if it does not exist on ongoing downloads
            #Get NRO
            NRO = self.db.getNro(fileId)
            verification_bool = self.raw_signature_verification(curr_userId,bytes.fromhex(NRO),signature_byte)
            if (verification_bool == None or OngDownNonce == None):
                print("verification failed")
                return False
            if (verification_bool==True and OngDownNonce==nonce):
                filePath = self.db.completeDownload(curr_userId,fileId,signature)
                if (filePath == -1):
                    print("no correct filepath")
                    return False
                #send protocol step 7 to A
                step7msgdic = {
                    "fileId": fileId,
                    "downloaderId": curr_userId,
                    "NRR": signature
                }
                #msg_content1 = json.dumps(step7msgdic)
                step7dic = {
                    "protocolStep": 7,
                    "userId": None,
                    "message": step7msgdic  
                }
                json_msg_to_A = json.dumps(step7dic)
                # Send message to A (using current time as MessageDeduplicationId)
                response_a = self.queue_for_a.send_message(MessageBody=json_msg_to_A, MessageGroupId="1",
                                                MessageDeduplicationId=dt.datetime.now().strftime('%j%H%M%S'))
                print("Uploader Queue: MessageId & MD5 of message Body :")
                print(response_a.get('MessageId'))
                print(response_a.get('MD5OfMessageBody'))
                
                #send protocol step 8 to B
                step8msgdic = {
                    "NRO": NRO,
                    "filePath": filePath
                }
                #msg_content2 = json.dumps(step8msgdic)
                step8dic = {
                    "protocolStep": 8,
                    "userId": None,
                    "message": step8msgdic  
                }
                json_msg_to_B = json.dumps(step8dic)
                # Send message to A (using current time as MessageDeduplicationId)
                response_b = self.queue_for_b.send_message(MessageBody=json_msg_to_B, MessageGroupId="1",
                                                MessageDeduplicationId=dt.datetime.now().strftime('%j%H%M%S'))
                print("Downloader Queue: MessageId & MD5 of message Body :")
                print(response_b.get('MessageId'))
                print(response_b.get('MD5OfMessageBody'))
                print('Finished step 7 and 8.')
                return True
            else:
                print("Did not pass verification. NRO, NRR and Doc DL skipped.")
                return True
        else:
            print("file does not exist")
            return False

    def perform_abort(self,dic):
        print('Starting Abort..')
        curr_userId = dic["userId"]
        fileId = dic["fileId"]
        #DB performs abort and return the corresponding abort code for client
        abort = self.db.abort(fileId)
        print(abort)
        if (isinstance(abort,str)):
            self.delete_doc(abort)
            abort = 2
        stepAdic = {
            "protocolStep": 'a',
            "userId": curr_userId,
            "fileId": fileId,
            "abort": abort  
        }
        json_msg = json.dumps(stepAdic)
        
        # Send message to A (using current time as MessageDeduplicationId)
        response_a = self.queue_for_a.send_message(MessageBody=json_msg, MessageGroupId="1",
                                        MessageDeduplicationId=dt.datetime.now().strftime('%j%H%M%S'))
        print(response_a.get('MessageId'))
        print(response_a.get('MD5OfMessageBody'))
        print('Finished Abort.')
        return True
        
#Returns cmk_id. (if the user already had one, or creates a new key for the user)
#In any Amazon CLient Error it returns None.
    def key_for_user(self,userId):
        cmk_id = ""
        try:
            #KMS Client Connection
            kms_client = boto3.client('kms', 
                aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
                aws_secret_access_key="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",
                region_name='us-east-1')
        
            cmk_id = self.db.getKeyId(userId)
            
            if (cmk_id == None):
                response_ck = kms_client.create_key(
                    Description=userId,
                    KeyUsage='SIGN_VERIFY',
                    CustomerMasterKeySpec='ECC_NIST_P256', # only sign-verify. No encryption. elliptic curve cryptography
                    Origin='AWS_KMS',
                    BypassPolicyLockoutSafetyCheck=False, #default
                    Tags=[
                        {
                            'TagKey':  userId,
                            'TagValue': ''
                        },
                    ]
                )
                cmk_id = response_ck['KeyMetadata']['KeyId']
                self.db.insertInto("insertUsers",(userId,cmk_id))
                # create an alias
                kms_client.create_alias(
                    AliasName='alias/' +userId,
                    TargetKeyId=cmk_id
                )
            return cmk_id
        except botocore.exceptions.ClientError as e:
            print(e.response['Error']['Message'] + " -- No Connection with KMS.")
            return None

    def signature_verification(self,userId,message,signature):
        try:
            #Connect to KMS Client
            kms_client = boto3.client('kms', 
                aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
                aws_secret_access_key="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",
                region_name='us-east-1')
        
            cmk_id = self.db.getKeyId(userId)
            if cmk_id is not None:
                response_verify = kms_client.verify(
                        KeyId=cmk_id,
                        Message=message,
                        MessageType='DIGEST',
                        Signature=signature,
                        SigningAlgorithm='ECDSA_SHA_256',
                )
                return response_verify['SignatureValid']
            else:
                return False
        except botocore.exceptions.ClientError as e:
            print(e.response['Error']['Message'] + " -- No Connection with KMS.")
            return None
    
    def raw_signature_verification(self,userId,message,signature):
        try:
            #Connect to KMS Client
            kms_client = boto3.client('kms', 
                aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
                aws_secret_access_key="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",
                region_name='us-east-1')
        
            cmk_id = self.db.getKeyId(userId)
            if cmk_id is not None:
                response_verify = kms_client.verify(
                        KeyId=cmk_id,
                        Message=message,
                        MessageType='RAW',
                        Signature=signature,
                        SigningAlgorithm='ECDSA_SHA_256',
                )
                return response_verify['SignatureValid']
            else:
                return False
        except botocore.exceptions.ClientError as e:
            print(e.response['Error']['Message'] + " -- No Connection with KMS.")
            return None

    def create_file_digest(self,file_path):
      BUF_SIZE = 2**16
      with open(file_path, "rb") as f:
        file_hash = hashlib.sha256()
        # use buffer for faster digest calculation
        buffer = f.read(BUF_SIZE)
        while buffer:
            file_hash.update(buffer)
            buffer = f.read(BUF_SIZE)
      return file_hash.digest()

#This method is a placeholder for future extension.
#Purpose of this method is to return a number, based on how many clients are connected and want to upload or download files.
#This way we set the polling rate based on traffic. At this moment its a stable number, as our project message demand is low.
#The lower the number, the more polling requests, *read sleep method documentation*
    def traffic(self):
        return 5
    
    def download_doc_return_hash(self,filePath):
        try:
            s3 = boto3.resource('s3',
                aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
                aws_secret_access_key="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",
                region_name='us-east-1')
            filename = os.path.basename(filePath) # if its not working use Marshall's technique (split with / and take last part (-1))
            s3.Bucket('csc8113t3').download_file(filePath,filename) ##TESTING
            hDoc = self.create_file_digest(filename)
            if os.path.exists(filename):
                os.remove(filename)
            return hDoc
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "404":
                print("The object does not exist.")
            else:
                print(e.response['Error']['Message'] + " -- No Connection with S3.")
            return None
    
    def delete_doc(self,filePath):
        try:
            s3 = boto3.resource('s3',
                aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
                aws_secret_access_key="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",
                region_name='us-east-1')
            filename = os.path.basename(filePath)
            s3.Object(Bucket = 'csc8113t3', Key=filePath).delete()
        except botocore.exceptions.ClientError as e:
            print(e.response['Error']['Message'] + " -- No Connection with S3.")
            return None
        
    def purge(self):
        print('PURGING..')
        self.sqs.purge_queue(QueueUrl='https://sqs.us-east-1.amazonaws.com/120671915497/Queue_for_TTP.fifo')
        
# Instantiate the Server
if __name__ == "__main__":
    server = Server()
    server.run()
