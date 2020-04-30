import sys
import os
import mysql
import mysql.connector 
#AWS Libraries
import boto3
import botocore

INSERT_DIC = {
    "insertUsers"    : "INSERT INTO users(userId,cmkId)                          VALUES(%s,%s)",
    "insertOngUp"    : "INSERT INTO ongoingUploads(fileId, uploaderId, nonce)    VALUES(%s,%s,%s)",
    "insertCompUp"   : "INSERT INTO completedUploads(fileId, uploaderId, filepath, nro, abort) VALUES(%s,%s,%s,%s,%s)",
    "insertOngDown"  : "INSERT INTO ongoingDownloads(downloadId, downloaderId, fileId, nonce) VALUES(%s,%s,%s,%s)",
    "insertCompDown" : "INSERT INTO completedDownloads(downloadId, downloaderId, fileId, nrr) VALUES(%s,%s,%s,%s)"
}

class MySQL_DB(object):

    def __init__(self):
        self.conn = mysql.connector.connect(host="mysqldatabase.cz74fbbtgnlq.us-east-1.rds.amazonaws.com", port="3306",database="mysqldata", user="admin", password="admin1234")
        self.cur = self.conn.cursor()

    def __create_tables__(self):
        tables = (
            """
            CREATE TABLE users (
                userId INTEGER PRIMARY KEY,
                cmkId VARCHAR(255) NOT NULL
            )
            """,
            """ 
            CREATE TABLE ongoingUploads (
                fileId INTEGER PRIMARY KEY,
                uploaderId INTEGER NOT NULL,
                nonce VARCHAR(255) NOT NULL,
                    FOREIGN KEY(uploaderId)
                        REFERENCES users(userId)
            )
            """,
            """ 
            CREATE TABLE completedUploads (
                fileId INTEGER PRIMARY KEY,
                uploaderId INTEGER NOT NULL,
                filepath VARCHAR(255) NOT NULL,
                nro VARCHAR(255) NOT NULL,
                abort INTEGER NOT NULL,
                    FOREIGN KEY(uploaderId)
                        REFERENCES users(userId)
                        ON UPDATE CASCADE ON DELETE CASCADE
            )
            """,
            """ 
            CREATE TABLE ongoingDownloads (
                downloadId   VARCHAR(255) PRIMARY KEY,
                downloaderId INTEGER NOT NULL,
                fileId       INTEGER NOT NULL,
                nonce        VARCHAR(255) NOT NULL,
                    FOREIGN KEY(downloaderId)
                        REFERENCES users(userId)
            )
            """,
            """ 
            CREATE TABLE completedDownloads (
                downloadId   VARCHAR(255) PRIMARY KEY,
                downloaderId INTEGER NOT NULL,
                fileId       INTEGER NOT NULL,
                nrr          VARCHAR(255) NOT NULL,
                    FOREIGN KEY(downloaderId)
                        REFERENCES users(userId)
                        ON UPDATE CASCADE ON DELETE CASCADE,
                    FOREIGN KEY(fileId)
                        REFERENCES completedUploads(fileId)
                        ON UPDATE CASCADE ON DELETE CASCADE
            )
            """)
        for table in tables:
            self.cur.execute(table)

        # commit the changes
        self.conn.commit()

    def __reset__(self):
        self.cur.execute("SET FOREIGN_KEY_CHECKS = 0;")
        self.cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = %s", ("mysqldata",))
        rows = self.cur.fetchall()
        print(rows)
        for row in rows:
            print("drop table " + row[0])
            self.cur.execute("DROP TABLE " + row[0] + " cascade")   
        self.cur.execute("SET FOREIGN_KEY_CHECKS = 1;")
        self.conn.commit()

    def insertInto(self, query, params):
        try:
            response = self.cur.execute(INSERT_DIC[query], params)
            self.conn.commit()
            return response
        except mysql.connector.Error as error:
            print(error)
            return -1

    def getKeyId(self, userId):
        try:
            self.cur.execute("SELECT users.cmkId FROM users WHERE userId = %s",(userId,))
            record = self.cur.fetchall() 
            if (len(record) == 1):
                return record[0][0] # record = [('nro',)]
            return None
        except mysql.connector.Error as error:
            print(error)
            return -1
        return None

    def getNro(self, fileId):
        try:
            self.cur.execute("SELECT completedUploads.nro FROM completedUploads WHERE fileId = %s",(fileId,))
            record = self.cur.fetchall() 
            if (len(record) == 1):
                return record[0][0] # record = [('nro',)]
            return None
        except mysql.connector.Error as error:
            print(error)
            return -1

    def getUploadNonce(self, fileId):
        try:
            self.cur.execute("SELECT ongoingUploads.nonce FROM ongoingUploads WHERE fileId = %s",(fileId,))
            record = self.cur.fetchall() 
            if (len(record) == 1):
                return record[0][0]
            return None
        except mysql.connector.Error as error:
            print(error)
            return -1

    def getDownloadNonce(self, fileId, downloaderId):
        try:
            downloadId = str(downloaderId) + "_" + str(fileId)
            self.cur.execute("SELECT ongoingDownloads.nonce FROM ongoingDownloads WHERE downloadId = %s",(downloadId,))
            record = self.cur.fetchall() 
            if (len(record) == 1):
                return record[0][0]
            return None
        except mysql.connector.Error as error:
            print(error)
            return -1

    def query(self, query, params):
        response = self.cur.execute(query, params)
        self.conn.commit()
        return response

    def fileExists(self,fileId):
        try:
            self.cur.execute("SELECT * FROM completedUploads WHERE fileId = %s",(fileId,))
            if (self.cur.fetchall()):
                return True
            else:
                return False
        except mysql.connector.Error as error:
            print(error)
            return -1

    def downloadExists(self,downloadId):
        try:
            self.cur.execute("SELECT * FROM ongoingDownloads WHERE downloadId = %s",(downloadId,))
            if (self.cur.fetchall()):
                return True
            else:
                return False
        except mysql.connector.Error as error:
            print(error)
            return -1

    def updateNonce(self,downloadId,nonce):
        try:
            self.cur.execute("UPDATE ongoingDownloads SET nonce=%s WHERE downloadId = %s",(nonce,downloadId,))
            if (self.cur.fetchall()):
                return True
            else:
                return False
        except mysql.connector.Error as error:
            print(error)
            return -1

    def isFileDownloaded(self,fileId):
        try:
            self.cur.execute("SELECT * FROM completedDownloads WHERE fileId = %s",(fileId,))
            if (self.cur.fetchall()):
                return True
            else:
                return False
        except mysql.connector.Error as error:
            print(error)
            return -1

    def completeUpload(self,fileId,filepath,nro):
        # deletes from ongoingUploads and add row to completeUploads
        try:
            self.cur.execute("SELECT u.uploaderId FROM ongoingUploads as u WHERE fileId = %s",(fileId,))
            record = self.cur.fetchall() 
            if (len(record) == 0):
                return
            self.cur.execute(INSERT_DIC["insertCompUp"], (fileId,record[0][0],filepath,nro,0))
            self.cur.execute("DELETE FROM ongoingUploads as u WHERE fileId = %s",(fileId,))
            self.conn.commit()
        except mysql.connector.Error as error:
            print(error)
            return -1

    def completeDownload(self,downloaderId,fileId,nrr):
        """
        Deletes from ongoingDownloads and add row to completeDownloads.
        Returns the filepath
        """
        try:
            downloadId = str(downloaderId) + "_" + str(fileId)
            self.cur.execute(INSERT_DIC["insertCompDown"], (downloadId,downloaderId,fileId,nrr))
            self.cur.execute("DELETE FROM ongoingDownloads as u WHERE downloadId = %s",(downloadId,))
            self.conn.commit()

            # return filepath
            self.cur.execute("SELECT u.filepath FROM completedUploads as u WHERE fileId = %s",(fileId,))
            record = self.cur.fetchall()
            return record[0][0]
        except mysql.connector.Error as error:
            print(error)
            return -1

    def abort(self,fileId):
        """
        Abort current & future exchanges for a specific file with fileId.
        1) Check if file has been successfully uploaded:
            i) If yes then checks if fileId has been downloaded: 
                a) If yes, delete file from ongoingDownloads, flag abort=1 on completedUploads
                 and return 3
                b) If not, delete file from ongoingDownloads and completedUploads and return filepath so
                server can delete file from S3.
            ii) If not, delete file from ongoingUploads and return 1
        """
        try:
            if (self.fileExists(fileId)):
                self.cur.execute("DELETE FROM ongoingDownloads as u WHERE fileId = %s",(fileId,))
                if (self.isFileDownloaded(fileId)):
                    self.cur.execute("UPDATE completedUploads SET abort=1 WHERE fileId = %s",(fileId,))
                    self.conn.commit()
                    return 3
                else:
                    # return filepath
                    self.cur.execute("SELECT u.filepath FROM completedUploads as u WHERE fileId = %s",(fileId,))
                    record = self.cur.fetchall() 

                    self.cur.execute("DELETE FROM completedUploads as u WHERE fileId = %s",(fileId,))
                    self.conn.commit()
                    return record[0][0]

            else:
                resp = self.cur.execute("DELETE FROM ongoingUploads as u WHERE fileId = %s",(fileId,))
                self.conn.commit()
                return 1
        except mysql.connector.Error as error:
            print(error)
            return -1

    def __del__(self):
        self.cur.close()
        self.conn.close()
        pass


def raw_signature_verification(userId,cmk_id,message,signature):
    try:
        #Connect to KMS Client
        kms_client = boto3.client('kms', 
            aws_access_key_id="AKIARYGE3JXUSJN4DHMF",
            aws_secret_access_key="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",
            region_name='us-east-1')
    
        response_verify = kms_client.verify(
                KeyId=cmk_id,
                Message=message,
                Signature=signature,
                SigningAlgorithm='ECDSA_SHA_256',
        )
        return response_verify['SignatureValid']
    except botocore.exceptions.ClientError as e:
        print(e.response['Error']['Message'] + " -- No Connection with KMS.")
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

import hashlib
def create_file_digest(file_path):
    BUF_SIZE = 2**16
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256()
        # use buffer for faster digest calculation
        buffer = f.read(BUF_SIZE)
        while buffer:
            file_hash.update(buffer)
            buffer = f.read(BUF_SIZE)
    return file_hash.digest()
import json
def send_msg_to_SQS_step_3(filePath, fileId, nonce, sigA, userId):
    sigA = sigA.decode('ascii')
    message =  sigA
    message = json.dumps(message)
    return message

if __name__ == "__main__":
    db = MySQL_DB()

    if (len(sys.argv) > 1):
        if (sys.argv[1] == "reset"):
            db.__reset__()
            db.__create_tables__()
            exit()
        if (sys.argv[1] == "create"):
            db.__create_tables__()
            exit()
        elif (sys.argv[1] == "test1"):
            for x in range(70,80):
                db.completeUpload(x+30,"filepath"+str(os.urandom(10)),str(os.urandom(16)))
                db.completeDownload(x,x+30,str(os.urandom(16)))
            exit()
        elif (sys.argv[1] == "upload"):
            for x in range(70,80):
                db.completeUpload(x+30,"filepath"+str(os.urandom(10)),str(os.urandom(16)))
            exit()
        elif (sys.argv[1] == "test2"):
            fileid = 105
            user = 70
            db.insertInto("insertOngDown",(str(user)+"_"+str(fileid),user,fileid,nonce))
            nocenb  = db.getDownloadNonce(fileid,user)
            print(nonce)
            print("DB below")
            print(nocenb)
            print(str(nonce)==nocenb)
            exit()
        elif(sys.argv[1] == "sign"):
            cwd = os.getcwd()
            hash = create_file_digest("AwsSQS.py")
            cmkA = "a223456b-6a1e-47f3-be75-7cef9bb149d8"
            sigA = sign_by_KMS(cmkA,hash)
            sigA = (str(sigA))
            db.insertInto("insertCompUp",(1999,6,"da",sigA,0))
            sigA2 = db.getNro(1999)

            cmkB = "0078b4c7-ee3c-44d2-a30e-6d07efba986a"
            sigB = sign_by_KMS(cmkB,sigA2)

            print(sigB)
            sigB = sigB.hex()
            message = {"signature": sigB}
            message = json.dumps(message)
            sigB = json.loads(message)
            sigB = sigB["signature"]
            print(sigB)
            sigB = bytes.fromhex(sigB)
            print(sigB)
            valid = raw_signature_verification(2,cmkB,sigA2,sigB)
            print(valid)
            exit()
        elif(sys.argv[1] == "ver"):
            nonce = str(os.urandom(24))
        elif (sys.argv[1] == "file"):
            print(db.fileExists(100))
            exit()
        elif (sys.argv[1] == "abort"):
            print(db.getKeyId(442))
            exit()
        else:
            print("wrong argument")
            exit()


    for x in range(70,80):
        db.insertInto("insertUsers",(x,"4161616161",)) #uploader
        db.insertInto("insertUsers",(x+10,"4161611551",)) #downloaders
        db.insertInto("insertOngUp",(x+30,x,"nonceAAAD",))
        #db.insertInto("insertOngDown",(str(x)+"_"+str(x+30),x,x+30,"noncebbb",))
        #print(db.getKeyId(x))

    #del db # however it is done automatically when object is out of scope.
