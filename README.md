# A fair File-sharing platform

This is a group project that was further refined and debugged by myself. In short, a cloud Trusted Document Storage was developed that was based on the Coffey and Saidha protocol 'NON-REPUDIATION WITH MANDATORY PROOF OF RECEIPT'; an inline non-repudiation protocol. Also, there are many web services that were used from Amazon which now they are inactive to avoid expenses. Detailed project explanation can be found @ Report.pdf.

## Amazon Web Services

A brief description for the selected AWS that were used:

1. Simple Queue Service (SQS): for communication purposes between entities.
2. Relation Database service (RDS): for persistent data storage.
3. Key Management Service (KMS): for signing and verifying documents.
4. Simple Storage Service (S3): for documents storage.
5. Elastic Compute Cloud  (EC2): for an online website.

### Lessons learnt

1. Postgres is not suitable for storing cryptographic hash values since it does not allow saving null bytes. For this reason, mySQL was used to avoid values conversion.
2. Serializing bytearrays was a task itself since many different conversions were resulting into invalid verification while sending converted bytearrays via JSON. Converting to hex values and back was the solution.
