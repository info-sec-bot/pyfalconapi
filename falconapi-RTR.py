import os

CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET=os.environ['CLIENT_SECRET']

from falconpy import RealTimeResponseAudit

# Do not hardcode API credentials!
falcon = RealTimeResponseAudit(client_id=CLIENT_ID,
                               client_secret=CLIENT_SECRET
                               )

response = falcon.audit_sessions(limit="5",sort="created_at|desc")
# print(response)
for key in response["body"]["resources"]:
    print(key)




