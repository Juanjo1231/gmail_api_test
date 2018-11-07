from __future__ import print_function
from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools
import json
import base64

# If modifying these scopes, delete the file token.json.
SCOPES = 'https://www.googleapis.com/auth/gmail.modify'

def getMessageBodies(service, user_id, message_ids = [], valid_subjects = [], moveToTrash = True):
    """Get messages raw content decoded.
    
    Args:
        service:        Authorized Gmail API service instance.
        user_id:        User's email address. The special value 'me' can be used for authenticated user.
        message_id:     List of message ids.
        valid_subjects: List of subjects. The function will only return the body of the messages that
                        matches one of the strings on this list. If the list is not provided, the body of 
                        all messages is returned.

    Returns:
        List containing the [subject, decoded body raw content] of each message in message_id list that is on valid_subjects list
        or all if valid_subjects is not provided.
    """
    res = []

    if len(message_ids) == 0:
        return res

    for msg_id in message_ids:
        message = service.users().messages().get(id=msg_id, userId=user_id, format='metadata', metadataHeaders=['subject']).execute()
        subject = message['payload']['headers'][0]['value'].lower()

        if subject in valid_subjects or len(valid_subjects) == 0:
            raw_body = service.users().messages().get(id=msg_id, userId=user_id, format='raw').execute()

            if moveToTrash:
                # Move the message to the trash and mark it as read.
                msg_labels = {'removeLabelIds': ['UNREAD', 'INBOX'], 'addLabelIds': ['TRASH']}
                trashedMsg = service.users().messages().modify(id=msg_id, userId=user_id, body=msg_labels).execute()

            content = base64.urlsafe_b64decode(raw_body['raw'].encode('utf-8'))
            res.append([subject, res])
            

    

def getMessageIds(service, user_id):
    """Get messages id.
    
    Args:
        service: Authorized Gmail API service instance.
        user_id: User's email address. The special value 'me' can be used for authenticated user.

    Returns:
        List of message ids.
    """
    res = []
    # Search only unread threads in inbox, ignore chats and look for 3 specific subjects.
    query = 'in:inbox -in:chats label:unread subject:"Gua CSAT" | "Tpa CSAT" | "GCSAT"'
    result = service.users().messages().list(userId=user_id, q=query).execute()
    messages = result.get('messages', [])

    for msg in messages:
        res.append(msg['id'])

    return res

def main():
    store = file.Storage('token.json')
    creds = store.get()

    if not creds or creds.invalid:
        flow = client.flow_from_clientsecrets('credentials.json', SCOPES)
        creds = tools.run_flow(flow, store)

    service = build('gmail', 'v1', http=creds.authorize(Http()))
    message_ids = getMessageIds(service, 'me')
    message_bodies = getMessageBodies(service, 'me', message_ids, ['gcsat'])


if __name__ == '__main__':
    main()
