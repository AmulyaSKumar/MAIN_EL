import os.path
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import base64
from email.utils import parseaddr

# Scopes for Gmail API
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    """Authenticate and return a Gmail service object."""
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES
            )
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

def extract_message_content(payload):
    """Extract plain text or HTML message content from the email payload."""
    if 'body' in payload and 'data' in payload['body']:
        data = payload['body']['data']
        return base64.urlsafe_b64decode(data).decode('utf-8')

    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain' and 'data' in part['body']:
                data = part['body']['data']
                return base64.urlsafe_b64decode(data).decode('utf-8')
            elif part['mimeType'] == 'text/html' and 'data' in part['body']:
                data = part['body']['data']
                return base64.urlsafe_b64decode(data).decode('utf-8')

    return "No message content found."

def get_emails(service, query=''):
    """Fetch emails from the user's Gmail inbox and display them in the required format."""
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])

    if not messages:
        print("No emails found.")
        return

    for msg in messages:
        message = service.users().messages().get(userId='me', id=msg['id']).execute()
        payload = message['payload']
        headers = payload.get('headers', [])
        
        # Initialize variables
        sender_email = ''
        sender_name = ''
        receiver_email = ''
        subject = ''
        message_content = ''

        # Extract required header fields
        for header in headers:
            if header['name'] == 'From':
                sender = header['value']
                sender_name, sender_email = parseaddr(sender)
            elif header['name'] == 'To':
                receiver_email = header['value']
            elif header['name'] == 'Subject':
                subject = header['value']

        # Extract the message content
        message_content = extract_message_content(payload)

        # Print in the required format
        print(f"Sender Name: {sender_name}")
        print(f"Sender Email: {sender_email}")
        print(f"Receiver Email: {receiver_email}")
        print(f"Channel: Mail")
        print(f"Subject: {subject}")
        print(f"Message Content: {message_content}")
        print('-' * 50)

if __name__ == '__main__':
    # Authenticate with Gmail API
    service = authenticate_gmail()
    # Fetch and display emails
    print("Fetching emails...")
    get_emails(service, query='')  # Add a query if you want to filter emails
