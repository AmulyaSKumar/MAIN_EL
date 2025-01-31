import os.path
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import base64
from email.message import EmailMessage

# Scopes for Gmail API
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    """Authenticate and return a Gmail service object."""
    creds = None
    # Token file to store user credentials
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no valid credentials, authenticate via OAuth2
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES
            )
            creds = flow.run_local_server(port=0)
        # Save the credentials for future use
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

def get_emails(service, query=''):
    """Fetch emails from the user's Gmail inbox."""
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    for msg in messages:
        message = service.users().messages().get(userId='me', id=msg['id']).execute()
        payload = message['payload']
        headers = payload.get('headers', [])
        subject = None
        for header in headers:
            if header['name'] == 'Subject':
                subject = header['value']
        print(f"Subject: {subject}")
        if 'parts' in payload['body']:
            for part in payload['body']['parts']:
                data = part.get('body', {}).get('data')
                if data:
                    print(base64.urlsafe_b64decode(data).decode('utf-8'))

if __name__ == '__main__':
    # Authenticate with Gmail API
    service = authenticate_gmail()
    # Fetch and display emails
    print("Fetching emails...")
    get_emails(service, query='')  # Add a query if you want to filter emails
