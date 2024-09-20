# from flask import Flask, redirect, url_for, session, request
# import google.auth.transport.requests
# import google.oauth2.credentials
# import google_auth_oauthlib.flow
# import googleapiclient.discovery
# import os
# import base64
# from dotenv import load_dotenv

# # Set up Flask application
# app = Flask(__name__)

# # Load environment variables from .env file
# load_dotenv()
# app.secret_key = os.getenv('SECRET_KEY')
# GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
# GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')


# # OAuth 2.0 Scopes
# SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']

# # Dark theme CSS with white text and responsive design
# dark_theme_css = '''
#     <style>
#         body {
#             # background-color: black; !important
#             # color: #E0E0E0;
#             font-family: Arial, sans-serif;
#             margin: 0;
#             padding: 0;
#             display: flex;
#             justify-content: center;
#             align-items: center;
#             min-height: 100vh;
#             text-align: center;  /* Ensures all text is center aligned */
#         }
#         .container {
#             width: 50%;
#             margin: 20px auto;
#             padding: 80px 80px 80px 80px;
#             background-color: #1E1E1E;
#             border-radius: 8px;
#             box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
#             overflow: auto;
#             display: flex;
#             flex-direction: column;
#             align-items: center;  /* Centers content inside the container */
#             justify-content: center;
#         }
#         h1, h2 {
#             color: #E0E0E0;
#             font-weight: bold;
#             text-align: center;
#         }
#         a {
#             color: #BB86FC;
#             text-decoration: none;
#             margin-top: 20px;
#         }
#         a:hover {
#             text-decoration: underline;
#         }
#         .message {
#             padding: 30px;
#             margin: 20px 0;
#             border: 1px solid #333;
#             border-radius: 8px;
#             background-color: #2C2C2C;
#             width: 80%;  /* Restricts message width */
#             text-align: left;  /* Message text aligned left for readability */
#             word-wrap: break-word; /* Ensures long words break and wrap */
#             overflow-wrap: break-word; /* Modern alternative for word-wrap */
#             word-break: break-word; /* Ensures text always breaks when too long */
#         }
#         .message .header {
#             font-weight: bold;
#             color: #03DAC5;
#             font-size: 1.2em;
#         }
#         .message p {
#             color: #E0E0E0;
#             line-height: 1.5;
#         }
#         .footer {
#             text-align: center;
#             margin-top: 20px;
#             color: #666;
#         }
#         .wh{
#             color:white;
#         }
#         @media (max-width: 600px) {
#             .container {
#                 width: 95%;
#                 padding: 10px;
#             }
#             .message {
#                 width: 100%;
#             }
#         }
#     </style>
# '''
# @app.route('/')
# def index():
#     return f'''
#         {dark_theme_css}
#         <div class="container">
#             <h1>Welcome!</h1>
#             <p><a href="/login">Login with Google</a></p>
#             <div class="footer">OAuth 2.0 Integration</div>
#         </div>
#     '''

# @app.route('/login')
# def login():
#     # Start the OAuth 2.0 flow
#     flow = google_auth_oauthlib.flow.Flow.from_client_config(
#         {
#             "installed": {
#                 "client_id": os.getenv('CLIENT_ID'),
#                 "project_id": os.getenv('PROJECT_ID'),
#                 "auth_uri": os.getenv('AUTH_URI'),
#                 "token_uri": os.getenv('TOKEN_URI'),
#                 "auth_provider_x509_cert_url": os.getenv('AUTH_PROVIDER_X509_CERT_URL'),
#                 "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
#                 "redirect_uris": os.getenv('REDIRECT_URIS')
#             }
#         },
#         scopes=SCOPES
#     )
    
#     # Redirect URI (must match the one in Google Cloud Console)
#     flow.redirect_uri = url_for('callback', _external=True)

#     authorization_url, state = flow.authorization_url(
#         access_type='offline',
#         include_granted_scopes='true')
    
#     # Store the state in the session to verify it later
#     session['state'] = state

#     return redirect(authorization_url)

# @app.route('/callback')
# def callback():
#     # Verify the state to prevent CSRF attacks
#     state = session['state']

#     flow = google_auth_oauthlib.flow.Flow.from_client_config(
#         {
#             "installed": {
#                 "client_id": os.getenv('CLIENT_ID'),
#                 "project_id": os.getenv('PROJECT_ID'),
#                 "auth_uri": os.getenv('AUTH_URI'),
#                 "token_uri": os.getenv('TOKEN_URI'),
#                 "auth_provider_x509_cert_url": os.getenv('AUTH_PROVIDER_X509_CERT_URL'),
#                 "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
#                 "redirect_uris": os.getenv('REDIRECT_URIS')
#             }
#         },
#         scopes=SCOPES
#     )
#     flow.redirect_uri = url_for('callback', _external=True)

#     # Exchange the authorization code for credentials
#     authorization_response = request.url
#     flow.fetch_token(authorization_response=authorization_response)

#     # Save the credentials in session
#     credentials = flow.credentials
#     session['credentials'] = {
#         'token': credentials.token,
#         'refresh_token': credentials.refresh_token,
#         'token_uri': credentials.token_uri,
#         'client_id': credentials.client_id,
#         'client_secret': credentials.client_secret,
#         'scopes': credentials.scopes
#     }

#     return redirect(url_for('gmail'))

# @app.route('/gmail')
# def gmail():
#     # Check if the user is authenticated
#     if 'credentials' not in session:
#         return redirect('login')

#     # Load credentials from the session
#     credentials = google.oauth2.credentials.Credentials(
#         **session['credentials'])

#     # Build the Gmail API service
#     gmail_service = googleapiclient.discovery.build(
#         'gmail', 'v1', credentials=credentials)

#     # Fetch the user's Gmail messages
#     results = gmail_service.users().messages().list(userId='me').execute()
#     messages = results.get('messages', [])

#     output = [f'{dark_theme_css}<div class="container"><h2>Your Gmail Messages</h2>']
#     if not messages:
#         output.append('<p>No messages found.</p>')
#     else:
#         for message in messages[:50]:  # Fetch only the first 50 messages
#             msg = gmail_service.users().messages().get(userId='me', id=message['id'], format='full').execute()
#             headers = msg['payload']['headers']
            
#             # Initialize variables for sender, receiver, subject, and body
#             sender = receiver = subject = body = ''
            
#             # Extract headers
#             for header in headers:
#                 if header['name'] == 'From':
#                     sender = header['value']
#                 if header['name'] == 'To':
#                     receiver = header['value']
#                 if header['name'] == 'Subject':
#                     subject = header['value']
            
#             # Extract body (consider both plain text and HTML)
#             body_data = ''
#             if 'parts' in msg['payload']:
#                 for part in msg['payload']['parts']:
#                     if part['mimeType'] == 'text/plain':
#                         body_data += part['body']['data']
#                     elif part['mimeType'] == 'text/html' and not body_data:
#                         body_data += part['body']['data']
#             else:
#                 body_data = msg['payload']['body']['data']

#             # Decode body if it's Base64 encoded
#             body = base64.urlsafe_b64decode(body_data).decode('utf-8')

#             # Check for the keywords in the body
#             if 'internships' in body.lower() or 'jobs' in body.lower():
#                 # Append extracted details in the required format
#                 output.append(f'''
#                     <div class="message">
#                         <div class="header">Sender:</div> <div class="wh">{sender}</div><br>
#                         <div class="header">Receiver:</div><div class="wh">{receiver}<div><br>
#                         <div class="header">Subject:</div> <div class="wh">{subject}<div><br>
#                         <div class="header">Body:</div> 
#                         <p>{body}</p>
#                     </div>
#                 ''')

#     output.append('</div><div class="footer">End of Messages</div>')
#     return ''.join(output)

# @app.route('/logout')
# def logout():
#     # Clear the session
#     session.clear()
#     return redirect('/')

# if __name__ == '__main__':
#     # Ensure the OAuth callback URI is set correctly
#     os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # For development only, allows HTTP
    
#     app.run(os.getenv('HOST'), os.getenv('PORT'), debug=True)

from flask import Flask, redirect, url_for, session, request
import google.auth.transport.requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import os
import base64
from dotenv import load_dotenv

# Set up Flask application
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)

# Load environment variables from .env file
load_dotenv()
app.secret_key = os.getenv('SECRET_KEY')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')


# OAuth 2.0 Scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']

# Dark theme CSS with white text and responsive design
dark_theme_css = '''
    <style>
        body {
            background-color: black; !important
            color: #E0E0E0;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            text-align: center;  /* Ensures all text is center aligned */
        }
        .container {
            width: 50%;
            margin: 20px auto;
            padding: 80px 80px 80px 80px;
            background-color: #1E1E1E;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
            overflow: auto;
            display: flex;
            flex-direction: column;
            align-items: center;  /* Centers content inside the container */
            justify-content: center;
        }
        h1, h2 {
            color: #E0E0E0;
            font-weight: bold;
            text-align: center;
        }
        a {
            color: #BB86FC;
            text-decoration: none;
            margin-top: 20px;
        }
        a:hover {
            text-decoration: underline;
        }
        .message {
            padding: 30px;
            margin: 20px 0;
            border: 1px solid #333;
            border-radius: 8px;
            background-color: #2C2C2C;
            width: 80%;  /* Restricts message width */
            text-align: left;  /* Message text aligned left for readability */
            word-wrap: break-word; /* Ensures long words break and wrap */
            overflow-wrap: break-word; /* Modern alternative for word-wrap */
            word-break: break-word; /* Ensures text always breaks when too long */
        }
        .message .header {
            font-weight: bold;
            color: #03DAC5;
            font-size: 1.2em;
        }
        .message p {
            color: #E0E0E0;
            line-height: 1.5;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            color: #666;
        }
        .attachment {
            border: 1px solid #666;
            padding: 10px;
            margin: 10px 0;
            background-color: #333;
            color: #03DAC5;
            font-weight: bold;
            border-radius: 5px;
        }
        .wh {
            color: white;
        }
        @media (max-width: 600px) {
            .container {
                width: 95%;
                padding: 10px;
            }
            .message {
                width: 100%;
            }
        }
    </style>
'''

@app.route('/')
def index():
    return f'''
        {dark_theme_css}
        <div class="container">
            <h1>Welcome!</h1>
            <p><a href="/login">Login with Google</a></p>
            <div class="footer">OAuth 2.0 Integration</div>
        </div>
    '''

@app.route('/login')
def login():
    # Start the OAuth 2.0 flow
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        {
            "installed": {
                "client_id": os.getenv('CLIENT_ID'),
                "project_id": os.getenv('PROJECT_ID'),
                "auth_uri": os.getenv('AUTH_URI'),
                "token_uri": os.getenv('TOKEN_URI'),
                "auth_provider_x509_cert_url": os.getenv('AUTH_PROVIDER_X509_CERT_URL'),
                "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
                "redirect_uris": [os.getenv('REDIRECT_URIS')]
            }
        },
        scopes=SCOPES
    )
    
    # Redirect URI (must match the one in Google Cloud Console)
    flow.redirect_uri = url_for('callback', _external=True)
    # flow.redirect_uri='https://emailextractor.onrender.com/callback'
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')
    
    # Store the state in the session to verify it later
    session['state'] = state

    return redirect(authorization_url)

@app.route('/callback')
def callback():
    # Verify the state to prevent CSRF attacks
    state = session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        {
            "installed": {
                "client_id": os.getenv('CLIENT_ID'),
                "project_id": os.getenv('PROJECT_ID'),
                "auth_uri": os.getenv('AUTH_URI'),
                "token_uri": os.getenv('TOKEN_URI'),
                "auth_provider_x509_cert_url": os.getenv('AUTH_PROVIDER_X509_CERT_URL'),
                "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
                "redirect_uris": [os.getenv('REDIRECT_URIS')]
            }
        },
        scopes=SCOPES
    )
    flow.redirect_uri = url_for('callback', _external=True)
    # flow.redirect_uri='https://emailextractor.onrender.com/callback'
    print(flow.redirect_uri)
    # Exchange the authorization code for credentials
    authorization_response = request.url
    print('fetching token')
    flow.fetch_token(authorization_response=authorization_response)
    print("token fetched")
    # Save the credentials in session
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    return redirect(url_for('gmail'))
def get_body_from_message(message):
    """
    Extracts the body from the given Gmail message.
    Tries to handle both plain text and HTML parts.
    """
    if 'parts' in message['payload']:
        for part in message['payload']['parts']:
            # Check if the part has a body and is text
            if part['mimeType'] == 'text/plain' and 'data' in part['body']:
                return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
            elif part['mimeType'] == 'text/html' and 'data' in part['body']:
                # In case there's no plain text, use HTML as fallback
                return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
            elif 'parts' in part:
                # Recursively handle nested parts
                return get_body_from_message({'payload': part})
    else:
        # Directly decode if the message is not multipart
        return base64.urlsafe_b64decode(message['payload']['body']['data']).decode('utf-8')

    return None  # If no body is found
@app.route('/gmail')
def gmail():
    # Check if the user is authenticated
    if 'credentials' not in session:
        return redirect('login')

    # Load credentials from the session
    credentials = google.oauth2.credentials.Credentials(
        **session['credentials'])

    # Build the Gmail API service
    gmail_service = googleapiclient.discovery.build(
        'gmail', 'v1', credentials=credentials)

    # Fetch the user's Gmail messages
    results = gmail_service.users().messages().list(userId='me').execute()
    messages = results.get('messages', [])

    output = []
    if not messages:
        output.append('<p>No messages found.</p>')
    else:
        for message in messages[:1]:  # Fetch only the first 5 messages
            msg = gmail_service.users().messages().get(userId='me', id=message['id'], format='full').execute()
            headers = msg['payload']['headers']
            
            # Initialize variables for sender, receiver, subject, and body
            sender = receiver = subject = body = ''
            has_attachment = False  # Flag to check if there are attachments
            
            # Extract headers
            for header in headers:
                if header['name'] == 'From':
                    sender = header['value']
                if header['name'] == 'To':
                    receiver = header['value']
                if header['name'] == 'Subject':
                    subject = header['value']
            # print(msg)
            body_data = ''
            if 'parts' in msg['payload']:
                for part in msg['payload']['parts']:
                    if part['mimeType'] == 'text/plain':
                        body_data += part['body']['data']
                    elif part['mimeType'] == 'text/html' and not body_data:
                        body_data += part['body']['data']
            else:
                body_data = msg['payload']['body']['data']

            # Decode body if it's Base64 encoded
            if body_data:
                body = base64.urlsafe_b64decode(body_data).decode('utf-8')

            # Check for attachments and download them
            if 'parts' in msg['payload']:
                for part in msg['payload']['parts']:
                    if part['filename']:  # If filename exists, it's an attachment
                        has_attachment = True
                        attachment_id = part['body']['attachmentId']
                        attachment = gmail_service.users().messages().attachments().get(
                            userId='me', messageId=message['id'], id=attachment_id).execute()
                        
                        data = base64.urlsafe_b64decode(attachment['data'])
                        
                        # Define the path to save the attachment (desktop folder)
                        desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop', 'gmail_attachments')
                        if not os.path.exists(desktop_path):
                            os.makedirs(desktop_path)
                        
                        file_path = os.path.join(desktop_path, part['filename'])
                        with open(file_path, 'wb') as f:
                            f.write(data)

            # Filter emails that contain "Purchase Orders" in the subject or body
            if "Purchase Orders" in subject or "Purchase Orders" in body:
                # Append extracted details in the required format
                output.append(f'''
                    <div class="message">
                        <div class="header">Sender:</div> <div class="wh">{sender}</div><br>
                        <div class="header">Receiver:</div> <div class="wh">{receiver}<div><br>
                        <div class="header">Subject:</div> <div class="wh">{subject}<div><br>
                        <div class="header">Body:</div> 
                        <p>{body}</p>
                        {f'<div class="attachment">Attachment saved: {part["filename"]}</div>' if has_attachment else ''}
                    </div>
                ''')

    output.append('</div><div class="footer">End of Messages</div>')
    return ''.join(output)
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
if __name__ == '__main__':
    app.run(os.getenv('HOST'),os.getenv('PORT'), debug=True)

