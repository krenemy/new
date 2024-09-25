from flask import Flask, redirect, url_for, session, request
import google.auth.transport.requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import os
import base64
from dotenv import load_dotenv
from openai import OpenAI  # Version 1.33.0
from openai.types.beta.threads.message_create_params import Attachment, AttachmentToolFileSearch
import json
from PIL import Image
import pytesseract
# Set up Flask application
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)
app.config['PREFERRED_URL_SCHEME'] = 'https'
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
            background-color: #121212; /* Darker background for better contrast */
            color: #E0E0E0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; /* More modern font */
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            text-align: center;  
        }
        .container {
            width: 60%; /* Slightly wider for more content space */
            margin: 20px auto;
            padding: 40px; /* Reduced padding for a more compact look */
            background-color: #1E1E1E;
            border-radius: 12px; /* Softer corners */
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.7); /* Deeper shadow for depth */
            overflow: hidden; /* Prevent overflow for a cleaner appearance */
            display: flex;
            flex-direction: column;
            align-items: center;  
            justify-content: center;
        }
        h1, h2 {
            color: #E0E0E0;
            font-weight: bold;
            text-align: center;
            margin-bottom: 20px; /* Added margin for spacing */
        }
        a {
            color: #BB86FC;
            text-decoration: none;
            margin-top: 20px;
            transition: color 0.3s; /* Smooth color transition */
        }
        a:hover {
            color: #FF4081; /* Change color on hover for effect */
            text-decoration: underline;
        }
        .message {
            padding: 25px;
            margin: 15px 0;
            border: 1px solid #444; /* Softer border */
            border-radius: 8px;
            background-color: #2C2C2C;
            width: 90%; /* Wider message area */
            text-align: left;  
            word-wrap: break-word; 
            overflow-wrap: break-word; 
            word-break: break-word; 
            transition: transform 0.2s; /* Smooth transition effect */
        }
        .message:hover {
            transform: translateY(-2px); /* Lift effect on hover */
        }
        .message .header {
            font-weight: bold;
            color: #03DAC5;
            font-size: 1.4em; /* Slightly larger for emphasis */
            margin-bottom: 10px; /* Added margin for spacing */
        }
        .message p {
            color: #E0E0E0;
            line-height: 1.6;
            margin: 5px 0; /* Added margin for better spacing */
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            color: #888; /* Softer footer color */
        }
        .attachment {
            border: 1px solid #666;
            padding: 12px;
            margin: 10px 0;
            background-color: #333;
            color: #03DAC5;
            font-weight: bold;
            border-radius: 5px;
            transition: background-color 0.3s; /* Smooth transition */
        }
        .attachment:hover {
            background-color: #444; /* Darker background on hover */
        }
        .wh {
            color: white;
        }
        @media (max-width: 600px) {
            .container {
                width: 95%;
                padding: 15px; /* Adjusted padding */
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
    flow.redirect_uri = url_for('callback', _external=True,_scheme='https')
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
    flow.redirect_uri = url_for('callback', _external=True,_scheme='https')
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

client = OpenAI(api_key=os.getenv('OPEN_AI_KEY'))
def ocr_image_to_text(image_path):
    """
    Perform OCR on a JPEG file to extract text.
    """
    img = Image.open(image_path)
    text = pytesseract.image_to_string(img)
    return text

def upload_file(file_path):
    """
    Upload a file (PDF or JPEG) to the OpenAI API.
    """
    file_extension = os.path.splitext(file_path)[1].lower()
    
    if file_extension in ['.pdf', '.jpeg', '.jpg']:
        file = client.files.create(
            file=open(file_path, 'rb'),
            purpose='assistants'
        )
        return file.id
    else:
        raise ValueError("Unsupported file format. Please use PDF or JPEG.")
# Create thread
thread = client.beta.threads.create()
# Create an Assistant (or fetch it if it was already created). It has to have
# "file_search" tool enabled to attach files when prompting it.
def get_assistant():
    for assistant in client.beta.assistants.list():
        if assistant.name == 'My Assistant Name':
            return assistant

    # No Assistant found, create a new one
    return client.beta.assistants.create(
        model='gpt-4o',
        description='You are a PDF and image (JPEG) retrieval assistant.',
        instructions="You are a helpful assistant designed to output only JSON. Find information from the text and files provided.",
        tools=[{"type": "file_search"}],
        name='My Assistant Name',
    )
# Function to handle both PDFs and JPEGs
def process_file(file_path):
    """
    Process a file (PDF or JPEG) by uploading it to OpenAI or extracting text if it's a JPEG.
    """
    file_extension = os.path.splitext(file_path)[1].lower()

    if file_extension == '.pdf':
        file_id = upload_file(file_path)
        prompt = """
        Extract all necessary details about the purchase order from the PDF and output in JSON format. 
        The output should include fields such as:
        {
            "purchase_order_number": "PO123456",
            "vendor": "Vendor Name",
            "items": [
                {
                    "description": "Item 1",
                    "quantity": 10,
                    "unit_price": 25.00,
                    "total_price": 250.00
                },
                {
                    "description": "Item 2",
                    "quantity": 5,
                    "unit_price": 50.00,
                    "total_price": 250.00
                }
            ],
            "total_purchase_order_price": 500.00,
            "order_date": "2024-09-19"
        }
        """
        
        client.beta.threads.messages.create(
            thread_id=thread.id,
            role='user',
            content=prompt,
            attachments=[Attachment(file_id=file_id, tools=[AttachmentToolFileSearch(type='file_search')])]
        )

    elif file_extension in ['.jpeg', '.jpg']:
        extracted_text = ocr_image_to_text(file_path)
        prompt = f"""
        Extract all necessary details about the purchase order from the following text and output in JSON format. 
        The text is extracted from an image (JPEG):
        {extracted_text}
        The output should include fields such as:
        {{
            "purchase_order_number": "PO123456",
            "vendor": "Vendor Name",
            "items": [
                {{
                    "description": "Item 1",
                    "quantity": 10,
                    "unit_price": 25.00,
                    "total_price": 250.00
                }},
                {{
                    "description": "Item 2",
                    "quantity": 5,
                    "unit_price": 50.00,
                    "total_price": 250.00
                }}
            ],
            "total_purchase_order_price": 500.00,
            "order_date": "2024-09-19"
        }}
        """
        
        client.beta.threads.messages.create(
            thread_id=thread.id,
            role='user',
            content=prompt
        )

# Run the created thread with the assistant. It will wait until the message is processed.
def run_thread(file_path):
    process_file(file_path)

    run = client.beta.threads.runs.create_and_poll(
        thread_id=thread.id,
        assistant_id=get_assistant().id,
        timeout=300,  # 5 minutes
    )

    # Check if the run is completed
    if run.status != "completed":
        raise Exception('Run failed:', run.status)

    # Fetch outputs of the thread
    messages_cursor = client.beta.threads.messages.list(thread_id=thread.id)
    messages = [message for message in messages_cursor]

    message = messages[0]  # This is the output from the Assistant (second message is your message)
    assert message.content[0].type == "text"

    # Output text of the Assistant
    res_txt = message.content[0].text.value

    # Parse the JSON output
    if res_txt.startswith('```json'):
        res_txt = res_txt[6:]
    if res_txt.endswith('```'):
        res_txt = res_txt[:-3]
    res_txt = res_txt[:res_txt.rfind('}') + 1]
    res_txt = res_txt[res_txt.find('{'):]
    res_txt.strip()

    data = json.loads(res_txt)
    # print(data)

    return data

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

    # Fetch the user's Gmail messages (max 30)
    results = gmail_service.users().messages().list(userId='me', maxResults=30).execute()
    messages = results.get('messages', [])

    output = []
    if not messages:
        output.append('<p>No messages found.</p>')
    else:
        for message in messages:  # Fetch all 30 messages
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

            body_data = ''
            if 'parts' in msg['payload']:
                for part in msg['payload']['parts']:
                    if part['mimeType'] == 'text/plain':
                        body_data += part['body'].get('data', '')
                    elif part['mimeType'] == 'text/html' and not body_data:
                        body_data += part['body'].get('data', '')
            else:
                body_data = msg['payload']['body'].get('data', '')

            if body_data:
                body = base64.urlsafe_b64decode(body_data).decode('utf-8')

            # Check for attachments and download them
            JSONdata=0
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
                        try:
                            JSONdata = run_thread(file_path)
                        except json.JSONDecodeError:
                            print("Error decoding JSON")
                        print(JSONdata)

            # Filter emails that contain "Purchase Orders" in the subject or body
            if "Purchase Orders" in subject or "Purchase Orders" in body:
                # Append extracted details in the required format
                output.append(f'''
                   <div class="message">
                        <div class="">Sender:</div>
                        <div class="wh">{sender}</div><br>
                        <div class="header">Receiver:</div>
                        <div class="wh">{receiver}</div><br>
                        <div class="header">Subject:</div>
                        <div class="wh">{subject}</div><br>
                        <div>Body:</div> 
                        <p>{body}</p>
                        {f'<div class="attachment">Attachment saved: {part["filename"]}</div>' if has_attachment else ''}
                        <p>{JSONdata}</p>
                        <br><br>
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



