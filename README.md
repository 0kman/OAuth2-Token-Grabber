# OAuth2 Token Grabber
Burp Suite extension to grab OAuth2 access tokens and add them to requests as a custom header

Currently supported auth flows:
- Client Credentials
- Password Credentials
- Resource Owner Password Credentials (ROPC)

## Usage
- Select desired grant type & client authentication method
- (Optional) Set a custom header for access tokens to be added to
- Input token URL
- Input relevant credentials and scope
- Hit 'Test'. You should receive an access token (Otherwise, try debug mode)
- Select desired tool scope
- Hit 'Activate'. The access token will then be added to all in scope traffic
- When the access token expires, a new one will be requested automatically
