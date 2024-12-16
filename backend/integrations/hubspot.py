import asyncio
import base64
import hashlib
import secrets
import json
import logging
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
from redis.asyncio import Redis
from integrations.integration_item import IntegrationItem

# Initialize Redis client
redis_client = Redis(host='localhost', port=6379, db=0)

CLIENT_ID = '3b6a48aa-bcd4-4e76-a615-ba25f048ff2c'
CLIENT_SECRET = '307fb46a-ce24-42c0-88d2-c71cebc77c48'
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
authorization_url = f'https://app.hubspot.com/oauth/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=oauth%20crm.objects.companies.write%20crm.objects.companies.read'

# Initialize logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')
    await redis_client.setex(f'hubspot_state:{org_id}:{user_id}', 600, json.dumps(state_data))
    return authorization_url + f'&state={encoded_state}'

async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state = await redis_client.get(f'hubspot_state:{org_id}:{user_id}')
    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    async with httpx.AsyncClient() as client:
        response = await client.post(
            'https://api.hubapi.com/oauth/v1/token',
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': REDIRECT_URI,
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

    if response.status_code != 200:
        logger.error(f"Error during token exchange: {response.text}")
        raise HTTPException(status_code=response.status_code, detail=response.text)

    await redis_client.setex(f'hubspot_credentials:{org_id}:{user_id}', 600, json.dumps(response.json()))
    await redis_client.delete(f'hubspot_state:{org_id}:{user_id}')

    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id, org_id):
    credentials = await redis_client.get(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    await redis_client.delete(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials

async def create_integration_item_metadata_object(response_json):
    return IntegrationItem(
        id=response_json.get('id'),
        name=response_json.get('properties', {}).get('firstname', '') + ' ' + response_json.get('properties', {}).get('lastname', ''),
        type='Contact',
        creation_time=response_json.get('properties', {}).get('createdate'),
        last_modified_time=response_json.get('properties', {}).get('lastmodifieddate'),
        url=f'https://app.hubspot.com/contacts/{response_json.get("portalId")}/contact/{response_json.get("id")}/'
    )

async def get_items_hubspot(credentials):
    if isinstance(credentials, str):
        access_token = credentials
    else:
        credentials = json.loads(credentials)
        access_token = credentials.get('access_token')

    url = 'https://api.hubapi.com/crm/v3/objects/contacts'
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    all_contacts = []

    async with httpx.AsyncClient() as client:
        try:
            while url:
                response = await client.get(url, headers=headers)
                response.raise_for_status()

                data = response.json()
                all_contacts.extend(data.get('results', []))
                url = data.get('paging', {}).get('next', {}).get('link')
        except httpx.HTTPStatusError as e:
            logger.error(f"Error retrieving HubSpot contacts: {e}")
            raise HTTPException(status_code=e.response.status_code, detail=str(e))
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve HubSpot contacts")

    return [await create_integration_item_metadata_object(contact) for contact in all_contacts]
