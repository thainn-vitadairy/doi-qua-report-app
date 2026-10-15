"""Server-to-server Supabase email OTP; verified identity plus report allowlist."""
import json,re,urllib.request,urllib.error
try:
    from .password_auth import credential_version
except ImportError:
    from password_auth import credential_version


def login_mode(settings):
    if settings.get('enabled') is not True:return 'password'
    mode=settings.get('mode','otp')
    if mode not in ('otp','allowlist'):raise ValueError('Invalid access mode')
    return mode


def allowlist_session(email,accounts,now):
    """Owner-approved email gate. This does NOT verify mailbox ownership."""
    email=email.strip().lower()
    account=accounts.get(email)
    if not account or account.get('enabled') is not True:return None
    return {'email':email,'version':credential_version(account),
            'expires':now+8*3600,'method':'email_allowlist'}


class AuthenticationError(Exception):
    """Safe public error: never expose a provider response or credentials."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise AuthenticationError('Unexpected authentication redirect')


def report_accounts(accounts,settings):
    result={email.strip().lower():dict(account) for email,account in accounts.items()}
    for email in settings.get('allowed_emails',[]):
        email=email.strip().lower()
        if not re.fullmatch(r'[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}',email):
            raise ValueError('Invalid allowed email')
        # An explicit disabled account always overrides the bulk allowlist.
        result.setdefault(email,{'enabled':True})
    return result


class EmailAuth:
    def __init__(self,settings):
        url=settings.get('url','').rstrip('/')
        if not re.fullmatch(r'https://[a-z0-9-]+\.supabase\.co',url):
            raise ValueError('Expected hosted Supabase project URL')
        key=settings.get('publishable_key','')
        if not isinstance(key,str) or len(key)<20 or '\n' in key or '\r' in key:
            raise ValueError('Missing Supabase publishable key')
        # Only the low privilege publishable key belongs in this app.
        if not key.startswith('sb_publishable_'):
            raise ValueError('Use a Supabase publishable key, not a service role key')
        self.url=url;self.key=key

    def request(self,path,payload=None,token=None):
        headers={'apikey':self.key,'Content-Type':'application/json','User-Agent':'VitaDairy-Report-Auth'}
        if token:headers['Authorization']='Bearer '+token
        request=urllib.request.Request(self.url+'/auth/v1/'+path,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers=headers,method='POST' if payload is not None else 'GET')
        try:
            with urllib.request.build_opener(NoRedirect()).open(request,timeout=15) as response:
                body=response.read(65537)
                if len(body)>65536:raise ValueError('Oversized response')
                result=json.loads(body)
                if not isinstance(result,dict):raise ValueError('Invalid response')
                return result
        except (OSError,ValueError,urllib.error.URLError) as exc:
            raise AuthenticationError('Email authentication unavailable or rejected') from None

    def send(self,email,accounts):
        account=accounts.get(email)
        if not account or account.get('enabled') is not True:return False
        self.request('otp',{'email':email,'create_user':True})
        return True

    def verify(self,email,code,accounts):
        account=accounts.get(email)
        if not account or account.get('enabled') is not True:raise AuthenticationError('Access denied')
        if not re.fullmatch(r'[0-9]{6}',code):raise AuthenticationError('Invalid code')
        result=self.request('verify',{'email':email,'token':code,'type':'email'})
        token=result.get('access_token')
        if not isinstance(token,str) or not token or '\n' in token or '\r' in token:
            raise AuthenticationError('Missing verified session')
        # Do not trust email fields from the submitted form or an unverified JWT.
        user=self.request('user',token=token)
        if (str(user.get('email','')).lower()!=email or not user.get('email_confirmed_at')
            or user.get('is_anonymous') is True or not user.get('id')):
            raise AuthenticationError('Identity mismatch')
        return user['id']
