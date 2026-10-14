"""Dedicated report credentials; no Microsoft identity or reusable client auth tokens."""
import hashlib,hmac,json,math,secrets,sqlite3
from contextlib import closing

def hash_password(password):
    if not isinstance(password,str) or not 16<=len(password)<=1024:raise ValueError('Use a strong report password')
    salt=secrets.token_bytes(16)
    key=hashlib.scrypt(password.encode(),salt=salt,n=131072,r=8,p=1,dklen=32,maxmem=256*1024*1024)
    return 'scrypt$131072$8$1$'+salt.hex()+'$'+key.hex()

def verify_password(password,encoded):
    try:
        if not isinstance(password,str) or len(password)>1024:return False
        method,n,r,p,salt,expected=encoded.split('$')
        if (method,n,r,p)!=('scrypt','131072','8','1'):return False
        salt=bytes.fromhex(salt);expected=bytes.fromhex(expected)
        if len(salt)!=16 or len(expected)!=32:return False
        actual=hashlib.scrypt(password.encode(),salt=salt,n=131072,r=8,p=1,dklen=32,maxmem=256*1024*1024)
        return hmac.compare_digest(actual,expected)
    except (TypeError,ValueError,AttributeError):return False

def credential_version(account):
    return hashlib.sha256(json.dumps([account.get('password_hash'),account.get('enabled')]).encode()).hexdigest()

def session_valid(session,accounts,now):
    try:
        account=accounts.get(session['email']);expiry=float(session['expires'])
        return bool(account and account.get('enabled') is True and math.isfinite(expiry) and now<expiry
            and hmac.compare_digest(session['version'],credential_version(account)))
    except (KeyError,TypeError,ValueError,AttributeError):return False

class RateLimiter:
    """SQLite buckets shared by sessions/processes on one app instance, fixed 15-minute windows."""
    def __init__(self,path):
        self.path=str(path)
        with closing(sqlite3.connect(self.path,timeout=10)) as db,db:
            db.execute('CREATE TABLE IF NOT EXISTS attempts (bucket TEXT PRIMARY KEY,started REAL,n INTEGER)')

    @staticmethod
    def account_key(email):return 'account:'+hashlib.sha256(email.encode()).hexdigest()

    def reserve(self,email,client,now):
        buckets=[(self.account_key(email),5),('global',120)]
        if client:buckets.append(('client:'+hashlib.sha256(client.encode()).hexdigest(),20))
        with closing(sqlite3.connect(self.path,timeout=10)) as db,db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM attempts WHERE started<=?',[now-900])
            for key,limit in buckets:
                row=db.execute('SELECT n FROM attempts WHERE bucket=?',[key]).fetchone()
                if row and row[0]>=limit:return False
            for key,_ in buckets:
                db.execute('INSERT INTO attempts VALUES(?,?,1) ON CONFLICT(bucket) DO UPDATE SET n=n+1',[key,now])
        return True

    def success(self,email):
        with closing(sqlite3.connect(self.path,timeout=10)) as db,db:db.execute('DELETE FROM attempts WHERE bucket=?',[self.account_key(email)])
