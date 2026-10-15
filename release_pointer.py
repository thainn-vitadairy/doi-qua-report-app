"""Signed release pointer: public metadata, authenticated by the private report key."""
import hashlib,hmac,json,re

def signature(payload,key):
    data=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
    return hmac.new(bytes.fromhex(key),b'vitadairy-release-v1\0'+data,hashlib.sha256).hexdigest()

def make_pointer(url,sha256,key):
    payload={'url':url,'sha256':sha256}
    return {'payload':payload,'signature':signature(payload,key)}

def read_pointer(document,key):
    payload=document['payload']
    if set(payload)!={'url','sha256'}:raise ValueError('Unexpected release fields')
    if not hmac.compare_digest(signature(payload,key),document['signature']):raise ValueError('Invalid release signature')
    if not re.fullmatch(r'https://github.com/thainn-vitadairy/doi-qua-report-app/releases/download/[A-Za-z0-9_.-]+/report.enc',payload['url']):raise ValueError('Invalid release URL')
    if not re.fullmatch('[a-f0-9]{64}',payload['sha256']):raise ValueError('Invalid digest')
    return payload
