"""Encrypted report launcher with owner-configured access mode."""
from pathlib import Path
import hashlib,io,os,re,runpy,shutil,sys,tempfile,time,urllib.request,urllib.parse,zipfile,json
import streamlit as st
from security import archive_members
from password_auth import verify_password,session_valid,credential_version,RateLimiter
from encrypted_payload import decrypt_payload
from release_pointer import read_pointer
from runtime_store import RuntimeStore
from email_auth import report_accounts,login_mode

st.set_page_config(page_title='VitaDairy · Báo cáo đổi quà',page_icon='◈',layout='wide')
try:
    accounts={key:dict(value) for key,value in st.secrets['report_users'].items()}
    artifact=dict(st.secrets['artifact'])
    email_settings=dict(st.secrets.get('email_login',{}))
    access_mode=login_mode(email_settings)
    if email_settings.get('enabled') is True:accounts=report_accounts(accounts,email_settings)
    if not accounts or not all(k in artifact for k in ('url','sha256','key')):raise ValueError('Missing configuration')
except (KeyError,ValueError,FileNotFoundError):
    st.info('Báo cáo đang chờ hoàn tất cấu hình truy cập.');st.stop()

@st.cache_resource(show_spinner=False)
def limiter():return RateLimiter(Path(tempfile.gettempdir())/'vitadairy-report-login.sqlite3')

def attempt_login():
    email=st.session_state.get('_report_email','').strip().lower()
    password=st.session_state.pop('_report_password','')
    now=time.time();account=accounts.get(email)
    client=getattr(st.context,'ip_address',None)
    try:allowed=limiter().reserve(email,str(client) if client else '',now)
    except Exception:allowed=False
    if not allowed:
        st.session_state['_login_error']='Đã vượt số lần thử. Vui lòng thử lại sau 15 phút.';return
    dummy=next(iter(accounts.values())).get('password_hash','')
    valid=verify_password(password,(account or {}).get('password_hash',dummy))
    if not valid or not account or account.get('enabled') is not True:
        st.session_state['_login_error']='Thông tin đăng nhập chưa đúng hoặc tài khoản chưa được cấp quyền.';return
    limiter().success(email)
    st.session_state['_report_session']={'email':email,'version':credential_version(account),'expires':now+8*3600}
    st.session_state.pop('_login_error',None)

def valid_session():
    session=st.session_state.get('_report_session')
    return (session_valid(session,accounts,time.time()) and
            session.get('method','password')=={'password':'password','otp':'email_otp','allowlist':'email_allowlist'}[access_mode])

if not valid_session():
    # Reset report widget state when access is revoked/expired or mode changes.
    if '_report_session' in st.session_state:st.session_state.clear()
    st.markdown('''<style>.block-container{max-width:560px;padding-top:10vh}
        [data-testid="stForm"]{padding:28px;border-radius:18px;background:white;border:1px solid #dce6dc}
        h1{color:#174b35!important;font-size:34px!important}.login-kicker{color:#a58132;letter-spacing:2px;font-weight:700}
        </style><div class="login-kicker">VITADAIRY · LOYALTY PERFORMANCE</div>''',unsafe_allow_html=True)
    st.title('Báo cáo đổi quà')
    if access_mode=='allowlist':
        from email_login import render_allowlist_login
        render_allowlist_login(accounts,limiter())
    elif access_mode=='otp':
        from email_login import render_email_login
        render_email_login(accounts,email_settings,limiter())
    else:
        st.write('Đăng nhập bằng tài khoản được cấp cho báo cáo.')
        with st.form('report_login'):
            st.text_input('Email',key='_report_email',max_chars=254)
            st.text_input('Mật khẩu báo cáo',type='password',key='_report_password',max_chars=1024)
            st.form_submit_button('Đăng nhập',type='primary',on_click=attempt_login,width='stretch')
        if st.session_state.get('_login_error'):st.error(st.session_state['_login_error'])
        st.caption('Dùng mật khẩu riêng của báo cáo. Không nhập mật khẩu Microsoft 365.')
    st.stop()

class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        target=urllib.parse.urlsplit(newurl)
        if target.scheme!='https' or not (target.hostname or '').endswith('.githubusercontent.com'):
            raise ValueError('Unexpected download redirect')
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def download_payload(url,sha256,_key):
    parsed=urllib.parse.urlsplit(url)
    if (parsed.scheme!='https' or parsed.netloc!='github.com' or parsed.query or parsed.fragment
        or not re.fullmatch(r'/thainn-vitadairy/doi-qua-report-app/releases/download/[A-Za-z0-9_.-]+/report.enc',parsed.path)
        or not re.fullmatch(r'[a-f0-9]{64}',sha256)):
        raise ValueError('Invalid artifact location')
    request=urllib.request.Request(url,headers={'User-Agent':'VitaDairy-Report'})
    chunks=[];size=0
    with urllib.request.build_opener(SafeRedirect()).open(request,timeout=90) as response:
        while chunk:=response.read(1024*1024):
            size+=len(chunk)
            if size>200_000_000:raise ValueError('Report download too large')
            chunks.append(chunk)
    envelope=b''.join(chunks)
    if hashlib.sha256(envelope).hexdigest()!=sha256:raise ValueError('Checksum mismatch')
    return decrypt_payload(envelope,_key)

@st.cache_resource(show_spinner=False)
def runtime_store():return RuntimeStore()

@st.fragment(run_every='5m')
def check_release():
    if not valid_session():st.rerun()
    pointer=Path(__file__).parent/'current_release.json'
    try:version=read_pointer(json.loads(pointer.read_text(encoding='utf-8')),artifact['key'])['sha256']
    except (OSError,ValueError,KeyError,TypeError):return
    if version!=st.session_state.get('_attempted_release'):st.rerun()

with st.container(horizontal=True,vertical_alignment='center'):
    st.caption('Tài khoản: '+st.session_state['_report_session']['email'])
    if st.button('Đăng xuất',key='cloud_logout'):
        st.session_state.clear();st.rerun()
os.environ['VITADAIRY_CLOUD']='1'
store=runtime_store()
with store.lock:
    try:
        pointer=Path(__file__).parent/'current_release.json'
        selected=read_pointer(json.loads(pointer.read_text(encoding='utf-8')),artifact['key']) if pointer.exists() else artifact
        st.session_state['_attempted_release']=selected['sha256']
        if store.version!=selected['sha256']:
            with st.spinner('Đang mở bản dữ liệu mới nhất…'):
                data=download_payload(selected['url'],selected['sha256'],artifact['key'])
                if store.install(data,selected['sha256']):st.cache_data.clear()
    except Exception:
        if not store.version:
            st.error('Chưa tải được bản báo cáo. Vui lòng liên hệ người quản lý báo cáo.');st.stop()
        st.warning('Chưa tải được bản cập nhật. Đang hiển thị bản dữ liệu đã kiểm tra gần nhất.')
    runtime=store.root
    if str(runtime) not in sys.path:sys.path.insert(0,str(runtime))
    try:runpy.run_path(str(runtime/'app.py'),run_name='__main__')
    finally:check_release()
