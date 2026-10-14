"""Protected report launcher: dedicated credentials + authenticated encrypted snapshot."""
from pathlib import Path
import hashlib,io,os,re,runpy,shutil,sys,tempfile,time,urllib.request,urllib.parse,zipfile
import streamlit as st
from security import archive_members
from password_auth import verify_password,session_valid,credential_version,RateLimiter
from encrypted_payload import decrypt_payload

st.set_page_config(page_title='VitaDairy · Báo cáo đổi quà',page_icon='◈',layout='wide')
try:
    accounts={key:dict(value) for key,value in st.secrets['report_users'].items()}
    artifact=dict(st.secrets['artifact'])
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

if not session_valid(st.session_state.get('_report_session'),accounts,time.time()):
    st.session_state.pop('_report_session',None)
    st.markdown('''<style>.block-container{max-width:560px;padding-top:10vh}
        [data-testid="stForm"]{padding:28px;border-radius:18px;background:white;border:1px solid #dce6dc}
        h1{color:#174b35!important;font-size:34px!important}.login-kicker{color:#a58132;letter-spacing:2px;font-weight:700}
        </style><div class="login-kicker">VITADAIRY · LOYALTY PERFORMANCE</div>''',unsafe_allow_html=True)
    st.title('Báo cáo đổi quà')
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

@st.cache_resource(show_spinner=False,max_entries=1)
def prepare_runtime(url,sha256,_key):
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
    data=decrypt_payload(envelope,_key)
    target=Path(tempfile.mkdtemp(prefix='vitadairy-report-'))
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for member in archive_members(z):
            path=target/member.filename
            if member.is_dir():path.mkdir(parents=True,exist_ok=True)
            else:
                path.parent.mkdir(parents=True,exist_ok=True)
                with z.open(member) as src,path.open('wb') as dst:shutil.copyfileobj(src,dst)
    if not (target/'app.py').is_file() or not (target/'local/manifest.json').is_file():raise ValueError('Incomplete report')
    return target

try:
    with st.spinner('Đang mở báo cáo…'):runtime=prepare_runtime(artifact['url'],artifact['sha256'],artifact['key'])
except Exception:
    st.error('Chưa tải được bản báo cáo. Vui lòng liên hệ người quản lý báo cáo.');st.stop()

with st.sidebar:
    st.caption('Tài khoản: '+st.session_state['_report_session']['email'])
    if st.button('Đăng xuất',key='cloud_logout'):
        st.session_state.clear();st.rerun()
os.environ['VITADAIRY_CLOUD']='1'
if str(runtime) not in sys.path:sys.path.insert(0,str(runtime))
runpy.run_path(str(runtime/'app.py'),run_name='__main__')
