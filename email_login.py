"""Email-code login screen. Provider must be configured before this mode is enabled."""
import time
import streamlit as st
from email_auth import EmailAuth,AuthenticationError,allowlist_session
from password_auth import credential_version


def render_allowlist_login(accounts,limiter):
    """Email-only access chosen by the owner; no OTP or password request."""
    def enter():
        email=st.session_state.get('_report_email','').strip().lower()
        now=time.time();client=getattr(st.context,'ip_address',None)
        try:allowed=limiter.reserve('access:'+email,str(client) if client else '',now)
        except Exception:allowed=False
        if not allowed:
            st.session_state['_access_error']='Đã vượt số lần thử. Vui lòng thử lại sau 15 phút.';return
        session=allowlist_session(email,accounts,now)
        if session is None:
            st.session_state['_access_error']='Email chưa được cấp quyền xem báo cáo. Vui lòng liên hệ người quản lý.';return
        limiter.success('access:'+email)
        st.session_state['_report_session']=session
        st.session_state.pop('_access_error',None)
    st.write('Nhập email công ty đã được cấp quyền xem báo cáo.')
    with st.form('email_access'):
        st.text_input('Email công ty',key='_report_email',max_chars=254,placeholder='ten@vitadairy.com.vn')
        st.form_submit_button('Vào báo cáo',on_click=enter,type='primary',width='stretch')
    if st.session_state.get('_access_error'):st.error(st.session_state['_access_error'])


def render_email_login(accounts,settings,limiter):
    try:provider=EmailAuth(settings)
    except (ValueError,TypeError):
        st.error('Đăng nhập email chưa sẵn sàng. Vui lòng liên hệ người quản lý báo cáo.');st.stop()

    def clear_pending():
        for key in ('_otp_email','_otp_started','_otp_attempts','_otp_notice','_otp_error','_otp_code'):
            st.session_state.pop(key,None)

    def send_code():
        email=st.session_state.get('_report_email','').strip().lower();now=time.time()
        st.session_state.pop('_otp_error',None)
        if now-st.session_state.get('_otp_last_request',0)<60:
            st.session_state['_otp_error']='Vui lòng chờ 60 giây trước khi yêu cầu mã mới.';return
        client=getattr(st.context,'ip_address',None)
        try:allowed=limiter.reserve('send:'+email,str(client) if client else '',now)
        except Exception:allowed=False
        if not allowed:
            st.session_state['_otp_error']='Đã vượt số lần yêu cầu. Vui lòng thử lại sau 15 phút.';return
        clear_pending();st.session_state['_otp_last_request']=now
        try:provider.send(email,accounts)
        except AuthenticationError:
            st.session_state['_otp_error']='Chưa gửi được mã. Vui lòng thử lại sau hoặc liên hệ người quản lý báo cáo.';return
        # Same response for unknown addresses; never disclose the allowlist.
        st.session_state.update(_otp_email=email,_otp_started=now,_otp_attempts=0,
            _otp_notice='Nếu email đã được cấp quyền, mã xác thực sẽ được gửi tới hộp thư. Kiểm tra cả thư rác.')

    def verify_code():
        code=st.session_state.pop('_otp_code','').strip();email=st.session_state.get('_otp_email','');now=time.time()
        st.session_state.pop('_otp_error',None)
        if now-st.session_state.get('_otp_started',0)>=300:
            clear_pending();st.session_state['_otp_error']='Phiên nhập mã đã hết hạn. Vui lòng yêu cầu mã mới.';return
        attempts=st.session_state.get('_otp_attempts',0)
        if attempts>=5:
            st.session_state['_otp_error']='Đã hết lượt thử. Vui lòng yêu cầu mã mới.';return
        st.session_state['_otp_attempts']=attempts+1
        client=getattr(st.context,'ip_address',None)
        try:allowed=limiter.reserve('verify:'+email,str(client) if client else '',now)
        except Exception:allowed=False
        if not allowed:
            st.session_state['_otp_error']='Đã vượt số lần thử. Vui lòng thử lại sau 15 phút.';return
        try:provider.verify(email,code,accounts)
        except AuthenticationError:
            st.session_state['_otp_error']='Mã không hợp lệ, đã hết hạn hoặc email chưa được cấp quyền.';return
        account=accounts[email]
        st.session_state['_report_session']={'email':email,'version':credential_version(account),'expires':now+8*3600,'method':'email_otp'}
        clear_pending()

    st.write('Dùng email được cấp quyền để nhận mã đăng nhập.')
    if not st.session_state.get('_otp_email'):
        with st.form('email_request'):
            st.text_input('Email công ty',key='_report_email',max_chars=254,placeholder='ten@vitadairy.com.vn')
            st.form_submit_button('Gửi mã xác thực',on_click=send_code,type='primary',width='stretch')
    else:
        st.caption('Email: '+st.session_state['_otp_email'])
        if st.session_state.get('_otp_notice'):st.info(st.session_state['_otp_notice'])
        with st.form('email_verify'):
            st.text_input('Mã xác thực 6 số',key='_otp_code',max_chars=6,placeholder='000000')
            st.form_submit_button('Xác thực và vào báo cáo',on_click=verify_code,type='primary',width='stretch')
        left,right=st.columns(2)
        with left:st.button('Gửi lại mã',on_click=send_code,width='stretch')
        with right:st.button('Dùng email khác',on_click=clear_pending,width='stretch')
        st.caption('Mã có hiệu lực 5 phút và chỉ dùng một lần.')
    if st.session_state.get('_otp_error'):st.error(st.session_state['_otp_error'])
    st.caption('Không cần mật khẩu riêng của báo cáo. Không nhập mật khẩu Microsoft 365.')
