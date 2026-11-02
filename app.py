"""둘의 하루 — Streamlit 커플 다이어리

배포
1. 이 파일과 requirements.txt를 GitHub 저장소에 업로드합니다.
2. Neon/Supabase 등의 PostgreSQL 데이터베이스를 준비합니다.
   Supabase는 IPv4 호환 Session pooler 연결 문자열을 권장합니다.
3. Streamlit Community Cloud에서 저장소를 연결하고 main file을 app.py로 지정합니다.
4. 앱 Settings > Secrets에 아래 TOML을 입력합니다(실제 값으로 교체).

DATABASE_URL = "postgresql://USER:PASSWORD@HOST:5432/DATABASE?sslmode=require"
APP_URL = "https://YOUR-APP.streamlit.app"
PARTNER_A_NAME = "나무"
PARTNER_B_NAME = "구름"
PARTNER_A_PASSWORD = "서로-다른-충분히-긴-비밀번호-A"
PARTNER_B_PASSWORD = "서로-다른-충분히-긴-비밀번호-B"

비밀번호는 각 12자 이상, 서로 다르게 설정하세요. Secrets는 GitHub에 올리지 마세요.
DB 테이블은 최초 실행 시 자동 생성됩니다. 이 앱은 한 커플 전용입니다.
QR에는 APP_URL만 들어가며 비밀번호나 로그인 토큰은 포함하지 않습니다.
공유 연결 문자열에 특수문자가 있는 비밀번호는 URL 인코딩되어야 합니다.

기능: 날짜별 1인 1일기, 수정 시 읽음 초기화, 상대의 명시적 읽음 체크,
15초 간격 읽음/일기 갱신, QR 다운로드, 한국 시간, DB 기반 로그인 시도 제한.
폰의 크기/브라우저/키보드에 따라 전체 무스크롤은 보장되지 않습니다.
일기 내용은 고정 높이 내부 스크롤 영역에서 확인합니다.
"""

from datetime import date, datetime
from io import BytesIO
from zoneinfo import ZoneInfo
import hashlib
import hmac
import html
from urllib.parse import urlparse

import psycopg
from psycopg.rows import dict_row
import qrcode
import streamlit as st

st.set_page_config(page_title="둘의 하루", page_icon="💌", layout="centered", initial_sidebar_state="collapsed")
KST = ZoneInfo("Asia/Seoul")
MOODS = ["🥰 행복", "😊 평온", "🥺 그리움", "😴 피곤", "😢 속상", "😤 화남"]

st.markdown("""<style>
[data-testid="stHeader"]{display:none}
.block-container{max-width:470px;padding:0.55rem 0.8rem 0.6rem!important}
[data-testid="stAppViewContainer"]{background:#fff8f6}
[data-testid="stVerticalBlock"]{gap:.38rem}
h1{font-size:1.5rem!important;padding:0!important;margin:0!important;color:#633b49}
p{margin-bottom:.2rem} .stCaption{font-size:.76rem}
[data-testid="stTextArea"] textarea{font-size:16px;min-height:88px!important}
[data-testid="stTextInput"] input{font-size:16px}
.stButton button,.stDownloadButton button{min-height:2.25rem;border-radius:12px}
[data-testid="stDateInput"] input{font-size:14px}
.diary{height:104px;overflow-y:auto;white-space:pre-wrap;overflow-wrap:anywhere;
background:white;border:1px solid #eed8df;border-radius:14px;padding:9px 12px;
color:#49343b;font-size:14px;line-height:1.5}
.tag{font-size:12px;color:#754957;margin:0 0 4px}.brand{font-weight:800;font-size:22px;color:#633b49}
@media(max-height:690px){.block-container{padding-top:.25rem!important}.diary{height:80px}}
</style>""", unsafe_allow_html=True)


def setting(key, default=""):
    try:
        return str(st.secrets.get(key, default)).strip()
    except Exception:
        return default


DB_URL = setting("DATABASE_URL")
NAMES = {"a": setting("PARTNER_A_NAME", "나무"), "b": setting("PARTNER_B_NAME", "구름")}
PASSWORDS = {"a": setting("PARTNER_A_PASSWORD"), "b": setting("PARTNER_B_PASSWORD")}


def db():
    # 트랜잭션별 연결: 재실행/동시 접속에서 공유 커넥션 충돌 방지.
    return psycopg.connect(DB_URL, row_factory=dict_row, connect_timeout=10)


@st.cache_resource(show_spinner=False)
def initialize_database(database_url):
    with psycopg.connect(database_url, connect_timeout=10) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS couple_diary_entries (
            author TEXT NOT NULL CHECK (author IN ('a','b')),
            diary_date DATE NOT NULL,
            mood TEXT NOT NULL,
            body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 800),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            read_at TIMESTAMPTZ,
            version BIGINT NOT NULL DEFAULT 1,
            PRIMARY KEY(author, diary_date)
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS couple_diary_login_guard (
            account TEXT PRIMARY KEY,
            failures INTEGER NOT NULL DEFAULT 0,
            blocked_until TIMESTAMPTZ,
            last_failure TIMESTAMPTZ
        )""")
        for account in ("a", "b"):
            conn.execute("INSERT INTO couple_diary_login_guard(account) VALUES (%s) ON CONFLICT DO NOTHING", (account,))
    return True


def authenticate(account, password):
    with db() as conn:
        row = conn.execute("SELECT *, now() AS current_time FROM couple_diary_login_guard WHERE account=%s FOR UPDATE", (account,)).fetchone()
        if row["blocked_until"] and row["blocked_until"] > row["current_time"]:
            return False, "로그인 시도가 많아요. 5분 후 다시 시도해주세요."
        valid = hmac.compare_digest(password.encode(), PASSWORDS[account].encode())
        if valid:
            conn.execute("UPDATE couple_diary_login_guard SET failures=0, blocked_until=NULL, last_failure=NULL WHERE account=%s", (account,))
            return True, ""
        # 오래된 실패는 초기화. 계정당 5회 연속 실패 시 5분 잠금.
        recent = row["last_failure"] and (row["current_time"] - row["last_failure"]).total_seconds() < 300
        failures = row["failures"] + 1 if recent else 1
        conn.execute("""UPDATE couple_diary_login_guard SET failures=%s, last_failure=now(),
            blocked_until=CASE WHEN %s >= 5 THEN now()+interval '5 minutes' ELSE NULL END WHERE account=%s""", (failures, failures, account))
        return False, "비밀번호를 확인해주세요. 5회 실패하면 5분간 잠깁니다."


def entries_for(day):
    with db() as conn:
        rows = conn.execute("SELECT * FROM couple_diary_entries WHERE diary_date=%s", (day,)).fetchall()
    return {row["author"]: row for row in rows}


def save_entry(author, day, mood, body):
    with db() as conn:
        conn.execute("""INSERT INTO couple_diary_entries(author, diary_date, mood, body)
            VALUES (%s,%s,%s,%s)
            ON CONFLICT(author, diary_date) DO UPDATE SET
            mood=EXCLUDED.mood, body=EXCLUDED.body, updated_at=clock_timestamp(),
            read_at=NULL, version=couple_diary_entries.version+1""", (author, day, mood, body))


def mark_read(author, day, version):
    # 화면에 표시된 버전만 확인 처리. 읽는 사이 수정되면 새 버전을 다시 보여줍니다.
    with db() as conn:
        result = conn.execute("""UPDATE couple_diary_entries SET read_at=clock_timestamp()
            WHERE author=%s AND diary_date=%s AND version=%s AND read_at IS NULL""", (author, day, version))
        return result.rowcount == 1


def stamp(value):
    return value.astimezone(KST).strftime("%m/%d %H:%M") if value else ""


@st.dialog("우리의 접속 QR")
def show_qr():
    url = setting("APP_URL")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        st.warning("Secrets의 APP_URL을 로그인 정보·쿼리가 없는 https 앱 주소로 설정해주세요.")
        return
    buffer = BytesIO()
    qrcode.make(url).save(buffer, format="PNG")
    image = buffer.getvalue()
    st.image(image, width=210)
    st.caption("휴대폰 카메라로 스캔 → 각자의 이름과 비밀번호로 로그인")
    st.link_button("앱 열기", url)
    st.download_button("QR 이미지 다운로드", image, "couple-qr.png", "image/png")


def main():
    if not DB_URL or any(len(p) < 12 for p in PASSWORDS.values()) or PASSWORDS["a"] == PASSWORDS["b"]:
        st.title("💌 둘의 하루")
        st.info("최초 설정이 필요합니다. app.py 맨 위 안내에 따라 데이터베이스와 두 사람의 서로 다른 비밀번호(12자 이상)를 Streamlit Secrets에 등록해주세요.")
        st.stop()
    initialize_database(DB_URL)
    # Secrets 변경 후 기존 세션도 자동 로그아웃.
    signature = hashlib.sha256((PASSWORDS["a"] + "\0" + PASSWORDS["b"]).encode()).hexdigest()
    if st.session_state.get("auth_signature") != signature:
        st.session_state.pop("account", None)
    if "account" not in st.session_state:
        st.title("💌 둘의 하루")
        st.caption("오늘의 마음을, 가장 가까운 사람에게")
        with st.form("login"):
            who = st.selectbox("나는", ["a", "b"], format_func=lambda x: NAMES[x])
            password = st.text_input("나의 비밀번호", type="password")
            submit = st.form_submit_button("우리 일기 열기", type="primary", use_container_width=True)
        if submit:
            ok, message = authenticate(who, password)
            if ok:
                st.session_state.account = who
                st.session_state.auth_signature = signature
                st.rerun()
            st.error(message)
        st.caption("비밀번호는 QR에 포함되지 않아요. 앱 관리자에게 따로 받아주세요.")
        return

    me = st.session_state.account
    partner = "b" if me == "a" else "a"
    title, qr, logout = st.columns([6, 1.5, 2])
    title.markdown('<div class="brand">💌 둘의 하루</div>', unsafe_allow_html=True)
    if qr.button("QR", use_container_width=True):
        show_qr()
    if logout.button("나가기", use_container_width=True):
        st.session_state.clear()
        st.rerun()
    today = datetime.now(KST).date()
    day = st.date_input("일기 날짜 · 한국 시간", value=today, max_value=today, min_value=date(2000, 1, 1))
    mine = entries_for(day).get(me)
    # 날짜/로그인 사용자마다 독립적인 작성 위젯. 다른 날 초안이 섞이지 않습니다.
    key = f"{me}_{day.isoformat()}"
    st.caption(f"✏️ {NAMES[me]}의 마음 · 날짜별 한 편, 수정 가능")
    with st.form(f"editor_{key}"):
        mood = st.selectbox("오늘 기분", MOODS, index=MOODS.index(mine["mood"]) if mine and mine["mood"] in MOODS else 0, key=f"mood_{key}", label_visibility="collapsed")
        body = st.text_area("나의 일기", value=mine["body"] if mine else "", height=88, max_chars=800, placeholder="오늘 너에게 들려주고 싶은 이야기…", label_visibility="collapsed", key=f"body_{key}")
        saved = st.form_submit_button("💌 수정해서 보내기" if mine else "💌 마음 보내기", type="primary", use_container_width=True)
    if saved:
        if not body.strip():
            st.toast("짧게라도 오늘의 마음을 적어주세요.", icon="✏️")
        else:
            save_entry(me, day, mood, body.strip())
            st.toast("마음을 보냈어요. 수정한 일기는 읽음 표시가 초기화돼요.", icon="💌")
            st.rerun()

    @st.fragment(run_every="15s")
    def shared_panel():
        try:
            rows = entries_for(day)
            own, other = rows.get(me), rows.get(partner)
            if own:
                st.caption(f"내 일기 · ✅ {NAMES[partner]} 확인 {stamp(own['read_at'])}" if own["read_at"] else "내 일기 · 💌 아직 상대가 확인하지 않았어요")
            else:
                st.caption("내 일기 · 오늘의 마음을 기다리고 있어요")
            if not other:
                st.markdown(f'<div class="diary">{html.escape(NAMES[partner])}의 일기가 아직 없어요.\n조금만 기다려볼까요? 🌷</div>', unsafe_allow_html=True)
            else:
                label = f"{NAMES[partner]}의 마음 · {other['mood']} · {stamp(other['updated_at'])}"
                st.markdown(f'<div class="tag">{html.escape(label)}</div><div class="diary">{html.escape(other["body"])}</div>', unsafe_allow_html=True)
                # 체크를 푸는 대신 명시적인 확인만 기록합니다. 이미 읽은 일기는 체크 고정.
                read = st.checkbox("확인했어요 💗", value=bool(other["read_at"]), disabled=bool(other["read_at"]), key=f"read_{key}_{other['version']}")
                if read and not other["read_at"]:
                    if mark_read(partner, day, other["version"]):
                        st.toast("상대에게 확인 표시를 남겼어요.", icon="💗")
                    else:
                        st.toast("일기가 갱신됐어요. 최신 내용을 확인해주세요.")
                    st.rerun(scope="fragment")
            st.caption("15초마다 자동 확인 · 수정하면 읽음 초기화")
        except psycopg.Error:
            st.warning("연결이 잠시 끊겼어요. 잠시 후 자동으로 다시 확인합니다.")
    shared_panel()


try:
    main()
except psycopg.Error:
    st.error("데이터베이스에 연결하지 못했어요. DATABASE_URL, 연결 허용 및 테이블 생성 권한을 확인한 뒤 다시 시도해주세요.")
    if st.button("다시 시도"):
        st.rerun()
