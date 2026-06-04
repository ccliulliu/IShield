# 复制为 config.py 后按需修改（config.py 已在 .gitignore 中）

# ── 语义检测 API ──────────────────────────────────────
API_PROVIDER = "local"  # local | deepseek | openai | dashscope
API_KEY = ""
API_BASE_URL = "https://api.deepseek.com/v1"
API_MODEL = "deepseek-chat"

# ── 沙箱配置 ──────────────────────────────────────────
SANDBOX_MODE = "mock"  # mock | real
SANDBOX_ROOT = "sandbox_files"

# ── 邮件沙箱（SANDBOX_MODE="real" 时填写真实 SMTP）──
EMAIL_HOST = "smtp.example.com"
EMAIL_PORT = 587
EMAIL_USER = ""
EMAIL_PASSWORD = ""
EMAIL_FROM = "ishield@localhost"
EMAIL_USE_TLS = True

# ── HTTP 沙箱（可选）──
# SANDBOX_ALLOWED_DOMAINS = {"httpbin.org", "api.github.com"}
