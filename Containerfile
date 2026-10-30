# audit-content sandbox image: one disposable microVM per check (Apple `container`).
# Built once by `audit-content setup`; every check runs it read-only with tmpfs scratch space.
FROM debian:trixie-slim

ARG CLAUDE_VERSION=stable
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq file xxd binutils 7zip python3 python3-venv nftables \
      chromium fonts-liberation fonts-dejavu-core \
      clamav clamav-freshclam yara \
      poppler-utils libimage-exiftool-perl \
      libreoffice-writer-nogui libreoffice-calc-nogui libreoffice-impress-nogui \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Analysis tools the agents may call (they are tools, not audit-content code).
RUN python3 -m venv /opt/tools \
 && /opt/tools/bin/pip install --no-cache-dir oletools pdfid \
 && ln -s /opt/tools/bin/olevba /opt/tools/bin/mraptor /opt/tools/bin/oleid \
          /opt/tools/bin/rtfobj /opt/tools/bin/pdfid /usr/local/bin/

# Signatures. They refresh only when the image is rebuilt (`audit-content setup --rebuild`).
RUN freshclam --foreground --stdout --quiet && rm -f /var/log/clamav/freshclam.log
RUN curl -fsSL -o /tmp/yf.zip \
      https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip \
 && mkdir -p /opt/rules && 7z e -o/tmp/yf /tmp/yf.zip '*.yar' -r >/dev/null \
 && yarac -w /tmp/yf/yara-rules-core.yar /opt/rules/core.yarc \
 && rm -rf /tmp/yf /tmp/yf.zip

# Claude Code CLI. Credentials never enter the image or the VM: the host proxy injects them.
RUN curl -fsSL https://claude.ai/install.sh | bash -s "$CLAUDE_VERSION" \
 && cp -L /root/.local/bin/claude /usr/local/bin/claude \
 && rm -rf /root/.local /root/.claude /root/.claude.json /root/.cache

# Keep Chromium quiet: no sign-in, sync, search preconnects, safe-browsing or component traffic, so every
# request the proxy records comes from the page under test.
RUN mkdir -p /etc/chromium/policies/managed && printf '%s' '{"BrowserSignin":0,"SyncDisabled":true,\
"DefaultSearchProviderEnabled":false,"NetworkPredictionOptions":2,"SearchSuggestEnabled":false,\
"SafeBrowsingProtectionLevel":0,"ComponentUpdatesEnabled":false,"MetricsReportingEnabled":false,\
"TranslateEnabled":false,"SpellCheckServiceEnabled":false,"PasswordManagerEnabled":false,\
"AutofillAddressEnabled":false,"AutofillCreditCardEnabled":false,"BackgroundModeEnabled":false,\
"UrlKeyedAnonymizedDataCollectionEnabled":false,"PromotionsEnabled":false,"MediaRouterCastAllowAllIPs":false,\
"EnableMediaRouter":false,"ShoppingListEnabled":false,"PrivacySandboxPromptEnabled":false}' \
    > /etc/chromium/policies/managed/audit-content.json

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin audit
COPY sandbox.py /opt/audit-content/sandbox.py
ENTRYPOINT ["python3", "-I", "/opt/audit-content/sandbox.py"]
