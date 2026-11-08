# 呼叫契約

客戶端請求這個 deployment 的任意 path。代理把同一個 method、path、query 轉到 `https://<target-host>`，port 443。

## Headers

請求要帶這三個 header。它們不會轉給上游。

- `X-DynamicForwardProxyVercel-Target-Host`：小寫 hostname
- `X-DynamicForwardProxyVercel-Timestamp`：Unix 秒
- `X-DynamicForwardProxyVercel-Signature`：HMAC-SHA256 的 64 字小寫 hex

簽章字串是 UTF-8，四行以 `\n` 連接：

```text
${timestamp}
${targetHost}
${METHOD}
${pathname}${search}
```

`METHOD` 是大寫。`pathname` 與 `search` 是請求 URL 的原始值，`search` 含 `?`，沒有 query 時是空字串。時間差超過 60 秒視為無效。不簽 body。

缺 header、時間無效或簽章不符回 401。名稱不合法回 400。不在 allowlist 回 403。`CONNECT` 與 `TRACE` 回 400。

## 環境變數

- `DYNAMIC_FORWARD_PROXY_HMAC_SECRET`：HMAC 密鑰。未設定時回 500。
- `DYNAMIC_FORWARD_PROXY_HMAC_SECRET_PREVIOUS`：可選。輪替時舊鑰仍可通過驗證。
- `DYNAMIC_FORWARD_PROXY_HOST_ALLOWLIST`：逗號分隔的小寫 hostname，只做全名比對。未設定或空的時候回 500。

Allowlist 不能放行 IP、localhost，或被名稱政策拒絕的內網 suffix。
