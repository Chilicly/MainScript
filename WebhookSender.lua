-- ========== 兼容层（纯 Lua 5.1 写法，不使用 Luau 专有语法）==========
local warn = warn or print
local sleep = (task and task.wait) or wait
local spawnFn = (task and task.spawn) or spawn or function(f) f() end

-- ========== 读取配置 ==========
local Config = (getgenv and getgenv().WebhookConfig) or {}
local HttpService = game:GetService("HttpService")

-- ========== 工具函数 ==========
-- 统计字符数（UTF-8 里不是 0x80-0xBF 的字节，才算一个字符的开头）
local function charLen(s)
    local _, continuation = s:gsub("[\128-\191]", "")
    return #s - continuation
end

-- 去掉首尾空白，并按「字符」截断（中文不会被截坏）
local function clean(s, n)
    s = tostring(s or ""):match("^%s*(.-)%s*$")
    local count = 0
    for i = 1, #s do
        local b = s:byte(i)
        if b < 128 or b > 191 then
            count = count + 1
            if count > n then
                return s:sub(1, i - 1)
            end
        end
    end
    return s
end

local DEFAULT_COLOR = 5814783

-- 颜色：支持数字，或十六进制字符串（"#FF0000" / "0xFF0000"）
local function parseColor(c)
    local n
    if type(c) == "number" then
        n = c
    elseif type(c) == "string" then
        n = tonumber((c:gsub("^#", ""):gsub("^0[xX]", "")), 16)
    end
    if not n or n ~= n then return DEFAULT_COLOR end
    n = math.floor(n)
    if n < 0 then n = 0 end
    if n > 0xFFFFFF then n = 0xFFFFFF end
    return n
end

-- 校验 Webhook URL 格式
local function isValidWebhookURL(u)
    local host, path = u:match("^https://([^/]+)(/.*)$")
    if not host then return false end
    local okHost = host == "discord.com" or host == "discordapp.com"
        or host:match("%.discord%.com$") ~= nil
        or host:match("%.discordapp%.com$") ~= nil
    return okHost and path:match("^/api/[%w/]*webhooks/%d+/[%w_%-]+") ~= nil
end

-- ========== 配置（没填的项使用默认值）==========
local webhookURL  = clean(Config.URL, 2000)
local avatar      = clean(Config.Avatar, 2000)
local content     = clean(Config.Content, 2000)
local title       = clean(Config.Title, 256)
local footerText  = clean(Config.Footer, 2048)
local color       = parseColor(Config.Color)
local description = clean(Config.Description, 4096)
-- embed 所有文字加起来不能超过 6000 字符，超出时缩短描述
description = clean(description, math.min(4096, 6000 - charLen(title) - charLen(footerText)))

local username = clean(Config.Username, 80)
if username == "" then username = "Webhook Sender" end

if not avatar:match("^https?://") then avatar = "" end -- 空或格式不对就不发送头像

local showTimestamp = Config.Timestamp == true

local times = math.floor(tonumber(Config.Times) or 1) -- 0 = 无限
if times < 0 then times = 1 end

local delayTime = math.max(1, tonumber(Config.Delay) or 3) -- 最小 1 秒，避免限速

local hasEmbed = title ~= "" or description ~= "" or footerText ~= ""

local requestFunc = (syn and syn.request) or (http and http.request)
    or http_request or request or (fluxus and fluxus.request)

-- ========== 发送函数 ==========
-- 返回：状态, 需要等待的秒数
-- 状态："ok" 成功 / "ratelimit" 被限速 / "fail" 失败
local function SendWebhook()
    local embed = { color = color }
    if title ~= "" then embed.title = title end
    if description ~= "" then embed.description = description end
    if footerText ~= "" then embed.footer = { text = footerText } end
    if showTimestamp then embed.timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ") end

    local data = { username = username }
    if avatar ~= "" then data.avatar_url = avatar end
    if content ~= "" then data.content = content end
    if hasEmbed then data.embeds = { embed } end

    local ok, jsonData = pcall(HttpService.JSONEncode, HttpService, data)
    if not ok then
        warn("JSON 编码失败: " .. tostring(jsonData))
        return "fail", 0
    end

    local success, response = pcall(requestFunc, {
        Url = webhookURL,
        Method = "POST",
        Headers = { ["Content-Type"] = "application/json" },
        Body = jsonData
    })
    if not success or not response then
        warn("请求出错: " .. tostring(response))
        return "fail", 0
    end

    local code = tonumber(response.StatusCode)
    if code == 200 or code == 204 or (code == nil and response.Success == true) then
        print("Webhook 发送成功")
        return "ok", 0
    end

    if code == 429 then
        local waitSec = tonumber(tostring(response.Body or ""):match('"retry_after"%s*:%s*([%d%.]+)')) or delayTime
        if waitSec < 1 then waitSec = 1 end
        warn("触发限速，等待 " .. waitSec .. " 秒后重试")
        return "ratelimit", waitSec
    end

    warn(("Webhook 发送失败 [%s]: %s"):format(tostring(code), clean(response.Body, 200)))
    return "fail", 0
end

-- ========== 循环发送 ==========
-- Times = 0 → 无限发送（任意一次发送失败就自动停止）
-- Times = 其他数字 → 发送指定次数后停止
local MAX_RATELIMIT_RETRIES = 5 -- 连续被限速超过这个次数，按失败处理

spawnFn(function()
    if not isValidWebhookURL(webhookURL) then
        warn("Webhook URL 未设置或格式不正确")
        return
    end
    if content == "" and not hasEmbed then
        warn("内容、标题、描述、页脚不能全部为空")
        return
    end
    if not requestFunc then
        warn("当前执行器不支持 HTTP 请求")
        return
    end

    local attempts, successCount, rlStreak = 0, 0, 0

    while times == 0 or attempts < times do
        local status, retryAfter = SendWebhook()

        if status == "ratelimit" and rlStreak < MAX_RATELIMIT_RETRIES then
            rlStreak = rlStreak + 1
            sleep(retryAfter) -- 限速：不计次数，等待后重试
        else
            rlStreak = 0
            attempts = attempts + 1
            if status == "ok" then
                successCount = successCount + 1
            elseif times == 0 then
                warn("发送失败，无限发送已自动停止")
                break
            end
            if times == 0 or attempts < times then
                sleep(delayTime)
            end
        end
    end

    print(("Webhook 发送结束：共尝试 %d 次，成功 %d 次"):format(attempts, successCount))
end)
