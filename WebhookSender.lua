-- ========== 兼容层（纯 Lua 5.1 写法，不使用 Luau 专有语法）==========
local warn = warn or print
local sleep = (task and task.wait) or wait
local spawnFn = (task and task.spawn) or spawn or function(f) f() end

-- ========== 读取配置 ==========
local Config = (getgenv and getgenv().WebhookConfig) or {}
local HttpService = game:GetService("HttpService")

-- ========== 工具函数 ==========
-- 按「真实字节数」截断，不是按字符数：中文一个字 3 字节，英文一个字 1 字节，
-- UTF-8 本身就是这样编码的，这里直接数字节，絶不会把一个字从中间切断
local function cleanBytes(s, maxBytes)
    s = tostring(s or ""):match("^%s*(.-)%s*$")
    if maxBytes <= 0 then return "" end
    if #s <= maxBytes then return s end

    local lastSafeEnd = 0
    local i = 1
    while i <= #s do
        local b = s:byte(i)
        local charBytes = 1
        if b >= 240 then charBytes = 4
        elseif b >= 224 then charBytes = 3
        elseif b >= 192 then charBytes = 2
        end
        local charEnd = i + charBytes - 1
        if charEnd > maxBytes then break end
        lastSafeEnd = charEnd
        i = charEnd + 1
    end
    return s:sub(1, lastSafeEnd)
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

-- ========== 配置（所有上限按「字节数」计算，而不是字符数，更保守、更不容易发送失败）==========
local webhookURL  = cleanBytes(Config.URL, 2000)
local avatar      = cleanBytes(Config.Avatar, 2000)
local content     = cleanBytes(Config.Content, 2000)   -- 全英文 2000 字，全中文约 666 字
local title       = cleanBytes(Config.Title, 256)      -- 全英文 256 字，全中文约 85 字
local footerText  = cleanBytes(Config.Footer, 2048)     -- 全英文 2048 字，全中文约 682 字
local color       = parseColor(Config.Color)

-- description 预算 = 6000 字节的 embed 总预算，减去 title、footer 已占用的字节
local descBudget  = math.min(4096, 6000 - #title - #footerText)
local description = cleanBytes(Config.Description, descBudget) -- 全中文时约封顶 2000 字

local username = cleanBytes(Config.Username, 80)
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

    if not requestFunc then
        warn("当前执行器不支持 HTTP 请求")
        return "fail", 0
    end

    local success, response = pcall(requestFunc, {
        Url = webhookURL,
        Method = "POST",
        Headers = { ["Content-Type"] = "application/json; charset=utf-8" },
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

    warn(("Webhook 发送失败 [%s]: %s"):format(tostring(code), cleanBytes(tostring(response.Body or ""), 200)))
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
