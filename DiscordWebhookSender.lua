-- ========== 读取配置 ==========
-- 作用：从 getgenv().WebhookConfig 读取用户设置的参数
-- 没有填写的项会使用默认值
local Config = getgenv().WebhookConfig or {}

local webhookURL   = Config.URL or ""                  -- Webhook 地址
local username     = Config.Username or "Discord Webhook Sender"     -- 发送者名字
local avatar       = Config.Avatar or ""               -- 发送者头像
local content      = Config.Content or ""              -- 普通文字内容（可@人）
local title        = Config.Title or ""        -- 标题
local description  = Config.Description or ""  -- 描述内容
local color        = Config.Color or 5814783           -- 颜色
local footerText   = Config.Footer or ""       -- 页脚文字
local showTimestamp = Config.Timestamp                 -- 是否显示时间戳
if showTimestamp == nil then showTimestamp = false end  -- 默认不显示
local times        = Config.Times or 1                 -- 发送次数（0 = 无限）
local delayTime    = Config.Delay or 3                 -- 每次发送间隔（秒）

-- ========== 发送函数 ==========
local function SendWebhook()
    local embed = {
        -- ========== 标题 ==========
        ["title"] = title,

        -- ========== 描述内容 ==========
        ["description"] = description,

        -- ========== 颜色 ==========
        ["color"] = color,

        -- ========== 页脚文字 ==========
        ["footer"] = {
            ["text"] = footerText
        }
    }

    -- ========== 时间戳 ==========
    -- 作用：显示在页脚旁边的时间
    if showTimestamp then
        embed["timestamp"] = os.date("!%Y-%m-%dT%H:%M:%SZ")
    end

    local data = {
        -- ========== 发送者名字 ==========
        ["username"] = username,

        -- ========== 发送者头像 ==========
        -- 作用：显示在消息左边的头像
        ["avatar_url"] = avatar,

        -- ========== 普通文字内容 ==========
        ["content"] = content,

        -- ========== Embeds ==========
        ["embeds"] = { embed }
    }

    local jsonData = game:GetService("HttpService"):JSONEncode(data)
    local requestFunc = (syn and syn.request) or (http and http.request) or http_request or request or (fluxus and fluxus.request)

    if requestFunc then
        local response = requestFunc({
            Url = webhookURL,
            Method = "POST",
            Headers = {
                ["Content-Type"] = "application/json"
            },
            Body = jsonData
        })

        if response and (response.StatusCode == 200 or response.StatusCode == 204) then
            print("Webhook 发送成功")
        else
            warn("Webhook 发送失败")
        end
    else
        warn("当前执行器不支持 HTTP 请求")
    end
end

-- ========== 循环发送 ==========
-- Times = 0 → 无限发送
-- Times = 其他数字 → 发送指定次数后停止
task.spawn(function()
    if webhookURL == "" then
        warn("未设置 Webhook URL")
        return
    end

    local count = 0

    while times == 0 or count < times do
        SendWebhook()
        count = count + 1

        if times == 0 or count < times then
            task.wait(delayTime)
        end
    end

    print("Webhook 发送结束，共发送 " .. count .. " 次")
end)