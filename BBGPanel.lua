-- ============================================================
--  BBG Panel  |  Soru Silent + ESP + AIM  |  Rayfield UI
-- ============================================================

-- ============================================================
--  ANTI-HOOK BOOTSTRAP  (BBG V7 Exact)
--  Captures C-closure references BEFORE any hooks can run.
-- ============================================================
local _SAFE = {}
do
    _SAFE.pcall        = pcall
    _SAFE.type         = type
    _SAFE.tostring     = tostring
    _SAFE.tonumber     = tonumber
    _SAFE.rawget       = rawget
    _SAFE.rawset       = rawset
    _SAFE.select       = select
    _SAFE.pairs        = pairs
    _SAFE.ipairs       = ipairs
    _SAFE.next         = next
    _SAFE.unpack       = unpack or table.unpack
    _SAFE.error        = error
    _SAFE.setmetatable = setmetatable
    _SAFE.getmetatable = getmetatable
    _SAFE.require      = require
    _SAFE.string_sub    = string.sub
    _SAFE.string_byte   = string.byte
    _SAFE.string_char   = string.char
    _SAFE.string_format = string.format
    _SAFE.string_len    = string.len
    _SAFE.string_find   = string.find
    _SAFE.string_rep    = string.rep
    _SAFE.string_lower  = string.lower
    _SAFE.string_upper  = string.upper
    _SAFE.string_gsub   = string.gsub
    _SAFE.string_match  = string.match
    _SAFE.string_gmatch = string.gmatch
    _SAFE.math_floor    = math.floor
    _SAFE.math_random   = math.random
    _SAFE.math_abs      = math.abs
    _SAFE.math_max      = math.max
    _SAFE.math_min      = math.min
    _SAFE.math_huge     = math.huge
    _SAFE.os_time       = os.time
    _SAFE.os_clock      = os.clock
    _SAFE.table_insert  = table.insert
    _SAFE.table_remove  = table.remove
    _SAFE.table_concat  = table.concat
    _SAFE.table_sort    = table.sort
    _SAFE.task_spawn    = task.spawn
    _SAFE.task_wait     = task.wait
    _SAFE.task_defer    = task.defer
    _SAFE.task_delay    = task.delay
    _SAFE.game          = game
    _SAFE.workspace     = workspace

    -- Executor API snapshots
    _SAFE.pcall(function()
        if getgenv         then _SAFE.getgenv         = getgenv         end
        if iscclosure      then _SAFE.iscclosure      = iscclosure      end
        if islclosure      then _SAFE.islclosure      = islclosure      end
        if getrawmetatable then _SAFE.getrawmetatable = getrawmetatable end
        if hookfunction    then _SAFE.hookfunction    = hookfunction    end
        if newcclosure     then _SAFE.newcclosure     = newcclosure     end
        if setreadonly     then _SAFE.setreadonly     = setreadonly     end
    end)

    -- Verify bootstrap integrity
    local _bootClean = true
    _SAFE.pcall(function()
        if _SAFE.iscclosure then
            local criticals = {
                _SAFE.pcall, _SAFE.type, _SAFE.tostring,
                _SAFE.rawget, _SAFE.pairs, _SAFE.ipairs,
                _SAFE.next,  _SAFE.select,
            }
            for _, fn in _SAFE.ipairs(criticals) do
                if not _SAFE.iscclosure(fn) then
                    _bootClean = false
                end
            end
        end
    end)

    if not _bootClean then
        warn("[BBG] Anti-hook: hooks detected at load time!")
    end

    if _SAFE.getgenv then _SAFE.getgenv()._SAFE = _SAFE end
end

-- ============================================================
--  BBG MODULE  (V7 Exact)
-- ============================================================
local Security = {}
do
    local _violations     = {}
    local _violationCount = 0
    local _degraded       = false
    local _scanCount      = 0

    local function _s(bytes)
        local chars = {}
        for i = 1, #bytes do chars[i] = string.char(bytes[i]) end
        return table.concat(chars)
    end

    local _STR = {
        namecall = _s({95,95,110,97,109,101,99,97,108,108}),
        C_source = _s({91,67,93}),
        request  = _s({114,101,113,117,101,115,116}),
    }

    local function _isHooked(func)
        if type(func) ~= "function" then return true end
        if iscclosure and not iscclosure(func) then return true end
        if islclosure and islclosure(func) then return true end
        if debug and debug.info then
            local s, source = pcall(debug.info, func, "s")
            if s and source and source ~= _STR.C_source then return true end
        end
        return false
    end

    local function _getCriticals()
        local list = {
            {pcall,    "pcall"},
            {type,     "type"},
            {tostring, "tostring"},
            {rawget,   "rawget"},
            {rawset,   "rawset"},
        }
        if string.sub  then table.insert(list, {string.sub,  "string.sub"})  end
        if string.byte then table.insert(list, {string.byte, "string.byte"}) end
        if os and os.time then table.insert(list, {os.time, "os.time"}) end
        pcall(function()
            local hs = game:GetService("HttpService")
            table.insert(list, {hs.JSONEncode, "JSONEncode"})
            table.insert(list, {hs.JSONDecode, "JSONDecode"})
        end)
        return list
    end

    function Security._recordViolation(cat, detail)
        _violationCount += 1
        table.insert(_violations, {category=cat, detail=detail or "", time=os.time()})
    end

    function Security.checkFunctionIntegrity()
        local violations = {}
        for _, item in ipairs(_getCriticals()) do
            if item[1] and _isHooked(item[1]) then
                table.insert(violations, item[2])
            end
        end
        return #violations == 0, violations
    end

    function Security._checkMetamethods()
        local clean = true
        pcall(function()
            if not getrawmetatable then return end
            local gameMt = getrawmetatable(game)
            if gameMt then
                local ncHook = rawget(gameMt, _STR.namecall)
                if ncHook and islclosure and islclosure(ncHook) then
                    clean = false
                end
            end
        end)
        return clean
    end

    function Security.runFullScan()
        _scanCount += 1
        local allClean = true
        local reasons  = {}
        local funcOk, funcViol = Security.checkFunctionIntegrity()
        if not funcOk then
            allClean = false
            for _, v in ipairs(funcViol) do
                Security._recordViolation("function_hooked", v)
                table.insert(reasons, "Hooked: "..v)
            end
        end
        if not Security._checkMetamethods() then
            allClean = false
            Security._recordViolation("metamethod_hooked", "Game metamethods tampered")
            table.insert(reasons, "Metamethod hook detected")
        end
        return allClean, reasons
    end

    function Security.isDegraded() return _degraded end
    function Security.getViolationCount() return _violationCount end

    local function _silentDegrade()
        if _degraded then return end
        _degraded = true
        task.spawn(function()
            task.wait(math.random(10, 30))
            pcall(function()
                if getgenv then getgenv().BBGShuttingDown = true end
            end)
        end)
    end

    -- Heartbeat scanner (45-120s intervals)
    function Security.startHeartbeat()
        task.spawn(function()
            task.wait(math.random(30, 60))
            while true do
                task.wait(math.random(45, 120))
                pcall(function()
                    if getgenv and getgenv().BBGShuttingDown then return end
                end)
                local clean, reasons = Security.runFullScan()
                if not clean and not _degraded then
                    _silentDegrade()
                end
            end
        end)
    end

    -- Start on load
    Security.startHeartbeat()
    print("[BBG] Security module active — heartbeat started")
end

-- ============================================================
--  SERVICES
-- ============================================================
local Rayfield          = loadstring(game:HttpGet("https://sirius.menu/rayfield"))()
local Players           = game:GetService("Players")
local RunService        = game:GetService("RunService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local UserInputService  = game:GetService("UserInputService")
local TweenService      = game:GetService("TweenService")
local Stats             = game:GetService("Stats")
local Camera            = workspace.CurrentCamera
local LP                = Players.LocalPlayer
local mouse             = LP:GetMouse()
local isMobile          = UserInputService.TouchEnabled and not UserInputService.KeyboardEnabled

-- ============================================================
--  LPH STUBS (prevent crash if not obfuscated)
-- ============================================================
if not LPH_OBFUSCATED then
    LPH_JIT           = function(...) return ... end
    LPH_NO_VIRTUALIZE = function(...) return ... end
end

-- ============================================================
--  REMOTE FINDER
-- ============================================================
local function getMainRemote()
    if ReplicatedStorage:FindFirstChild("MainEvent")  then return ReplicatedStorage.MainEvent  end
    if ReplicatedStorage:FindFirstChild("MAINEVENT")  then return ReplicatedStorage.MAINEVENT  end
    if ReplicatedStorage:FindFirstChild("Remote")     then return ReplicatedStorage.Remote     end
    if ReplicatedStorage:FindFirstChild("Bullets")    then return ReplicatedStorage.Bullets    end
    local mr = ReplicatedStorage:FindFirstChild("MainRemotes")
    if mr and mr:FindFirstChild("MainRemoteEvent") then return mr.MainRemoteEvent end
    local pkg = ReplicatedStorage:FindFirstChild("Packages")
    if pkg then
        local knit = pkg:FindFirstChild("Knit")
        if knit and knit:FindFirstChild("Services") then
            local ts = knit.Services:FindFirstChild("ToolService")
            if ts and ts:FindFirstChild("RE") then
                local re = ts.RE
                if re:FindFirstChild("UpdateAim") then return re.UpdateAim end
            end
        end
    end
    return nil
end
local MainEvent = getMainRemote()

-- ============================================================
--  BLOX FRUITS REMOTE (for Soru)
-- ============================================================
local bfRemote
pcall(function()
    bfRemote = ReplicatedStorage:FindFirstChild("Remotes")
               and ReplicatedStorage.Remotes:FindFirstChild("CommF_")
end)

-- ============================================================
--  STATE TABLE
-- ============================================================
local soruSilentEnabled = false
local cachedTarget   = nil   -- string player name

-- Sacred Red additions
local antiLavaActive      = false
local antiLavaConnection  = nil
local deleteShipActive    = false
local deleteShipRunning   = false
local NoCooldownEnabled   = false
local RajawareEliteEnabled= false
local RajawareLagEnabled  = false
local _RajawareGui        = nil
local _RajawareLagLoop    = nil  -- connection for continuous lag

local function stopRajawareLag()
    if _RajawareLagLoop then
        pcall(function() _RajawareLagLoop:Disconnect() end)
        _RajawareLagLoop = nil
    end
end

local function startRajawareLag()
    stopRajawareLag()
    
    local DROP_TO_FPS  = 20
    local INTERVAL     = 1 / DROP_TO_FPS
    
    _RajawareLagLoop = RunService.RenderStepped:Connect(function()
        if not RajawareLagEnabled then
            stopRajawareLag()
            return
        end
        -- Continuous FPS drop while toggle is ON
        local start = tick()
        while tick() - start < INTERVAL do end
    end)
end

local soruMaxDist    = 2000  -- default 2000 studs

local matchacc = {
    TargetAim = {
        Enabled              = false,
        Target               = "None",
        AutoSelect           = false,
        AutoFire             = false,
        Strafe               = false,
        ToggleStrafe         = false,
        VisualizeStrafe      = false,
        VisualizeStrafeInlineColor  = Color3.fromRGB(255,255,255),
        VisualizeStrafeOutlineColor = Color3.fromRGB(255,255,255),
        StrafeMethod         = "Randomize",
        StrafePrediction     = 0.1,
        Highlight            = false,
        HighlightOutlineColor= Color3.fromRGB(255,255,255),
        Tracer               = false,
        TracerPosition       = "Mouse",
        TracerFillColor      = Color3.fromRGB(255,255,255),
        TracerOutlineColor   = Color3.fromRGB(0,0,0),
        LookAt               = false,
        AutoStomp            = false,
        Prediction           = 0,
        AutoPredict          = false,
        PredictMode          = "Ping Sets",
        HitPart              = "Head",
        Offset               = 0,
        JumpOffset           = 0,
        AirPartEnabled       = false,
        AirPart              = "Head",
        Resolver             = false,
        Autokill             = false,
        DotCircle            = false,
        Spoofer              = false,
    },
    HitEffects = {
        HitSounds            = false,
        HitSoundID           = "rbxassetid://6534948092",
        HitSoundVolume       = 5,
        HitNotifications     = false,
        HitNotificationsTime = 3,
        HitChams = {
            Enabled     = false,
            Color       = Color3.fromRGB(255,255,255),
            Lifetime    = 3,
            Transparency= 0.7,
            Material    = "Neon",
        },
        HitSkeleton = {
            Enabled = false,
            Color   = Color3.fromRGB(255,255,255),
        },
    },
    Checks = {
        Wall        = false,
        Forcefield  = false,
        Alive       = false,
    },
    KillAura = {
        Enabled   = false,
        Active    = false,
        Range     = 250,
        Silent    = false,
        Visualize = false,
        StompAura = false,
        Whitelist = {},
    },
    HitboxExpander = {
        Enabled           = false,
        Visualize         = false,
        Color             = Color3.fromRGB(255,255,255),
        OutlineColor      = Color3.fromRGB(255,255,255),
        FillTransparency  = 0.5,
        OutlineTransparency= 0.3,
        Size              = 15,
    },
}

local oldVelPos          = {}
local previousPositions  = {}
local customVelocities   = {}
local VelocityData       = {}
local previousTargetHealth = {}
local M1Down             = false
local lastHealth         = nil
local lastTarget_name    = nil
local ka_lastHealth      = {}
local t_stomp            = 0
local TargetAimActive    = false

-- ============================================================
--  DRAWINGS
-- ============================================================
local DotCircle = Drawing.new("Circle")
DotCircle.Visible     = false
DotCircle.Filled      = true
DotCircle.Radius      = 5
DotCircle.Thickness   = 1.5
DotCircle.Color       = Color3.fromRGB(255,255,255)
DotCircle.Transparency= 1

-- ── FOV Circle (Matcha style — fixed screen center, nahi hilta slide se) ──
local FOVCircleEnabled  = false
local FOVCircleSize     = 300
local FOVInnerColor     = Color3.fromRGB(255, 255, 255)
local GradientFillEnabled = false
local GradientColor1    = Color3.fromRGB(255, 255, 255)
local GradientColor2    = Color3.fromRGB(0, 0, 0)
local FOVFillTransparency = 0.5

local InnerCircle = Drawing.new("Circle")
InnerCircle.Visible      = false
InnerCircle.Thickness    = 1
InnerCircle.NumSides     = 64
InnerCircle.Filled       = false
InnerCircle.Color        = FOVInnerColor
InnerCircle.Radius       = FOVCircleSize
InnerCircle.ZIndex       = 10001

local FillCircle = Drawing.new("Circle")
FillCircle.Visible       = false
FillCircle.Filled        = true
FillCircle.Transparency  = FOVFillTransparency
FillCircle.NumSides      = 64
FillCircle.Radius        = FOVCircleSize
FillCircle.Color         = GradientColor1
FillCircle.ZIndex        = 10001

-- FOV update loop — ALWAYS screen center (mobile + PC dono pe slide nahi karega)
RunService.RenderStepped:Connect(function()
    if FOVCircleEnabled then
        local center = Vector2.new(Camera.ViewportSize.X / 2, Camera.ViewportSize.Y / 2)
        InnerCircle.Position = center
        FillCircle.Position  = center
        if GradientFillEnabled then
            local t = math.sin(tick() * 2) * 0.5 + 0.5
            local r = GradientColor1.R + (GradientColor2.R - GradientColor1.R) * t
            local g = GradientColor1.G + (GradientColor2.G - GradientColor1.G) * t
            local b = GradientColor1.B + (GradientColor2.B - GradientColor1.B) * t
            FillCircle.Color = Color3.new(r, g, b)
        end
    end
end)


local tracerOutline = Drawing.new("Line")
tracerOutline.Visible    = false
tracerOutline.Color      = matchacc.TargetAim.TracerOutlineColor
tracerOutline.Thickness  = 4

local tracer = Drawing.new("Line")
tracer.Visible   = false
tracer.Color     = matchacc.TargetAim.TracerFillColor
tracer.Thickness = 2

local DesyncLine = Drawing.new("Line")
DesyncLine.Thickness   = 2
DesyncLine.Color       = Color3.fromRGB(255,255,255)
DesyncLine.Visible     = false
DesyncLine.Transparency= 1

-- ============================================================
--  BODY CLONE (Desync visualizer)
-- ============================================================
local BodyClone = game:GetObjects("rbxassetid://8246626421")[1]
BodyClone.Parent = workspace
BodyClone.Humanoid:Destroy()
BodyClone.Head.Face:Destroy()
for _, v in pairs(BodyClone:GetDescendants()) do
    if v:IsA("BasePart") or v:IsA("MeshPart") then
        v.CanCollide  = false
        v.Transparency= 1
    end
end
BodyClone.HumanoidRootPart.Transparency = 1
BodyClone.HumanoidRootPart.Velocity     = Vector3.zero
BodyClone.HumanoidRootPart.CFrame       = CFrame.new(9999,9999,9999)

local BodyCloneHighlight = Instance.new("Highlight")
BodyCloneHighlight.Enabled             = false
BodyCloneHighlight.DepthMode           = Enum.HighlightDepthMode.AlwaysOnTop
BodyCloneHighlight.FillColor           = Color3.fromRGB(0,255,0)
BodyCloneHighlight.OutlineColor        = Color3.fromRGB(255,255,255)
BodyCloneHighlight.FillTransparency    = 0.3
BodyCloneHighlight.OutlineTransparency = 0
BodyCloneHighlight.Adornee             = BodyClone
BodyCloneHighlight.Parent              = BodyClone

local ka_tracer = Instance.new("Part")
ka_tracer.Size        = Vector3.new(0.2,0.2,0.2)
ka_tracer.Material    = Enum.Material.Neon
ka_tracer.Color       = Color3.fromRGB(255,255,255)
ka_tracer.Transparency= 1
ka_tracer.Anchored    = true
ka_tracer.CanCollide  = false
ka_tracer.Parent      = workspace

-- ============================================================
--  HELPER FUNCTIONS
-- ============================================================
local function SetRigTransparency(clone, trans)
    for _, v in pairs(clone:GetDescendants()) do
        if v:IsA("BasePart") or v:IsA("MeshPart") then v.Transparency = trans end
    end
end

local function SetRigColor(clone, color)
    for _, v in pairs(clone:GetDescendants()) do
        if v:IsA("BasePart") or v:IsA("MeshPart") then v.Color = color end
    end
end

local function isAlive(plr)
    if not plr or not plr.Character then return false end
    local hum = plr.Character:FindFirstChildOfClass("Humanoid")
    return hum and hum.Health > 0
end

local function KnockCheck(plr)
    if plr and plr.Character and plr.Character:FindFirstChild("BodyEffects") then
        local ko = plr.Character.BodyEffects:FindFirstChild("K.O")
        return ko and ko.Value or false
    end
    return false
end

local function isPlayerVisible(player)
    if not player.Character or not player.Character:FindFirstChild("Head") then return false end
    local head = player.Character.Head
    local origin = Camera.CFrame.Position
    local direction = (head.Position - origin).Unit * (head.Position - origin).Magnitude
    local rp = RaycastParams.new()
    rp.FilterDescendantsInstances = {LP.Character}
    rp.FilterType = Enum.RaycastFilterType.Blacklist
    local result = workspace:Raycast(origin, direction, rp)
    return not result or result.Instance:IsDescendantOf(player.Character)
end

local function getPlayerList()
    local list = {}
    for _, pl in pairs(Players:GetPlayers()) do
        if pl ~= LP then table.insert(list, pl.Name) end
    end
    if #list == 0 then list = {"No players"} end
    return list
end

local function GetClosestCharacter()
    local closestDist   = math.huge
    local closestPlayer = nil
    local mousePos
    if isMobile then
        mousePos = Vector2.new(Camera.ViewportSize.X/2, Camera.ViewportSize.Y/2)
    else
        mousePos = UserInputService:GetMouseLocation()
    end
    for _, player in pairs(Players:GetPlayers()) do
        if player == LP then continue end
        local char = player.Character
        if not char or not char:FindFirstChild("Head") or not char:FindFirstChild("HumanoidRootPart") then continue end
        if not isAlive(player) and matchacc.Checks.Alive then continue end
        if matchacc.Checks.Forcefield and player.Character:FindFirstChildWhichIsA("ForceField") then continue end
        local headPos, onScreen = Camera:WorldToViewportPoint(char.Head.Position)
        local screenPos = Vector2.new(headPos.X, headPos.Y)
        local dist = (screenPos - mousePos).Magnitude
        if FOVCircleEnabled and dist > FOVCircleSize then continue end
        local isVisible = true
        if matchacc.Checks.Wall then
            local rp = RaycastParams.new()
            rp.FilterDescendantsInstances = {LP.Character}
            rp.FilterType = Enum.RaycastFilterType.Blacklist
            local res = workspace:Raycast(Camera.CFrame.Position, char.Head.Position - Camera.CFrame.Position, rp)
            if res and res.Instance and not res.Instance:IsDescendantOf(char) then isVisible = false end
        end
        if onScreen and isVisible and dist < closestDist then
            closestDist   = dist
            closestPlayer = player
        end
    end
    return closestPlayer
end

local function createHitSound()
    pcall(function()
        local sound = Instance.new("Sound")
        sound.Parent   = LP.Character.HumanoidRootPart
        sound.SoundId  = matchacc.HitEffects.HitSoundID
        sound.Volume   = matchacc.HitEffects.HitSoundVolume
        sound:Play()
        sound.Ended:Connect(function() sound:Destroy() end)
    end)
end

local HitChams = LPH_NO_VIRTUALIZE(function(Player)
    if not matchacc.HitEffects.HitChams.Enabled then return end
    if not (Player and Player.Character and Player.Character:FindFirstChild("HumanoidRootPart")) then return end
    Player.Character.Archivable = true
    local Cloned = Player.Character:Clone()
    Cloned.Name = "BBGClone"
    local validParts = {"Head","UpperTorso","LowerTorso","LeftUpperArm","LeftLowerArm","LeftHand","RightUpperArm","RightLowerArm","RightHand","LeftUpperLeg","LeftLowerLeg","LeftFoot","RightUpperLeg","RightLowerLeg","RightFoot"}
    for _, Part in ipairs(Cloned:GetChildren()) do
        if Part:IsA("BasePart") then
            local valid = false
            for _, vp in ipairs(validParts) do if Part.Name == vp then valid = true break end end
            if not valid then Part:Destroy() end
        elseif Part:IsA("Accessory") or Part:IsA("Tool") or Part.Name=="face" or Part:IsA("Shirt") or Part:IsA("Pants") or Part:IsA("Hat") then
            Part:Destroy()
        end
    end
    if Cloned:FindFirstChild("Humanoid") then Cloned.Humanoid:Destroy() end
    for _, bp in ipairs(Cloned:GetChildren()) do
        if bp:IsA("BasePart") then
            bp.CanCollide  = false
            bp.Anchored    = true
            bp.Transparency= matchacc.HitEffects.HitChams.Transparency
            bp.Color       = matchacc.HitEffects.HitChams.Color
            bp.Material    = matchacc.HitEffects.HitChams.Material
        end
    end
    local head = Cloned:FindFirstChild("Head")
    if head then
        head.Transparency = matchacc.HitEffects.HitChams.Transparency
        head.Color    = matchacc.HitEffects.HitChams.Color
        head.Material = matchacc.HitEffects.HitChams.Material
        if head:FindFirstChild("face") then head.face:Destroy() end
    end
    Cloned.Parent = workspace
    local ti = TweenInfo.new(matchacc.HitEffects.HitChams.Lifetime, Enum.EasingStyle.Sine, Enum.EasingDirection.InOut, 0, true)
    for _, bp in ipairs(Cloned:GetChildren()) do
        if bp:IsA("BasePart") then TweenService:Create(bp, ti, {Transparency=1}):Play() end
    end
    task.delay(matchacc.HitEffects.HitChams.Lifetime, function()
        if Cloned and Cloned.Parent then Cloned:Destroy() end
    end)
end)

-- ============================================================
--  PING PREDICTION TABLE
-- ============================================================
local PingPredTable = {
    [50]=0.1433,[55]=0.1412,[60]=0.1389,[65]=0.1367,[70]=0.1346,
    [75]=0.1324,[80]=0.1303,[85]=0.1282,[90]=0.1261,[95]=0.1240,
    [100]=0.1219,[110]=0.1177,[120]=0.1136,[130]=0.1095,[140]=0.1055,
    [150]=0.1015,[160]=0.0975,[170]=0.0936,[180]=0.0897,[190]=0.0859,
    [200]=0.0821,[210]=0.0783,[220]=0.0746,[230]=0.0710,[240]=0.0674,
    [250]=0.0638,[260]=0.0603,[270]=0.0568,[280]=0.0534,[290]=0.0500,
}
local currentPred = 0.13
task.spawn(function()
    while true do
        pcall(function()
            local ping = Stats.Network.ServerStatsItem["Data Ping"]:GetValue()
            local closest, minDiff = 100, math.huge
            for p in pairs(PingPredTable) do
                local d = math.abs(p - ping)
                if d < minDiff then minDiff=d; closest=p end
            end
            currentPred = PingPredTable[closest] or 0.13
        end)
        task.wait(0.3)
    end
end)

-- ============================================================
--  METATABLE HOOK  (Soru Silent+ AIM mouse.Hit)
-- ============================================================
local mt       = getrawmetatable(game)
local oldIndex = mt.__index
setreadonly(mt, false)

mt.__index = newcclosure(function(self, key)
    if self == mouse and (key == "Hit" or key == "Target") then
        -- Soru Silent (Sacred Soru distance logic + sorusilent redirect)
        if soruSilentEnabled and cachedTarget then
            local target = Players:FindFirstChild(cachedTarget)
            local eHRP = target and target.Character and target.Character:FindFirstChild("HumanoidRootPart")
            if eHRP then
                local myChar = LP.Character
                local myHRP  = myChar and myChar:FindFirstChild("HumanoidRootPart")
                -- Sacred Soru style: compute actual stud distance, only redirect if within limit
                if myHRP then
                    local dist = (eHRP.Position - myHRP.Position).Magnitude
                    if dist <= soruMaxDist then
                        if key == "Hit" then return CFrame.new(eHRP.Position)
                        elseif key == "Target" then return eHRP end
                    end
                end
            end
        end
        -- Silent Aim mouse.Hit override (sword/melee/fruit visual fix)
        if SA_Enabled and SA_Playersaimbot ~= nil and SA_PlayersPosition ~= nil then
            local tp = Players:FindFirstChild(SA_Playersaimbot)
            if tp and tp.Character then
                local tPart = tp.Character:FindFirstChild("Head")
                           or tp.Character:FindFirstChild("HumanoidRootPart")
                if tPart then
                    if key == "Hit"    then return CFrame.new(SA_PlayersPosition) end
                    if key == "Target" then return tPart end
                end
            end
        end
        -- AIM (Matcha-style) mouse.Hit override
        if matchacc.TargetAim.Enabled and matchacc.TargetAim.Target ~= "None" and LP.Character and LP.Character:FindFirstChild("HumanoidRootPart") then
            local TargetPlayer = Players:FindFirstChild(matchacc.TargetAim.Target)
            if TargetPlayer and TargetPlayer.Character and TargetPlayer.Character:FindFirstChildOfClass("Humanoid") and TargetPlayer.Character:FindFirstChildOfClass("Humanoid").Health > 0 and not TargetPlayer.Character:FindFirstChild("ForceField") then
                if matchacc.Checks.Forcefield and TargetPlayer.Character:FindFirstChildWhichIsA("ForceField") then return oldIndex(self, key) end
                local partName = matchacc.TargetAim.HitPart
                if matchacc.TargetAim.AirPartEnabled then
                    local tState = TargetPlayer.Character.Humanoid:GetState()
                    if tState == Enum.HumanoidStateType.Freefall or tState == Enum.HumanoidStateType.Jumping then
                        partName = matchacc.TargetAim.AirPart
                    end
                end
                local targetPart = TargetPlayer.Character:FindFirstChild(partName)
                if targetPart then
                    local vel = (VelocityData[TargetPlayer] and VelocityData[TargetPlayer].Velocity) or targetPart.AssemblyLinearVelocity
                    local pred = matchacc.TargetAim.Prediction
                    if matchacc.TargetAim.AutoPredict then
                        if matchacc.TargetAim.PredictMode == "Ping Sets" then
                            pred = currentPred
                        elseif matchacc.TargetAim.PredictMode == "Calculate" then
                            local ping = 0
                            pcall(function() ping = Stats.Network.ServerStatsItem["Data Ping"]:GetValue()/1000 end)
                            pred = 0.0368 + ping
                        end
                    end
                    if matchacc.TargetAim.Resolver then pred = pred + 0.015 end
                    local yOff = matchacc.TargetAim.Offset
                    pcall(function()
                        if TargetPlayer.Character.Humanoid:GetState() == Enum.HumanoidStateType.Freefall or vel.Y > 20 then
                            yOff = matchacc.TargetAim.JumpOffset
                        end
                    end)
                    local predictedPos = targetPart.Position + (vel * pred) + Vector3.new(0, yOff, 0)
                    if key == "Hit"    then return CFrame.new(Camera.CFrame.Position, predictedPos) end
                    if key == "Target" then return targetPart end
                end
            end
        end
    end
    return oldIndex(self, key)
end)

setreadonly(mt, true)

-- ============================================================
--  VELOCITY TRACKER
-- ============================================================
RunService.Heartbeat:Connect(function(dT)
    if dT > 0.5 then return end
    for _, plr in Players:GetPlayers() do
        if plr.Character and plr.Character:FindFirstChild("HumanoidRootPart") then
            local hrp = plr.Character.HumanoidRootPart
            if not VelocityData[plr] then VelocityData[plr] = {PreviousPosition=hrp.Position, Velocity=Vector3.zero} end
            local data = VelocityData[plr]
            data.Velocity       = (hrp.Position - data.PreviousPosition) / dT
            data.PreviousPosition = hrp.Position
        end
    end
end)
Players.PlayerRemoving:Connect(function(plr) VelocityData[plr] = nil end)

-- ============================================================
--  DOTCIRCLE UPDATE
-- ============================================================
RunService.RenderStepped:Connect(function()
    -- DotCircle update
    if matchacc.TargetAim.Enabled and matchacc.TargetAim.Target ~= "None" then
        local tp = Players:FindFirstChild(matchacc.TargetAim.Target)
        if tp and tp.Character then
            local hitPart = tp.Character:FindFirstChild(matchacc.TargetAim.HitPart)
            if hitPart and matchacc.TargetAim.DotCircle then
                local vel  = (VelocityData[tp] and VelocityData[tp].Velocity) or hitPart.AssemblyLinearVelocity
                local pred = matchacc.TargetAim.AutoPredict and currentPred or matchacc.TargetAim.Prediction
                local screenPos, onScreen = Camera:WorldToViewportPoint(hitPart.Position + vel * pred)
                if onScreen then
                    DotCircle.Position = Vector2.new(screenPos.X, screenPos.Y)
                    DotCircle.Visible  = true
                else
                    DotCircle.Visible  = false
                end
            else
                DotCircle.Visible = false
            end
        else
            DotCircle.Visible = false
        end
    else
        DotCircle.Visible = false
    end
end)

-- ============================================================
--  M1 TRACKING
-- ============================================================
UserInputService.InputBegan:Connect(function(input, gp)
    if gp then return end
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        M1Down = true
    end
end)
UserInputService.InputEnded:Connect(function(input, gp)
    if gp then return end
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        M1Down = false
    end
end)

-- ============================================================
--  AIM HEARTBEAT (Strafe, AutoKill, KillAura, Tracers, HitEffects)
-- ============================================================
RunService.Heartbeat:Connect(function(dt)
    TargetAimActive = false
    local hrp = LP.Character and LP.Character:FindFirstChild("HumanoidRootPart")
    local Tool = LP.Character and LP.Character:FindFirstChildOfClass("Tool")
    local SavedPosition = hrp and hrp.CFrame

    -- Hit Effects detection
    if matchacc.TargetAim.Enabled and matchacc.TargetAim.Target ~= "None" then
        local tp = Players:FindFirstChild(matchacc.TargetAim.Target)
        if tp and tp.Character and tp.Character:FindFirstChildOfClass("Humanoid") then
            local hum = tp.Character:FindFirstChildOfClass("Humanoid")
            local curr = math.round(hum.Health)
            local prev = previousTargetHealth[tp.Name]
            if prev ~= nil and curr < prev then
                if matchacc.HitEffects.HitSounds       then createHitSound() end
                if matchacc.HitEffects.HitNotifications then
                    Rayfield:Notify({Title="BBG AIM",Content="Hit: "..tp.Name.." HP:"..curr,Duration=matchacc.HitEffects.HitNotificationsTime})
                end
                if matchacc.HitEffects.HitChams.Enabled then HitChams(tp) end
            end
            previousTargetHealth[tp.Name] = curr
        end
    end

    if not hrp then return end

    -- Tracer update
    if matchacc.TargetAim.Enabled and matchacc.TargetAim.Target ~= "None" and matchacc.TargetAim.Tracer then
        local tp = Players:FindFirstChild(matchacc.TargetAim.Target)
        if tp and tp.Character and tp.Character:FindFirstChild("Head") then
            local headSP, onScreen = Camera:WorldToViewportPoint(tp.Character.Head.Position)
            if onScreen then
                local fromPos = UserInputService:GetMouseLocation()
                if matchacc.TargetAim.TracerPosition == "Tool" and Tool and Tool:FindFirstChild("Handle") then
                    local sp = Camera:WorldToViewportPoint(Tool.Handle.Position)
                    fromPos = Vector2.new(sp.X, sp.Y)
                end
                tracer.From        = fromPos
                tracerOutline.From = fromPos
                tracer.To          = Vector2.new(headSP.X, headSP.Y)
                tracerOutline.To   = Vector2.new(headSP.X, headSP.Y)
                tracer.Visible     = true
                tracerOutline.Visible = true
                tracer.Color       = matchacc.TargetAim.TracerFillColor
                tracerOutline.Color= matchacc.TargetAim.TracerOutlineColor
            else
                tracer.Visible = false; tracerOutline.Visible = false
            end
        end
    else
        tracer.Visible = false; tracerOutline.Visible = false
    end

    -- Strafe + AutoFire
    if matchacc.TargetAim.Strafe and matchacc.TargetAim.Target ~= "None" then
        local tp = Players:FindFirstChild(matchacc.TargetAim.Target)
        if tp and tp.Character and tp.Character:FindFirstChild("Head") and not tp.Character:FindFirstChild("ForceField") then
            if not KnockCheck(tp) then
                TargetAimActive = true
                local currentPos = tp.Character.Head.Position
                local lastPos    = previousPositions[tp] or currentPos
                local estVel     = (currentPos - lastPos) / dt
                local alpha      = 0.5
                customVelocities[tp] = (customVelocities[tp] or Vector3.zero)*alpha + estVel*(1-alpha)
                previousPositions[tp] = currentPos
                local strafeOffset
                if matchacc.TargetAim.StrafeMethod == "Orbit" then
                    strafeOffset = Vector3.new(math.cos(tick()*10)*10, 0, math.sin(tick()*10)*10)
                else
                    strafeOffset = Vector3.new(math.random(-15,15), math.random(-15,15), math.random(-15,15))
                end
                local desyncPos = currentPos + (customVelocities[tp] * matchacc.TargetAim.StrafePrediction) + strafeOffset
                hrp.CFrame = CFrame.lookAt(desyncPos, currentPos)
                if matchacc.TargetAim.Spoofer then
                    RunService:BindToRenderStep("RestoreStrafe",199,function()
                        hrp.CFrame = SavedPosition
                        RunService:UnbindFromRenderStep("RestoreStrafe")
                    end)
                end
                if matchacc.TargetAim.VisualizeStrafe then
                    BodyClone:SetPrimaryPartCFrame(hrp.CFrame)
                    BodyCloneHighlight.Enabled = true
                    SetRigTransparency(BodyClone, 0)
                    SetRigColor(BodyClone, matchacc.TargetAim.VisualizeStrafeInlineColor)
                    BodyCloneHighlight.FillColor    = matchacc.TargetAim.VisualizeStrafeInlineColor
                    BodyCloneHighlight.OutlineColor = matchacc.TargetAim.VisualizeStrafeOutlineColor
                else
                    BodyCloneHighlight.Enabled = false
                    BodyClone:SetPrimaryPartCFrame(CFrame.new(9999,9999,9999))
                    SetRigTransparency(BodyClone, 1)
                end
                if Tool and MainEvent then
                    local predictedPos = currentPos + (customVelocities[tp] * matchacc.TargetAim.StrafePrediction)
                    local args = {"ShootGun", Tool:FindFirstChild("Handle"), Tool:FindFirstChild("Handle") and Tool.Handle.Position or Vector3.zero, predictedPos, tp.Character.Head, Vector3.zero}
                    if (matchacc.TargetAim.AutoFire or M1Down) and Tool:FindFirstChild("Handle") then
                        MainEvent:FireServer(unpack(args))
                    end
                end
            end
        end
    else
        if not matchacc.KillAura.Active then
            BodyClone:SetPrimaryPartCFrame(CFrame.new(9999,9999,9999))
            BodyCloneHighlight.Enabled = false
        end
    end

    -- AutoStomp
    if matchacc.TargetAim.AutoStomp and matchacc.TargetAim.Target ~= "None" then
        local tp = Players:FindFirstChild(matchacc.TargetAim.Target)
        if tp and KnockCheck(tp) and MainEvent then
            local be = tp.Character and tp.Character:FindFirstChild("BodyEffects")
            local isDead = be and be:FindFirstChild("SDeath") and be.SDeath.Value
            if isDead == false then
                hrp.CFrame = CFrame.new(tp.Character.UpperTorso.Position + Vector3.new(0,3,0))
                RunService:BindToRenderStep("RestoreStomp",199,function()
                    hrp.CFrame = SavedPosition
                    RunService:UnbindFromRenderStep("RestoreStomp")
                end)
                MainEvent:FireServer("Stomp")
            end
        end
    end

    -- Kill Aura
    if matchacc.KillAura.Enabled and matchacc.KillAura.Active and Tool and Tool:FindFirstChild("Handle") then
        local closest, ka_target = math.huge, nil
        for _, player in pairs(Players:GetPlayers()) do
            if player ~= LP and not matchacc.KillAura.Whitelist[player.Name] and player.Character and player.Character:FindFirstChild("Head") then
                if not KnockCheck(player) and isAlive(player) then
                    local dist = (hrp.Position - player.Character.Head.Position).Magnitude
                    if dist < closest and dist <= matchacc.KillAura.Range then
                        closest = dist; ka_target = player
                    end
                end
            end
        end
        if ka_target and ka_target.Character and ka_target.Character:FindFirstChild("Head") then
            hrp.CFrame = CFrame.lookAt(hrp.Position, ka_target.Character.Head.Position)
            if matchacc.KillAura.Visualize then
                ka_tracer.Transparency = 0
                ka_tracer.Size  = Vector3.new(0.2,0.2,(hrp.Position-ka_target.Character.Head.Position).Magnitude)
                ka_tracer.CFrame= CFrame.lookAt(hrp.Position, ka_target.Character.Head.Position)*CFrame.new(0,0,-ka_tracer.Size.Z/2)
            else
                ka_tracer.Transparency = 1
            end
            local offset = matchacc.KillAura.Silent and Vector3.new(0,-12,0) or Vector3.zero
            if MainEvent then
                MainEvent:FireServer("ShootGun", Tool.Handle, Tool.Handle.CFrame.Position+offset, ka_target.Character.Head.Position+offset, ka_target.Character.Head, Vector3.new(0,0,-1))
            end
        else
            ka_tracer.Transparency = 1
        end
    end

    -- AutoKill
    if matchacc.TargetAim.Autokill and matchacc.TargetAim.Target ~= "None" and not matchacc.TargetAim.Strafe then
        local tp = Players:FindFirstChild(matchacc.TargetAim.Target)
        if tp and tp.Character and LP.Character then
            local tHead = tp.Character:FindFirstChild("Head")
            if tHead and Tool and Tool:FindFirstChild("Handle") and MainEvent then
                if not KnockCheck(tp) and not tp.Character:FindFirstChild("ForceField") then
                    hrp.CFrame = CFrame.lookAt(tp.Character.Head.Position + Vector3.new(math.random(-15,15),math.random(-15,15),math.random(-15,15)), tp.Character.Head.Position)
                    MainEvent:FireServer("ShootGun", Tool.Handle, Tool.Handle.Position, tp.Character.Head.Position, tHead, Vector3.new(0,1,0))
                    if matchacc.TargetAim.Spoofer then
                        RunService:BindToRenderStep("RestoreAK",199,function()
                            hrp.CFrame = SavedPosition
                            RunService:UnbindFromRenderStep("RestoreAK")
                        end)
                    end
                end
            end
        end
    end
end)

-- ============================================================
--  HITBOX EXPANDER LOOP
-- ============================================================
RunService.Heartbeat:Connect(function()
    if not matchacc.HitboxExpander.Enabled then return end
    for _, player in pairs(Players:GetPlayers()) do
        if player == LP then continue end
        local char = player.Character
        if not char then continue end
        local hrpTarget = char:FindFirstChild("HumanoidRootPart")
        if not hrpTarget then continue end
        hrpTarget.Size = Vector3.new(matchacc.HitboxExpander.Size, matchacc.HitboxExpander.Size, matchacc.HitboxExpander.Size)
    end
end)

-- ============================================================
--  RAYFIELD WINDOW
-- ============================================================
local Window = Rayfield:CreateWindow({
    Name            = "BBG Panel",
    LoadingTitle    = "AHK Mobile",
    LoadingSubtitle = "By BBG",
    ConfigurationSaving = {Enabled = false},
    KeySystem       = false,
})

-- Discord link label (BBG Panel title ke neeche)
local DiscordTab = Window:CreateTab("Discord", 4483362458)
DiscordTab:CreateSection("BBG Community")
DiscordTab:CreateLabel("discord.gg/abhtkBceun")
DiscordTab:CreateButton({
    Name     = "Copy Discord Link",
    Callback = function()
        setclipboard("https://discord.gg/abhtkBceun")
        Rayfield:Notify({
            Title    = "BBG Panel",
            Content  = "Discord link copied!",
            Duration = 3,
        })
    end,
})

-- ============================================================
--  TAB 1: SORU SILENT (unchanged)
-- ============================================================
local SoruTab = Window:CreateTab("Soru", 4483362458)

-- Target section first
SoruTab:CreateSection("Target")

local _soruPlayerList = {"None"}
for _, p in ipairs(Players:GetPlayers()) do
    if p ~= LP then table.insert(_soruPlayerList, p.Name) end
end

local SoruPlayerDropdown = SoruTab:CreateDropdown({
    Name            = "Select Target",
    Options         = _soruPlayerList,
    CurrentOption   = {"None"},
    MultipleOptions = false,
    Flag            = "Soru_TargetDrop",
    Callback        = function(v)
        local sel = type(v) == "table" and v[1] or v
        cachedTarget = (sel == "None") and nil or sel
    end,
})

SoruTab:CreateButton({
    Name     = "Refresh Player List",
    Callback = function()
        local newList = {"None"}
        for _, p in ipairs(Players:GetPlayers()) do
            if p ~= LP then table.insert(newList, p.Name) end
        end
        SoruPlayerDropdown:Refresh(newList, true)
        Rayfield:Notify({Title="Soru Silent", Content="Player list refreshed", Duration=2})
    end,
})

-- Soru Silent ON/OFF (button, not toggle) + mini window toggle
SoruTab:CreateSection("Soru Silent")

SoruTab:CreateToggle({
    Name         = "Soru Silent",
    CurrentValue = false,
    Flag         = "SoruSilent_Main",
    Callback     = function(v)
        soruSilentEnabled = v
        Rayfield:Notify({
            Title   = "Soru Silent",
            Content = v and "Soru Silent ON" or "Soru Silent OFF",
            Duration= 2,
        })
    end,
})

SoruTab:CreateToggle({
    Name         = "Soru Silent Window",
    CurrentValue = false,
    Flag         = "SoruSilent_Window",
    Callback     = function(v)
        if _SoruMiniGui then
            _SoruMiniGui.Enabled = v
        end
    end,
})

-- Distance
SoruTab:CreateSection("Distance")

SoruTab:CreateSlider({
    Name         = "Max Distance",
    Range        = {100, 2000},
    Increment    = 50,
    Suffix       = " studs",
    CurrentValue = 2000,
    Flag         = "Soru_MaxDist",
    Callback     = function(v)
        soruMaxDist = v
    end,
})

-- Infinity Soru
SoruTab:CreateSection("Infinity Soru")

SoruTab:CreateToggle({
    Name         = "Infinite Soru",
    CurrentValue = false,
    Flag         = "Soru_InfSoru",
    Callback     = function(v)
        infiniteSoruEnabled = v
        if v and LP.Character then
            pcall(function()
                LP.Character:SetAttribute("FlashstepCooldown", 1)
            end)
        end
        Rayfield:Notify({Title="Infinite Soru", Content=v and "ON — No cooldown" or "OFF", Duration=2})
    end,
})

-- ── AHK SORU SECTION ─────────────────────────────────────────
SoruTab:CreateSection("AHK Soru")

-- ============================================================
--  SORU DETECTOR V10 — RED THEME + PER-CAT DELAY 0.10–0.20
--  AHK delay mapping: UI 0.10 → 0.0167s | UI 0.20 → 0.0334s
-- ============================================================

-- ── V9 STATE ─────────────────────────────────────────────────
local _v9Selected = nil   -- single selected move (cat + skill)
local _v9AllBtnData = {}

-- Per-category UI delay (0.10–0.20, independent per cat)
local _v9RowDelayUI = {
    Melee = 0.15,
    Fruit = 0.15,
    Sword = 0.15,
    Gun   = 0.15,
}

-- AHK delay mapping: UI 0.10 → 0.0167s (1 frame), 0.20 → 0.0334s (2 frames)
-- Linear interpolation between AHK_MIN and AHK_MAX
local AHK_MIN = 0.0167  -- 1 RenderStepped frame gap (60fps)
local AHK_MAX = 0.0334  -- 2 frame gaps
local UI_MIN  = 0.10
local UI_MAX  = 0.20

local function _v9MapDelay(uiVal)
    local t = (uiVal - UI_MIN) / (UI_MAX - UI_MIN)
    t = math.clamp(t, 0, 1)
    return AHK_MIN + (AHK_MAX - AHK_MIN) * t
end

-- ── V9 COLOUR PALETTE (BBG Strap Red Theme) ──────────────────
local _v9C = {
    bg        = Color3.fromRGB(8,   8,   8),
    card      = Color3.fromRGB(18,  18,  18),
    cardHov   = Color3.fromRGB(26,  26,  26),
    titleBg   = Color3.fromRGB(12,  12,  12),
    accent    = Color3.fromRGB(220, 30,  30),   -- Solid red
    accentDk  = Color3.fromRGB(140, 15,  15),
    white     = Color3.fromRGB(255, 255, 255),  -- Pure white (no stroke)
    whiteDim  = Color3.fromRGB(180, 180, 180),
    grey      = Color3.fromRGB(90,  90,  90),
    greyLight = Color3.fromRGB(120, 120, 120),
    btnOff    = Color3.fromRGB(22,  22,  22),
    stepOff   = Color3.fromRGB(22,  22,  22),
    minusRed  = Color3.fromRGB(220, 30,  30),   -- Red for – / + buttons
    shadow    = Color3.fromRGB(0,   0,   0),
    redBtn    = Color3.fromRGB(180, 20,  20),   -- Minimize/open button bg
}

-- ── V9 UI HELPERS ─────────────────────────────────────────────
local function _v9mkFrame(parent, size, pos, color, radius)
    local f = Instance.new("Frame")
    f.Size, f.Position, f.BackgroundColor3 = size, pos, color or _v9C.bg
    f.BorderSizePixel = 0
    f.Parent = parent
    if radius then Instance.new("UICorner", f).CornerRadius = UDim.new(0, radius) end
    return f
end

local function _v9mkText(parent, text, size, pos, color, fontSize, bold)
    -- NO stroke parameter — all text strokes removed
    local l = Instance.new("TextLabel")
    l.Size, l.Position = size, pos
    l.Text, l.TextColor3 = text, color or _v9C.white
    l.TextSize = fontSize or 13
    l.Font = bold and Enum.Font.GothamBold or Enum.Font.Gotham
    l.BackgroundTransparency, l.BorderSizePixel = 1, 0
    l.TextXAlignment = Enum.TextXAlignment.Left
    l.Parent = parent
    return l
end

local function _v9mkBtn(parent, text, size, pos, bgColor, txtColor, radius)
    local b = Instance.new("TextButton")
    b.Size, b.Position = size, pos
    b.Text, b.TextColor3 = text, txtColor or _v9C.white
    b.TextSize, b.Font = 12, Enum.Font.GothamBold
    b.BackgroundColor3 = bgColor or _v9C.card
    b.BorderSizePixel, b.AutoButtonColor = 0, false
    b.Parent = parent
    if radius then Instance.new("UICorner", b).CornerRadius = UDim.new(0, radius) end
    return b
end

-- Red border stroke (BBG Strap style — solid red, not grey)
local function _v9addRedStroke(parent, thickness)
    local s = Instance.new("UIStroke", parent)
    s.Color = _v9C.accent
    s.Thickness = thickness or 1.5
    s.Transparency = 0
    return s
end

-- Card grey stroke (inner cards keep subtle grey)
local function _v9addGreyStroke(parent, thickness)
    local s = Instance.new("UIStroke", parent)
    s.Color = _v9C.grey
    s.Thickness = thickness or 1
    s.Transparency = 0.4
    return s
end

-- Red gradient on active move button
local function _v9applyRedGradient(btn)
    local existing = btn:FindFirstChildOfClass("UIGradient")
    if existing then existing:Destroy() end
    local g = Instance.new("UIGradient", btn)
    g.Color = ColorSequence.new({
        ColorSequenceKeypoint.new(0,   Color3.fromRGB(230, 40,  40)),
        ColorSequenceKeypoint.new(0.5, Color3.fromRGB(180, 20,  20)),
        ColorSequenceKeypoint.new(1,   Color3.fromRGB(120, 10,  10)),
    })
    g.Rotation = 90
    -- Active: red text, NO stroke
    btn.TextColor3 = _v9C.accent
    local existStroke = btn:FindFirstChildOfClass("UIStroke")
    if existStroke then existStroke:Destroy() end
end

-- Remove gradient (reset move button to default — pure white, NO stroke)
local function _v9removeGradient(btn)
    local g = btn:FindFirstChildOfClass("UIGradient")
    if g then g:Destroy() end
    local s = btn:FindFirstChildOfClass("UIStroke")
    if s then s:Destroy() end
    btn.TextColor3 = _v9C.white  -- pure white, no stroke
end

local function _v9makeDraggable(target, handle)
    local dragging, dragStart, startX, startY
    handle.InputBegan:Connect(function(inp)
        if inp.UserInputType == Enum.UserInputType.Touch
        or inp.UserInputType == Enum.UserInputType.MouseButton1 then
            dragging  = true
            dragStart = inp.Position
            startX = target.Position.X.Offset
            startY = target.Position.Y.Offset
        end
    end)
    handle.InputChanged:Connect(function(inp)
        if dragging and (inp.UserInputType == Enum.UserInputType.MouseMovement
        or inp.UserInputType == Enum.UserInputType.Touch) then
            local d  = inp.Position - dragStart
            local vp = workspace.CurrentCamera.ViewportSize
            target.Position = UDim2.new(
                0, math.clamp(startX + d.X, 0, vp.X - target.AbsoluteSize.X),
                0, math.clamp(startY + d.Y, -(target.AbsoluteSize.Y - 40), vp.Y - 36)
            )
        end
    end)
    handle.InputEnded:Connect(function(inp)
        if inp.UserInputType == Enum.UserInputType.Touch
        or inp.UserInputType == Enum.UserInputType.MouseButton1 then
            dragging = false
        end
    end)
end

-- ── V9 SELECTION LOGIC (single-select + toggle) ─────────────────
local function _v9IsSelected(cat, skill)
    return _v9Selected ~= nil
        and _v9Selected.cat == cat
        and _v9Selected.skill == skill
end

local function _v9ToggleSelect(cat, skill)
    -- If same move clicked again → deselect
    if _v9Selected and _v9Selected.cat == cat and _v9Selected.skill == skill then
        _v9Selected = nil
        return
    end
    -- Otherwise replace with the new single selection
    _v9Selected = { cat = cat, skill = skill }
end

local function _v9RebuildColours()
    for _, bd in ipairs(_v9AllBtnData) do
        if _v9IsSelected(bd.cat, bd.skill) then
            bd.btn.BackgroundColor3 = _v9C.accentDk
            _v9applyRedGradient(bd.btn)
        else
            bd.btn.BackgroundColor3 = _v9C.btnOff
            _v9removeGradient(bd.btn)
        end
    end
end

local _v9statusLabel = nil

local function _v9UpdateStatus()
    if not _v9statusLabel then return end
    if not _v9Selected then
        _v9statusLabel.Text       = "Selected: None"
        _v9statusLabel.TextColor3 = _v9C.greyLight
    else
        _v9statusLabel.Text       = "Selected: " .. _v9Selected.cat .. "  [" .. _v9Selected.skill .. "]"
        _v9statusLabel.TextColor3 = _v9C.white
    end
end

-- ── BUILD V10 SCREENGUI ────────────────────────────────────────
local _v9Gui = Instance.new("ScreenGui")
_v9Gui.Name           = "BBG_SoruDetectorV10"
_v9Gui.ResetOnSpawn   = false
_v9Gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
_v9Gui.Enabled        = false
_v9Gui.Parent         = game:GetService("CoreGui")

local _v9FRAME_W = 310
local _v9FRAME_H = 410

local _v9main = _v9mkFrame(_v9Gui,
    UDim2.new(0, _v9FRAME_W, 0, _v9FRAME_H),
    UDim2.new(0.5, -_v9FRAME_W/2, 0.22, 0),
    _v9C.bg, 12)
-- SOLID RED border (BBG Strap style)
_v9addRedStroke(_v9main, 1.5)
_v9main.ClipsDescendants = true

-- ── TITLE BAR ─────────────────────────────────────────────────
local _v9titleBar = _v9mkFrame(_v9main,
    UDim2.new(1, 0, 0, 40),
    UDim2.new(0, 0, 0, 0),
    _v9C.titleBg, 12)

-- Red separator line under titlebar
local _v9titleSep = _v9mkFrame(_v9titleBar, UDim2.new(1,0,0,1), UDim2.new(0,0,1,-1), _v9C.accent, 0)
_v9titleSep.BackgroundTransparency = 0.3

-- Title text — SOLID RED, no stroke
local _v9titleLbl = Instance.new("TextLabel")
_v9titleLbl.Size             = UDim2.new(1, -60, 1, 0)
_v9titleLbl.Position         = UDim2.new(0, 14, 0, 0)
_v9titleLbl.Text             = "SORU DETECTOR"
_v9titleLbl.TextColor3       = _v9C.accent   -- solid red
_v9titleLbl.TextSize         = 13
_v9titleLbl.Font             = Enum.Font.GothamBold
_v9titleLbl.BackgroundTransparency = 1
_v9titleLbl.BorderSizePixel  = 0
_v9titleLbl.TextXAlignment   = Enum.TextXAlignment.Left
_v9titleLbl.Parent           = _v9titleBar
-- NO UIStroke on title

-- Minimize button — RED background, BBG Strap style
local _v9minBtn = _v9mkBtn(_v9titleBar, "–",
    UDim2.new(0, 30, 0, 30),
    UDim2.new(1, -36, 0.5, -15),
    _v9C.redBtn,    -- red background
    _v9C.white, 6)
_v9minBtn.TextSize = 14
-- Red stroke on minimize button (BBG Strap style)
_v9addRedStroke(_v9minBtn, 1)

_v9makeDraggable(_v9main, _v9titleBar)

local _v9minimized = false
_v9minBtn.MouseButton1Click:Connect(function()
    _v9minimized = not _v9minimized
    _v9main.Size = _v9minimized
        and UDim2.new(0, _v9FRAME_W, 0, 40)
        or  UDim2.new(0, _v9FRAME_W, 0, _v9FRAME_H)
    -- Both states show + or – in red
    _v9minBtn.Text       = _v9minimized and "+" or "–"
    _v9minBtn.TextColor3 = _v9C.white
end)

-- ── STATUS BAR ────────────────────────────────────────────────
local _v9statCard = _v9mkFrame(_v9main,
    UDim2.new(1, -16, 0, 30),
    UDim2.new(0, 8, 0, 48),
    _v9C.card, 8)
_v9addGreyStroke(_v9statCard, 1)

-- Status label — no UIStroke
local _sl = Instance.new("TextLabel", _v9statCard)
_sl.Size             = UDim2.new(1, -12, 1, 0)
_sl.Position         = UDim2.new(0, 8, 0, 0)
_sl.Text             = "Starter: None"
_sl.TextColor3       = _v9C.greyLight
_sl.TextSize         = 11
_sl.Font             = Enum.Font.Gotham
_sl.BackgroundTransparency = 1
_sl.BorderSizePixel  = 0
_sl.TextXAlignment   = Enum.TextXAlignment.Center
-- NO UIStroke on status label
_v9statusLabel = _sl

-- ── ROW DEFINITIONS ───────────────────────────────────────────
local _v9ROW_DEFS = {
    { cat = "Melee", skills = {"Z","X","C"},         y = 88  },
    { cat = "Fruit", skills = {"Z","X","C","V","F"}, y = 172 },
    { cat = "Sword", skills = {"Z","X"},              y = 256 },
    { cat = "Gun",   skills = {"Z","X"},              y = 340 },
}
local _v9ROW_H = 76

for _, rowDef in ipairs(_v9ROW_DEFS) do
    local cat = rowDef.cat

    local rowCard = _v9mkFrame(_v9main,
        UDim2.new(1, -16, 0, _v9ROW_H),
        UDim2.new(0, 8, 0, rowDef.y),
        _v9C.card, 8)
    _v9addGreyStroke(rowCard, 1)

    -- Category label — pure white, NO stroke
    local catLbl = Instance.new("TextLabel", rowCard)
    catLbl.Size             = UDim2.new(0, 56, 0, 18)
    catLbl.Position         = UDim2.new(0, 8, 0, 6)
    catLbl.Text             = cat
    catLbl.TextColor3       = _v9C.white  -- pure white
    catLbl.TextSize         = 11
    catLbl.Font             = Enum.Font.GothamBold
    catLbl.BackgroundTransparency = 1
    catLbl.BorderSizePixel  = 0
    catLbl.TextXAlignment   = Enum.TextXAlignment.Left
    catLbl.Parent           = rowCard
    -- NO UIStroke on category label

    -- Skill move buttons — pure white text, NO stroke (default state)
    local xOff = 68
    for _, skillName in ipairs(rowDef.skills) do
        local sb = _v9mkBtn(rowCard, skillName,
            UDim2.new(0, 34, 0, 26),
            UDim2.new(0, xOff, 0, 4),
            _v9C.btnOff, _v9C.white, 7)  -- pure white text
        sb.TextSize = 11
        -- NO UIStroke on move buttons (removed completely)
        -- Grey border only for card definition
        _v9addGreyStroke(sb, 1)

        table.insert(_v9AllBtnData, { btn = sb, cat = cat, skill = skillName })

        sb.MouseButton1Click:Connect(function()
            _v9ToggleSelect(cat, skillName)
            _v9RebuildColours()
            _v9UpdateStatus()
        end)
        xOff = xOff + 38
    end

    -- Delay label — pure white, NO stroke
    local delayLbl = Instance.new("TextLabel", rowCard)
    delayLbl.Size             = UDim2.new(0, 36, 0, 14)
    delayLbl.Position         = UDim2.new(0, 8, 0, 44)
    delayLbl.Text             = "Delay:"
    delayLbl.TextColor3       = _v9C.white
    delayLbl.TextSize         = 9
    delayLbl.Font             = Enum.Font.Gotham
    delayLbl.BackgroundTransparency = 1
    delayLbl.BorderSizePixel  = 0
    delayLbl.TextXAlignment   = Enum.TextXAlignment.Left
    -- NO UIStroke

    -- Delay value display (UI range 0.10–0.20) — pure white, NO stroke
    local delayDisp = Instance.new("TextLabel", rowCard)
    delayDisp.Size             = UDim2.new(0, 40, 0, 14)
    delayDisp.Position         = UDim2.new(0, 46, 0, 44)
    delayDisp.Text             = string.format("%.2f", _v9RowDelayUI[cat])
    delayDisp.TextColor3       = _v9C.white
    delayDisp.TextSize         = 9
    delayDisp.Font             = Enum.Font.GothamBold
    delayDisp.BackgroundTransparency = 1
    delayDisp.BorderSizePixel  = 0
    delayDisp.TextXAlignment   = Enum.TextXAlignment.Left
    -- NO UIStroke on delay display

    -- Minus button — RED background (BBG Strap style)
    local minusBtn = _v9mkBtn(rowCard, "–",
        UDim2.new(0, 22, 0, 18),
        UDim2.new(0, 90, 0, 40),
        _v9C.redBtn, _v9C.white, 4)
    minusBtn.TextSize = 13
    _v9addRedStroke(minusBtn, 1)

    -- Plus button — RED background (BBG Strap style)
    local plusBtn = _v9mkBtn(rowCard, "+",
        UDim2.new(0, 22, 0, 18),
        UDim2.new(0, 116, 0, 40),
        _v9C.redBtn, _v9C.white, 4)
    plusBtn.TextSize = 13
    _v9addRedStroke(plusBtn, 1)

    -- Minus: decrease UI delay by 0.01, clamp 0.10–0.20, independent per cat
    minusBtn.MouseButton1Click:Connect(function()
        _v9RowDelayUI[cat] = math.max(UI_MIN,
            math.floor((_v9RowDelayUI[cat] - 0.01) * 100 + 0.5) / 100)
        delayDisp.Text = string.format("%.2f", _v9RowDelayUI[cat])
    end)

    -- Plus: increase UI delay by 0.01, clamp 0.10–0.20
    plusBtn.MouseButton1Click:Connect(function()
        _v9RowDelayUI[cat] = math.min(UI_MAX,
            math.floor((_v9RowDelayUI[cat] + 0.01) * 100 + 0.5) / 100)
        delayDisp.Text = string.format("%.2f", _v9RowDelayUI[cat])
    end)
end

-- ── V9 WEAPON DETECTION + COMBO EXECUTION ────────────────────
local _v9MELEE_KW = {"combat","step","electro","fishman","dragon","human","karate","claw"}
local _v9GUN_KW   = {"gun","rifle","musket","cannon","kabucha"}

local function _v9detectType(tool)
    if not tool or not tool:IsA("Tool") then return "None" end
    local attr = tool:GetAttribute("WeaponType")
    if attr then
        if attr == "Demon Fruit" or attr == "Fruit" then return "Fruit" end
        return attr
    end
    local name = string.lower(tool.Name)
    for _, kw in ipairs(_v9MELEE_KW) do
        if string.find(name, kw) then return "Melee" end
    end
    for _, kw in ipairs(_v9GUN_KW) do
        if string.find(name, kw) then return "Gun" end
    end
    if string.find(name, "fruit") then return "Fruit" end
    return "Sword"
end

local function _v9getCurrentType()
    local char = LP.Character
    if not char then return "None" end
    local tool = char:FindFirstChildOfClass("Tool")
    if not tool then return "None" end
    return _v9detectType(tool)
end

local function _v9autoEquip(cat)
    if _v9getCurrentType() == cat then return true end
    local char     = LP.Character
    local backpack = LP.Backpack
    if not char or not backpack then return false end
    local hum = char:FindFirstChildOfClass("Humanoid")
    if not hum then return false end
    local target = nil
    for _, t in ipairs(backpack:GetChildren()) do
        if t:IsA("Tool") and _v9detectType(t) == cat then target = t break end
    end
    if not target then return false end
    hum:EquipTool(target)
    for _ = 1, 17 do
        if _v9getCurrentType() == cat then return true end
        task.wait()   -- 1-frame poll, minimal blocking (~0.28s max, no movement freeze)
    end
    return _v9getCurrentType() == cat
end

local _v9VIM = game:GetService("VirtualInputManager")

local function _v9FireKey(keyName)
    local k = Enum.KeyCode[keyName]
    if not k then return end
    _v9VIM:SendKeyEvent(true,  k, false, game)
    _v9VIM:SendKeyEvent(false, k, false, game)
    _v9VIM:SendKeyEvent(true,  k, false, game)
    task.wait()   -- minimal 1-frame yield, does not block movement
    _v9VIM:SendKeyEvent(false, k, false, game)
end

-- Single move fire — fires only the currently selected move
local _v9MoveRunning = false

local function _v9FireMove()
    if not _v9Selected then return end
    -- Prevent overlapping calls (soru fires multiple AnimationPlayed events)
    if _v9MoveRunning then return end

    -- Snapshot the single selected move NOW
    local sel = { cat = _v9Selected.cat, skill = _v9Selected.skill }

    task.spawn(function()
        _v9MoveRunning = true

        local ok = _v9autoEquip(sel.cat)
        if ok then
            local realDelay = _v9MapDelay(_v9RowDelayUI[sel.cat])
            task.wait(realDelay)
            _v9FireKey(sel.skill)
        end

        -- Small cooldown before allowing next trigger
        task.wait(0.05)
        _v9MoveRunning = false
    end)
end

-- ── V9 SORU ANIMATION MONITOR ────────────────────────────────
local function _v9MonitorAnimations(char)
    local humanoid = char:WaitForChild("Humanoid", 5)
    if not humanoid then return end
    humanoid.AnimationPlayed:Connect(function(track)
        if not _v9Gui.Enabled then return end
        local id      = track.Animation.AnimationId
        local cleanId = id:match("%d+") or id
        if track.Name == "FlashStepRegular"
        or track.Name == "FlashStepDraco"
        or cleanId    == "17555632156"
        or cleanId    == "18461649274" then
            _v9FireMove()
        end
    end)
end

if LP.Character then _v9MonitorAnimations(LP.Character) end
LP.CharacterAdded:Connect(function(newChar)
    _v9MonitorAnimations(newChar)
end)

-- Soru Detector toggle — shows/hides v9 GUI
SoruTab:CreateToggle({
    Name         = "Soru Detector",
    CurrentValue = false,
    Flag         = "AHK_SoruDetector",
    Callback     = function(v)
        _v9Gui.Enabled = v
        Rayfield:Notify({
            Title   = "Soru Detector",
            Content = v and "ON — Soru Detector UI visible" or "OFF — UI hidden",
            Duration = 2,
        })
    end,
})

Players.PlayerRemoving:Connect(function(pl)
    if cachedTarget == pl.Name then cachedTarget = nil end
    local newList = {"None"}
    for _, p in ipairs(Players:GetPlayers()) do
        if p ~= LP and p ~= pl then table.insert(newList, p.Name) end
    end
    pcall(function() SoruPlayerDropdown:Refresh(newList, true) end)
end)

Players.PlayerAdded:Connect(function()
    local newList = {"None"}
    for _, p in ipairs(Players:GetPlayers()) do
        if p ~= LP then table.insert(newList, p.Name) end
    end
    pcall(function() SoruPlayerDropdown:Refresh(newList, true) end)
end)


-- ============================================================
--  INFINITE SORU ENGINE
-- ============================================================
local infiniteSoruEnabled = false

local function setupInfiniteSoru(char)
    if not infiniteSoruEnabled then return end
    pcall(function()
        char:SetAttribute("FlashstepCooldown", 1)
    end)
end

LP.CharacterAdded:Connect(function(char)
    setupInfiniteSoru(char)
end)
if LP.Character then setupInfiniteSoru(LP.Character) end

-- Keep applying every 0.5s so server-side resets can't override it
task.spawn(function()
    while true do
        task.wait(0.5)
        if infiniteSoruEnabled then
            pcall(function()
                local char = LP.Character
                if char then
                    char:SetAttribute("FlashstepCooldown", 1)
                end
            end)
        end
    end
end)

-- ============================================================
--  SORU SILENT MINI TOGGLE  
-- ============================================================
do
    local ACCENT  = Color3.fromRGB(220, 30, 30)   -- bright red for outline/text (same as Sang)
    local PURPLE1 = Color3.fromRGB(100, 10, 10)   -- toggle gradient ON
    local PURPLE2 = Color3.fromRGB(180, 30, 30)
    local OFF1    = Color3.fromRGB(100, 10, 10)   -- toggle gradient OFF
    local OFF2    = Color3.fromRGB(180, 30, 30)

    _SoruMiniGui = Instance.new("ScreenGui")
    _SoruMiniGui.Name           = "BBGSoruMini"
    _SoruMiniGui.ResetOnSpawn   = false
    _SoruMiniGui.IgnoreGuiInset = true
    _SoruMiniGui.DisplayOrder   = 1002
    _SoruMiniGui.Enabled        = false  -- hidden by default, shows after first toggle
    _SoruMiniGui.Parent         = game:GetService("CoreGui")

    local frame = Instance.new("Frame", _SoruMiniGui)
    frame.Size             = UDim2.new(0, 155, 0, 185)
    frame.Position         = UDim2.new(0, 10, 0.5, -80)
    frame.BackgroundColor3 = Color3.fromRGB(12, 12, 18)
    frame.BorderSizePixel  = 0
    frame.Active           = true
    frame.Draggable        = true
    Instance.new("UICorner", frame).CornerRadius = UDim.new(0, 10)
    local fs = Instance.new("UIStroke", frame)
    fs.Color        = ACCENT
    fs.Thickness    = 1.5
    fs.Transparency = 0.2

    -- Title
    local title = Instance.new("TextLabel", frame)
    title.Size               = UDim2.new(1, -28, 0, 22)
    title.Position           = UDim2.new(0, 0, 0, 4)
    title.BackgroundTransparency = 1
    title.Text               = "Soru Silent"
    title.TextColor3              = ACCENT
    title.TextStrokeColor3        = Color3.fromRGB(0,0,0)
    title.TextStrokeTransparency  = 0.4
    title.Font               = Enum.Font.GothamBold
    title.TextSize           = 12

    -- Minimize button
    local minimized  = false
    local fullHeight = 185

    local minBtn = Instance.new("TextButton", frame)
    minBtn.Size            = UDim2.new(0, 22, 0, 22)
    minBtn.Position        = UDim2.new(1, -24, 0, 4)
    minBtn.Text            = "–"
    minBtn.TextColor3             = ACCENT
    minBtn.TextStrokeColor3       = Color3.fromRGB(0,0,0)
    minBtn.TextStrokeTransparency = 0.4
    minBtn.Font            = Enum.Font.GothamBold
    minBtn.TextSize        = 14
    minBtn.BackgroundColor3= Color3.fromRGB(30, 30, 42)
    minBtn.BorderSizePixel = 0
    Instance.new("UICorner", minBtn).CornerRadius = UDim.new(0, 6)

    local contentFrame = Instance.new("Frame", frame)
    contentFrame.Size             = UDim2.new(1, 0, 1, -30)
    contentFrame.Position         = UDim2.new(0, 0, 0, 30)
    contentFrame.BackgroundTransparency = 1
    contentFrame.ClipsDescendants = true

    minBtn.MouseButton1Click:Connect(function()
        minimized = not minimized
        minBtn.Text = minimized and "+" or "–"
        frame.Size  = minimized and UDim2.new(0, 155, 0, 30) or UDim2.new(0, 155, 0, fullHeight)
        contentFrame.Visible = not minimized
    end)

    -- Target label
    local targetLbl = Instance.new("TextLabel", contentFrame)
    targetLbl.Size               = UDim2.new(1, -10, 0, 14)
    targetLbl.Position           = UDim2.new(0, 6, 0, 2)
    targetLbl.BackgroundTransparency = 1
    targetLbl.Text               = "Target: None"
    targetLbl.TextColor3         = Color3.fromRGB(160, 160, 170)
    targetLbl.Font               = Enum.Font.Gotham
    targetLbl.TextSize           = 11
    targetLbl.TextXAlignment     = Enum.TextXAlignment.Left

    -- Target select buttons (scrollable list)
    local listFrame = Instance.new("ScrollingFrame", contentFrame)
    listFrame.Size                = UDim2.new(1, -8, 0, 70)
    listFrame.Position            = UDim2.new(0, 4, 0, 20)
    listFrame.BackgroundColor3    = Color3.fromRGB(20, 20, 22)
    listFrame.BorderSizePixel     = 0
    listFrame.ScrollBarThickness  = 3
    listFrame.ScrollBarImageColor3= Color3.fromRGB(100, 100, 110)
    listFrame.AutomaticCanvasSize = Enum.AutomaticSize.Y
    listFrame.CanvasSize          = UDim2.new(0,0,0,0)
    Instance.new("UICorner", listFrame).CornerRadius = UDim.new(0, 6)

    local listLayout = Instance.new("UIListLayout", listFrame)
    listLayout.Padding           = UDim.new(0, 2)
    listLayout.SortOrder         = Enum.SortOrder.LayoutOrder
    Instance.new("UIPadding", listFrame).PaddingTop = UDim.new(0, 3)

    local function refreshTargetList()
        for _, v in pairs(listFrame:GetChildren()) do
            if v:IsA("TextButton") then v:Destroy() end
        end
        -- "None" option
        local noneBtn = Instance.new("TextButton", listFrame)
        noneBtn.Size            = UDim2.new(1, -6, 0, 20)
        noneBtn.BackgroundColor3= Color3.fromRGB(32, 32, 36)
        noneBtn.Text            = "None"
        noneBtn.TextColor3              = Color3.fromRGB(235, 235, 235)
        noneBtn.TextStrokeColor3        = Color3.fromRGB(255,255,255)
        noneBtn.TextStrokeTransparency  = 0.7
        noneBtn.Font            = Enum.Font.Gotham
        noneBtn.TextSize        = 11
        noneBtn.BorderSizePixel = 0
        Instance.new("UICorner", noneBtn).CornerRadius = UDim.new(0, 4)
        noneBtn.MouseButton1Click:Connect(function()
            cachedTarget = nil
            targetLbl.Text = "Target: None"
        end)

        for _, p in pairs(Players:GetPlayers()) do
            if p ~= LP then
                local btn = Instance.new("TextButton", listFrame)
                btn.Size            = UDim2.new(1, -6, 0, 20)
                btn.BackgroundColor3= Color3.fromRGB(32, 32, 36)
                btn.Text            = p.Name
                btn.TextColor3              = Color3.fromRGB(235, 235, 235)
                btn.TextStrokeColor3        = Color3.fromRGB(255,255,255)
                btn.TextStrokeTransparency  = 0.7
                btn.Font            = Enum.Font.Gotham
                btn.TextSize        = 11
                btn.BorderSizePixel = 0
                Instance.new("UICorner", btn).CornerRadius = UDim.new(0, 4)
                btn.MouseButton1Click:Connect(function()
                    cachedTarget = p.Name
                    targetLbl.Text = "Target: " .. p.Name
                end)
            end
        end
    end

    refreshTargetList()

    -- Refresh button
    local refreshBtn = Instance.new("TextButton", contentFrame)
    refreshBtn.Size            = UDim2.new(1, -12, 0, 20)
    refreshBtn.Position        = UDim2.new(0, 6, 0, 94)
    refreshBtn.BackgroundColor3= Color3.fromRGB(35, 35, 40)
    refreshBtn.Text            = "Refresh"
    refreshBtn.TextColor3             = Color3.fromRGB(235, 235, 235)
    refreshBtn.TextStrokeColor3       = Color3.fromRGB(255,255,255)
    refreshBtn.TextStrokeTransparency = 0.7
    refreshBtn.Font            = Enum.Font.GothamBold
    refreshBtn.TextSize        = 11
    refreshBtn.BorderSizePixel = 0
    Instance.new("UICorner", refreshBtn).CornerRadius = UDim.new(0, 5)
    refreshBtn.MouseButton1Click:Connect(refreshTargetList)

    -- ON/OFF toggle button (purple gradient)
    local toggleBtn = Instance.new("TextButton", contentFrame)
    toggleBtn.Size            = UDim2.new(1, -12, 0, 34)
    toggleBtn.Position        = UDim2.new(0, 6, 0, 118)
    toggleBtn.TextScaled      = true
    toggleBtn.TextColor3      = Color3.new(1,1,1)
    toggleBtn.TextStrokeColor3= Color3.fromRGB(0,0,0)
    toggleBtn.TextStrokeTransparency = 0.3
    toggleBtn.BorderSizePixel = 0
    toggleBtn.Font            = Enum.Font.GothamBold
    toggleBtn.AutoButtonColor = false
    Instance.new("UICorner", toggleBtn).CornerRadius = UDim.new(0, 9)
    local tg = Instance.new("UIGradient", toggleBtn)
    tg.Rotation = 45

    local function refreshToggleBtn()
        toggleBtn.Text = "Soru  " .. (soruSilentEnabled and "ON" or "OFF")
        tg.Color = ColorSequence.new{
            ColorSequenceKeypoint.new(0, soruSilentEnabled and PURPLE1 or OFF1),
            ColorSequenceKeypoint.new(1, soruSilentEnabled and PURPLE2 or OFF2),
        }
    end

    toggleBtn.MouseButton1Click:Connect(function()
        soruSilentEnabled = not soruSilentEnabled
        refreshToggleBtn()
    end)

    refreshToggleBtn()

    -- Draggable
    local dragging, dragStart, startPos2 = false, nil, nil
    frame.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.Touch
        or input.UserInputType == Enum.UserInputType.MouseButton1 then
            dragging  = true
            dragStart = input.Position
            startPos2 = frame.Position
            input.Changed:Connect(function()
                if input.UserInputState == Enum.UserInputState.End then dragging = false end
            end)
        end
    end)
    frame.InputChanged:Connect(function(input)
        if dragging and (input.UserInputType == Enum.UserInputType.Touch
            or input.UserInputType == Enum.UserInputType.MouseMovement) then
            local delta = input.Position - dragStart
            frame.Position = UDim2.new(0,
                math.clamp(startPos2.X.Offset + delta.X, 0, Camera.ViewportSize.X - frame.AbsoluteSize.X),
                0,
                math.clamp(startPos2.Y.Offset + delta.Y, 0, Camera.ViewportSize.Y - frame.AbsoluteSize.Y)
            )
        end
    end)

    _SoruMiniGui.Enabled = false  -- default off, shows when Soru Silent is first toggled ON
end


local VirtualInputManager = game:GetService("VirtualInputManager")

-- ── ECLAW X BOOST ───────────────────────────────────────
local eClawEnabled  = false
local eClawPower    = 400
local eClawDuration = 0.9
local eClawBoosted  = false

local function EClawBoost()
    local char = LP.Character
    local hrp  = char and char:FindFirstChild("HumanoidRootPart")
    local hum  = char and char:FindFirstChild("Humanoid")
    if not hrp or not hum then return end
    local dir = (mouse.Hit.p - hrp.Position).Unit
    hum.PlatformStand = true
    local att = Instance.new("Attachment", hrp)
    local lv  = Instance.new("LinearVelocity", hrp)
    lv.MaxForce               = 9999999
    lv.VelocityConstraintMode = Enum.VelocityConstraintMode.Vector
    lv.VectorVelocity         = dir * eClawPower
    lv.Attachment0            = att
    task.wait(eClawDuration)
    if lv  then lv:Destroy() end
    if att then att:Destroy() end
    hum.PlatformStand = false
end

local function hookEClawAnimations(hum)
    hum.AnimationPlayed:Connect(function(track)
        if not eClawEnabled then return end
        if track.Animation.AnimationId:find("6875496851")
        or track.Name == "ElectroClawXImpact" then
            eClawBoosted = false
            track.Stopped:Connect(function()
                if not eClawEnabled then return end
                if not eClawBoosted then
                    eClawBoosted = true
                    task.spawn(EClawBoost)
                end
            end)
        end
    end)
end

local function onEClawChar(char)
    local hum = char:WaitForChild("Humanoid")
    hookEClawAnimations(hum)
end

LP.CharacterAdded:Connect(onEClawChar)
if LP.Character then onEClawChar(LP.Character) end

-- ── SANGUINE Z BOOST ───────────────────────────────────────
local sangEnabled  = false
local sangPower    = 400
local sangDuration = 2.0
local sangBoosted  = false

local function SanguineZBoost()
    local char = LP.Character
    local hrp  = char and char:FindFirstChild("HumanoidRootPart")
    local hum  = char and char:FindFirstChild("Humanoid")
    if not hrp or not hum then return end
    local dir = (mouse.Hit.p - hrp.Position).Unit
    hum.PlatformStand = true
    local att = Instance.new("Attachment", hrp)
    local lv  = Instance.new("LinearVelocity", hrp)
    lv.MaxForce               = 9999999
    lv.VelocityConstraintMode = Enum.VelocityConstraintMode.Vector
    lv.VectorVelocity         = dir * sangPower
    lv.Attachment0            = att
    task.wait(sangDuration)
    if lv  then lv:Destroy() end
    if att then att:Destroy() end
    hum.PlatformStand = false
end

local function hookSangAnimations(hum)
    hum.AnimationPlayed:Connect(function(track)
        if not sangEnabled then return end
        -- Sanguine Z move animation IDs
        if (track.Animation.AnimationId:find("14418370048")
        or track.Animation.AnimationId:find("14418367908")
        or track.Name:lower():find("sanguine")
        or track.Name:lower():find("sang"))
        and not track.Animation.AnimationId:find("14586873525")
        and not track.Name:lower():find("basic")
        and not track.Name:lower():find("m1") then
            sangBoosted = false
            track.Stopped:Connect(function()
                if not sangEnabled then return end
                if not sangBoosted then
                    sangBoosted = true
                    task.spawn(SanguineZBoost)
                end
            end)
        end
    end)
end

local function onSangChar(char)
    local hum = char:WaitForChild("Humanoid")
    hookSangAnimations(hum)
end

LP.CharacterAdded:Connect(onSangChar)
if LP.Character then onSangChar(LP.Character) end

-- ── DIAMOND M1 BOOST ───────────────────────────────────────
local diamondEnabled  = false
local diamondPower    = 400
local diamondDuration = 0.6
local diamondBoosted  = false

local function DiamondM1Boost()
    local char = LP.Character
    local hrp  = char and char:FindFirstChild("HumanoidRootPart")
    local hum  = char and char:FindFirstChild("Humanoid")
    if not hrp or not hum then return end
    local dir = (mouse.Hit.p - hrp.Position).Unit
    hum.PlatformStand = true
    local att = Instance.new("Attachment", hrp)
    local lv  = Instance.new("LinearVelocity", hrp)
    lv.MaxForce               = 9999999
    lv.VelocityConstraintMode = Enum.VelocityConstraintMode.Vector
    lv.VectorVelocity         = dir * diamondPower
    lv.Attachment0            = att
    task.wait(diamondDuration)
    if lv  then lv:Destroy() end
    if att then att:Destroy() end
    hum.PlatformStand = false
end

local function hookDiamondAnimations(hum)
    hum.AnimationPlayed:Connect(function(track)
        if not diamondEnabled then return end
        -- Diamond hold M1 animation ID
        if track.Animation.AnimationId:find("14414815375")
        or track.Name:lower():find("diamond")
        and (track.Name:lower():find("m1") or track.Name:lower():find("hold")) then
            diamondBoosted = false
            track.Stopped:Connect(function()
                if not diamondEnabled then return end
                if not diamondBoosted then
                    diamondBoosted = true
                    task.spawn(DiamondM1Boost)
                end
            end)
        end
    end)
end

local function onDiamondChar(char)
    local hum = char:WaitForChild("Humanoid")
    hookDiamondAnimations(hum)
end

LP.CharacterAdded:Connect(onDiamondChar)
if LP.Character then onDiamondChar(LP.Character) end

-- ── GLITCHES TAB UI ──────────────────────────────────────────
local GlitchesTab = Window:CreateTab("Glitches", 4483362458)

-- ============================================================
--  FLOATING WINDOW BUILDER 
--  Creates a self-contained draggable ScreenGui with:
--    • Power slider  (tap +/- buttons)
--    • Duration slider
--    • Big ON/OFF toggle button with gradient
-- ============================================================
local cam = workspace.CurrentCamera

local function BuildBoostWindow(opts)
    --[[
        opts = {
            name        = string,
            guiName     = string,
            defaultPos  = UDim2,
            accentColor = Color3,
            onColor     = {Color3, Color3},
            offColor    = {Color3, Color3},
            getEnabled / setEnabled / getBoosted / setBoosted
            getPower   / setPower   / getDuration / setDuration
            powerRange = {min, max}
            durRange   = {min, max}  (centiseconds)
        }
    --]]

    local sg = Instance.new("ScreenGui")
    sg.Name           = opts.guiName
    sg.ResetOnSpawn   = false
    sg.IgnoreGuiInset = true
    sg.DisplayOrder   = 1001
    sg.Enabled        = false
    sg.Parent         = game:GetService("CoreGui")

    -- ── Main frame (140 × 165) ───────────────────────────────
    local frame = Instance.new("Frame", sg)
    frame.Size             = UDim2.new(0, 150, 0, 175)
    frame.Position         = opts.defaultPos
    frame.BackgroundColor3 = Color3.fromRGB(12, 12, 18)
    frame.BorderSizePixel  = 0
    frame.Active           = true
    frame.Draggable        = true
    local fc = Instance.new("UICorner", frame); fc.CornerRadius = UDim.new(0, 10)
    local fs = Instance.new("UIStroke", frame)
    fs.Color       = opts.accentColor
    fs.Thickness   = 1.5
    fs.Transparency= 0.25

    -- ── Title ────────────────────────────────────────────────
    local title = Instance.new("TextLabel", frame)
    title.Size               = UDim2.new(1, -28, 0, 22)
    title.Position           = UDim2.new(0, 0, 0, 4)
    title.BackgroundTransparency = 1
    title.Text               = opts.name .. " Boost"
    title.TextColor3              = opts.accentColor
    title.TextStrokeColor3        = Color3.fromRGB(0,0,0)
    title.TextStrokeTransparency  = 0.4
    title.Font               = Enum.Font.GothamBold
    title.TextSize           = 12

    -- ── Minimize button ──────────────────────────────────────
    local minimized  = false
    local fullHeight = 175

    local minBtn = Instance.new("TextButton", frame)
    minBtn.Size            = UDim2.new(0, 22, 0, 22)
    minBtn.Position        = UDim2.new(1, -24, 0, 4)
    minBtn.Text            = "–"
    minBtn.TextColor3             = opts.accentColor
    minBtn.TextStrokeColor3       = Color3.fromRGB(0,0,0)
    minBtn.TextStrokeTransparency = 0.4
    minBtn.Font            = Enum.Font.GothamBold
    minBtn.TextSize        = 14
    minBtn.BackgroundColor3= Color3.fromRGB(30, 30, 42)
    minBtn.BorderSizePixel = 0
    minBtn.ZIndex          = 10
    local mc2 = Instance.new("UICorner", minBtn); mc2.CornerRadius = UDim.new(0, 6)

    -- ── Content frame (hidden when minimized) ────────────────
    local contentFrame = Instance.new("Frame", frame)
    contentFrame.Size             = UDim2.new(1, 0, 1, -30)
    contentFrame.Position         = UDim2.new(0, 0, 0, 30)
    contentFrame.BackgroundTransparency = 1
    contentFrame.ClipsDescendants = true

    minBtn.MouseButton1Click:Connect(function()
        minimized = not minimized
        if minimized then
            minBtn.Text  = "+"
            frame.Size   = UDim2.new(0, 150, 0, 30)
            contentFrame.Visible = false
        else
            minBtn.Text  = "–"
            frame.Size   = UDim2.new(0, 150, 0, fullHeight)
            contentFrame.Visible = true
        end
    end)

    -- ── Helper: small row label ───────────────────────────────
    local function MakeLabel(parent, text, yPos)
        local lbl = Instance.new("TextLabel", parent)
        lbl.Size               = UDim2.new(1, -10, 0, 14)
        lbl.Position           = UDim2.new(0, 6, 0, yPos)
        lbl.BackgroundTransparency = 1
        lbl.Text               = text
        lbl.TextColor3              = Color3.fromRGB(235, 235, 235)
        lbl.TextStrokeColor3        = Color3.fromRGB(255,255,255)
        lbl.TextStrokeTransparency  = 0.7
        lbl.Font               = Enum.Font.Gotham
        lbl.TextSize           = 11
        lbl.TextXAlignment     = Enum.TextXAlignment.Left
        return lbl
    end

    -- ── Helper: +/- row for a value ──────────────────────────
    local function MakeStepRow(parent, yPos, getVal, setVal, step, minV, maxV, labelRef)
        local minus = Instance.new("TextButton", parent)
        minus.Size            = UDim2.new(0, 28, 0, 22)
        minus.Position        = UDim2.new(0, 6, 0, yPos)
        minus.Text            = "-"
        minus.TextColor3      = Color3.new(1,1,1)
        minus.Font            = Enum.Font.GothamBold
        minus.TextSize        = 14
        minus.BackgroundColor3= Color3.fromRGB(40,40,55)
        minus.BorderSizePixel = 0
        local mc = Instance.new("UICorner", minus); mc.CornerRadius = UDim.new(0,6)

        local valLbl = Instance.new("TextLabel", parent)
        valLbl.Size               = UDim2.new(0, 62, 0, 22)
        valLbl.Position           = UDim2.new(0, 38, 0, yPos)
        valLbl.BackgroundTransparency = 1
        valLbl.Text               = tostring(getVal())
        valLbl.TextColor3         = Color3.new(1,1,1)
        valLbl.Font               = Enum.Font.GothamBold
        valLbl.TextSize           = 12

        local plus = Instance.new("TextButton", parent)
        plus.Size            = UDim2.new(0, 28, 0, 22)
        plus.Position        = UDim2.new(0, 104, 0, yPos)
        plus.Text            = "+"
        plus.TextColor3      = Color3.new(1,1,1)
        plus.Font            = Enum.Font.GothamBold
        plus.TextSize        = 14
        plus.BackgroundColor3= Color3.fromRGB(40,40,55)
        plus.BorderSizePixel = 0
        local pc = Instance.new("UICorner", plus); pc.CornerRadius = UDim.new(0,6)

        minus.MouseButton1Click:Connect(function()
            local nv = math.clamp(getVal() - step, minV, maxV)
            setVal(nv)
            valLbl.Text = tostring(nv)
        end)
        plus.MouseButton1Click:Connect(function()
            local nv = math.clamp(getVal() + step, minV, maxV)
            setVal(nv)
            valLbl.Text = tostring(nv)
        end)
    end

    -- Power row
    MakeLabel(contentFrame, "Power", 0)
    MakeStepRow(contentFrame, 15, opts.getPower, opts.setPower, 50,
        opts.powerRange[1], opts.powerRange[2], nil)

    -- Duration row
    MakeLabel(contentFrame, "Duration (cs)", 45)
    MakeStepRow(contentFrame, 60,
        function() return math.floor(opts.getDuration()*100) end,
        function(v) opts.setDuration(v/100) end,
        10, opts.durRange[1], opts.durRange[2], nil)

    -- ── Big ON/OFF toggle button ──────────────────────────────
    local toggleBtn = Instance.new("TextButton", contentFrame)
    toggleBtn.Size            = UDim2.new(1, -12, 0, 38)
    toggleBtn.Position        = UDim2.new(0, 6, 0, 98)
    toggleBtn.TextScaled      = true
    toggleBtn.TextColor3      = Color3.new(1,1,1)
    toggleBtn.TextStrokeColor3= Color3.fromRGB(0,0,0)
    toggleBtn.TextStrokeTransparency = 0.3
    toggleBtn.BorderSizePixel = 0
    toggleBtn.Font            = Enum.Font.GothamBold
    toggleBtn.AutoButtonColor = false
    local tc = Instance.new("UICorner", toggleBtn); tc.CornerRadius = UDim.new(0, 9)
    local tg = Instance.new("UIGradient", toggleBtn); tg.Rotation = 45

    local function refreshBtn()
        local on = opts.getEnabled()
        toggleBtn.Text = opts.name .. "  " .. (on and "ON" or "OFF")
        tg.Color = ColorSequence.new{
            ColorSequenceKeypoint.new(0, on and opts.onColor[1]  or opts.offColor[1]),
            ColorSequenceKeypoint.new(1, on and opts.onColor[2]  or opts.offColor[2]),
        }
    end

    toggleBtn.MouseButton1Click:Connect(function()
        local nv = not opts.getEnabled()
        opts.setEnabled(nv)
        if not nv then opts.setBoosted(false) end
        refreshBtn()
    end)

    refreshBtn()

    -- ── Frame draggable (touch + mouse) ──────────────────────
    local dragging, dragStart, startPos2 = false, nil, nil
    frame.InputBegan:Connect(function(input)
        if input.UserInputType == Enum.UserInputType.Touch
        or input.UserInputType == Enum.UserInputType.MouseButton1 then
            dragging  = true
            dragStart = input.Position
            startPos2 = frame.Position
            input.Changed:Connect(function()
                if input.UserInputState == Enum.UserInputState.End then dragging = false end
            end)
        end
    end)
    frame.InputChanged:Connect(function(input)
        if dragging and (input.UserInputType == Enum.UserInputType.Touch
            or input.UserInputType == Enum.UserInputType.MouseMovement) then
            local delta = input.Position - dragStart
            frame.Position = UDim2.new(0,
                math.clamp(startPos2.X.Offset + delta.X, 0, cam.ViewportSize.X - frame.AbsoluteSize.X),
                0,
                math.clamp(startPos2.Y.Offset + delta.Y, 0, cam.ViewportSize.Y - frame.AbsoluteSize.Y)
            )
        end
    end)

    -- expose refreshBtn so toggle can sync it
    return sg, refreshBtn
end

-- ============================================================
--  BUILD ECLAW WINDOW
-- ============================================================
local eClawGui, refreshEClaw = BuildBoostWindow({
    name        = "EClaw X",
    guiName     = "BBGEClawFloat",
    defaultPos  = UDim2.new(0, 20, 0.45, 0),
    accentColor = Color3.fromRGB(220, 30, 30),
    onColor     = {Color3.fromRGB(100, 10, 10),  Color3.fromRGB(180, 30, 30)},
    offColor    = {Color3.fromRGB(100, 10, 10),  Color3.fromRGB(180, 30, 30)},
    getEnabled  = function() return eClawEnabled end,
    setEnabled  = function(v) eClawEnabled = v end,
    getBoosted  = function() return eClawBoosted end,
    setBoosted  = function(v) eClawBoosted = v end,
    getPower    = function() return eClawPower end,
    setPower    = function(v) eClawPower = v end,
    getDuration = function() return eClawDuration end,
    setDuration = function(v) eClawDuration = v end,
    powerRange  = {50, 1000},
    durRange    = {10, 500},
})

-- ============================================================
--  BUILD SANGUINE WINDOW
-- ============================================================
local sangGui, refreshSang = BuildBoostWindow({
    name        = "Sang Z",
    guiName     = "BBGSangFloat",
    defaultPos  = UDim2.new(0, 20, 0.62, 0),
    accentColor = Color3.fromRGB(220, 30, 30),
    onColor     = {Color3.fromRGB(100, 10, 10),  Color3.fromRGB(180, 30, 30)},
    offColor    = {Color3.fromRGB(100, 10, 10),  Color3.fromRGB(180, 30, 30)},
    getEnabled  = function() return sangEnabled end,
    setEnabled  = function(v) sangEnabled = v end,
    getBoosted  = function() return sangBoosted end,
    setBoosted  = function(v) sangBoosted = v end,
    getPower    = function() return sangPower end,
    setPower    = function(v) sangPower = v end,
    getDuration = function() return sangDuration end,
    setDuration = function(v) sangDuration = v end,
    powerRange  = {50, 1000},
    durRange    = {10, 500},
})

-- ============================================================
--  BUILD DIAMOND M1 WINDOW
-- ============================================================
local diamondGui, refreshDiamond = BuildBoostWindow({
    name        = "Diamond M1",
    guiName     = "BBGDiamondFloat",
    defaultPos  = UDim2.new(0, 20, 0.79, 0),
    accentColor = Color3.fromRGB(220, 30, 30),
    onColor     = {Color3.fromRGB(100, 10, 10),  Color3.fromRGB(180, 30, 30)},
    offColor    = {Color3.fromRGB(100, 10, 10),  Color3.fromRGB(180, 30, 30)},
    getEnabled  = function() return diamondEnabled end,
    setEnabled  = function(v) diamondEnabled = v end,
    getBoosted  = function() return diamondBoosted end,
    setBoosted  = function(v) diamondBoosted = v end,
    getPower    = function() return diamondPower end,
    setPower    = function(v) diamondPower = v end,
    getDuration = function() return diamondDuration end,
    setDuration = function(v) diamondDuration = v end,
    powerRange  = {50, 1000},
    durRange    = {10, 500},
})

-- ============================================================
--  GLITCHES TAB UI
-- ============================================================
GlitchesTab:CreateSection("EClaw X Boost")

GlitchesTab:CreateToggle({
    Name="EClaw X Boost", CurrentValue=false, Flag="EClaw_MainToggle",
    Callback=function(v)
        eClawEnabled = v
        if not v then eClawBoosted = false end
        refreshEClaw()
        Rayfield:Notify({Title="EClaw X", Content=v and "ON" or "OFF", Duration=2})
    end,
})

GlitchesTab:CreateSlider({
    Name="EClaw Power", Range={50, 1000}, Increment=50,
    Suffix=" power", CurrentValue=400, Flag="EClaw_MainPower",
    Callback=function(v) eClawPower = v end,
})

GlitchesTab:CreateSlider({
    Name="EClaw Duration (cs)", Range={10, 500}, Increment=10,
    Suffix=" cs", CurrentValue=90, Flag="EClaw_MainDur",
    Callback=function(v) eClawDuration = v / 100 end,
})

GlitchesTab:CreateToggle({
    Name="Enable EClaw Window", CurrentValue=false, Flag="EClaw_Enabled",
    Callback=function(v)
        eClawGui.Enabled = v
        if not v then eClawEnabled=false; eClawBoosted=false; refreshEClaw() end
        Rayfield:Notify({Title="EClaw X",Content=v and "Window Opened" or "Window Closed",Duration=2})
    end,
})

GlitchesTab:CreateKeybind({
    Name="Keybind EClaw", CurrentKeybind="None", HoldToInteract=false, Flag="EClaw_Keybind",
    Callback=function() end,
})

GlitchesTab:CreateSection("Sanguine Z Boost")

GlitchesTab:CreateToggle({
    Name="Sanguine Z Boost", CurrentValue=false, Flag="Sang_MainToggle",
    Callback=function(v)
        sangEnabled = v
        if not v then sangBoosted = false end
        refreshSang()
        Rayfield:Notify({Title="Sang Z Boost", Content=v and "🟢 ON — Boost aktiv" or "🔴 OFF", Duration=2})
    end,
})

GlitchesTab:CreateSlider({
    Name="Sang Power", Range={50, 1000}, Increment=50,
    Suffix=" power", CurrentValue=400, Flag="Sang_MainPower",
    Callback=function(v) sangPower = v end,
})

GlitchesTab:CreateSlider({
    Name="Sang Duration (cs)", Range={10, 500}, Increment=10,
    Suffix=" cs", CurrentValue=200, Flag="Sang_MainDur",
    Callback=function(v) sangDuration = v / 100 end,
})

GlitchesTab:CreateToggle({
    Name="Show Sang Z Window", CurrentValue=false, Flag="Sang_Enabled",
    Callback=function(v)
        sangGui.Enabled = v
        if not v then sangEnabled=false; sangBoosted=false; refreshSang() end
        Rayfield:Notify({Title="Sang Z",Content=v and "Window Opened" or "Window Closed",Duration=2})
    end,
})

GlitchesTab:CreateKeybind({
    Name="Keybind Sanguine", CurrentKeybind="None", HoldToInteract=false, Flag="Sang_Keybind",
    Callback=function() end,
})

GlitchesTab:CreateSection("Diamond M1 Booster")

GlitchesTab:CreateToggle({
    Name="Diamond M1 Boost", CurrentValue=false, Flag="Diamond_MainToggle",
    Callback=function(v)
        diamondEnabled = v
        if not v then diamondBoosted = false end
        refreshDiamond()
        Rayfield:Notify({Title="Diamond M1", Content=v and "ON" or "OFF", Duration=2})
    end,
})

GlitchesTab:CreateSlider({
    Name="Diamond Power", Range={50, 1000}, Increment=50,
    Suffix=" power", CurrentValue=400, Flag="Diamond_MainPower",
    Callback=function(v) diamondPower = v end,
})

GlitchesTab:CreateSlider({
    Name="Diamond Duration (cs)", Range={10, 500}, Increment=10,
    Suffix=" cs", CurrentValue=60, Flag="Diamond_MainDur",
    Callback=function(v) diamondDuration = v / 100 end,
})

GlitchesTab:CreateToggle({
    Name="Enable Diamond Window", CurrentValue=false, Flag="Diamond_Enabled",
    Callback=function(v)
        diamondGui.Enabled = v
        if not v then diamondEnabled=false; diamondBoosted=false; refreshDiamond() end
        Rayfield:Notify({Title="Diamond M1",Content=v and "Window Opened" or "Window Closed",Duration=2})
    end,
})

GlitchesTab:CreateKeybind({
    Name="Keybind Diamond M1", CurrentKeybind="None", HoldToInteract=false, Flag="Diamond_Keybind",
    Callback=function() end,
})

-- ============================================================
--  SILENT AIM ENGINE
-- ============================================================

local SilentAimModule = (function()
    local M = {}

    local _Players = game:GetService("Players")
    local _LP = _Players.LocalPlayer
    local _RS = game:GetService("RunService")
    local _RS2 = game:GetService("ReplicatedStorage")
    local _UIS = game:GetService("UserInputService")
    local _cam = workspace.CurrentCamera

    -- CommE remote
    local _commE = nil
    pcall(function()
        _commE = _RS2:WaitForChild("Remotes", 5)
            and _RS2.Remotes:WaitForChild("CommE", 5)
    end)

    -- State
    local SilentAimPlayersEnabled = false
    local SilentAimNPCsEnabled    = false
    local UserWantsPlayerAim      = false
    local UserWantsNPCAim         = false
    local PredictionEnabled       = false
    local HighlightEnabled        = false
    local AutoKen                 = false
    local autoKenRunning          = false

    local renderConn         = nil
    local currentTool        = nil
    local playersaimbot      = nil
    local PlayersPosition    = nil
    local NPCaimbot          = nil
    local NPCPosition        = nil
    local currentHighlight   = nil
    local currentTargetType  = nil
    local Selectedplayer     = nil
    local charConns          = {}

    local Skills = {"X"}
    local Booms  = {"TAP"}
    local PredictionAmount = 0.1
    local maxRange         = 1000

    -- Expose for BBG panel hook
    M._getPlayersPosition = function() return PlayersPosition end
    M._getNPCPosition     = function() return NPCPosition end
    M._getPlayersAimbot   = function() return playersaimbot end

    local function getHRP(model)
        if not model or not model:FindFirstChild("HumanoidRootPart") then return nil end
        return model.HumanoidRootPart
    end

    local function clearConns()
        for _, c in ipairs(charConns) do pcall(function() c:Disconnect() end) end
        charConns = {}
    end

    local function getPredicted(hrp)
        if not hrp then return nil end
        local hum = hrp.Parent:FindFirstChildOfClass("Humanoid")
        if not PredictionEnabled or not hum or hum.WalkSpeed < 5 then
            return hrp.Position
        end
        return hrp.Position + (hrp.Velocity * PredictionAmount)
    end

    -- Team / enemy check (BF Pirates vs Marines + Allies list)
    local function isAllyWithMe(tp)
        local myGui = _LP:FindFirstChild("PlayerGui")
        if not myGui then return false end
        local scrolling = myGui:FindFirstChild("Main")
            and myGui.Main:FindFirstChild("Allies")
            and myGui.Main.Allies:FindFirstChild("Container")
            and myGui.Main.Allies.Container:FindFirstChild("Allies")
            and myGui.Main.Allies.Container.Allies:FindFirstChild("ScrollingFrame")
        if scrolling then
            for _, frame in pairs(scrolling:GetDescendants()) do
                if frame:IsA("ImageButton") and frame.Name == tp.Name then
                    return true
                end
            end
        end
        return false
    end

    local function isEnemy(tp)
        if not tp or tp == _LP then return false end
        local myTeam  = _LP.Team
        local tpTeam  = tp.Team
        if myTeam and tpTeam then
            if myTeam.Name == "Pirates"  and tpTeam.Name == "Marines"  then return true end
            if myTeam.Name == "Marines"  and tpTeam.Name == "Pirates"  then return true end
            if myTeam.Name == "Pirates"  and tpTeam.Name == "Pirates"  then
                return not isAllyWithMe(tp)
            end
            if myTeam.Name == "Marines"  and tpTeam.Name == "Marines"  then return false end
        end
        return true
    end

    local function getClosestPlayer(lpHRP)
        if not lpHRP then return nil end
        -- Specific player lock
        if Selectedplayer then
            local tp = _Players:FindFirstChild(Selectedplayer)
            if tp and tp.Character and tp.Character:FindFirstChild("HumanoidRootPart") then
                local hum = tp.Character:FindFirstChildOfClass("Humanoid")
                if hum and hum.Health > 0 then return tp end
            end
            return nil
        end
        local closest, closestDist = nil, maxRange
        for _, pl in ipairs(_Players:GetPlayers()) do
            if pl ~= _LP and isEnemy(pl) and pl.Character and pl.Character.Parent ~= nil then
                local hum = pl.Character:FindFirstChildWhichIsA("Humanoid")
                local hrp = getHRP(pl.Character)
                if hum and hum.Health > 0 and hrp then
                    local dist = (hrp.Position - lpHRP.Position).Magnitude
                    if dist <= maxRange and dist < closestDist then
                        closestDist = dist
                        closest = pl
                    end
                end
            end
        end
        return closest
    end

    local function getClosestNPC(lpHRP)
        if not lpHRP then return nil end
        local enemiesFolder = workspace:FindFirstChild("Enemies")
        if not enemiesFolder then return nil end
        local closest, closestDist = nil, maxRange
        for _, npc in ipairs(enemiesFolder:GetChildren()) do
            if npc:IsA("Model") then
                local hum = npc:FindFirstChildWhichIsA("Humanoid")
                local hrp = getHRP(npc)
                if hum and hum.Health > 0 and hrp then
                    local dist = (hrp.Position - lpHRP.Position).Magnitude
                    if dist <= maxRange and dist < closestDist then
                        closestDist = dist
                        closest = npc
                    end
                end
            end
        end
        return closest
    end

    local function applyHighlight(targetModel)
        if not HighlightEnabled then return end
        if not targetModel then return end
        if currentHighlight and currentHighlight.Adornee == targetModel then return end
        if currentHighlight then currentHighlight:Destroy(); currentHighlight = nil end
        local hl = Instance.new("Highlight")
        hl.FillColor           = Color3.fromRGB(255, 255, 0)
        hl.OutlineColor        = Color3.fromRGB(255, 255, 0)
        hl.FillTransparency    = 0.5
        hl.OutlineTransparency = 0
        hl.Adornee = targetModel
        hl.Parent  = targetModel
        currentHighlight = hl
    end

    local function clearHighlight()
        if currentHighlight then currentHighlight:Destroy(); currentHighlight = nil end
        currentTargetType = nil
    end

    local function isSkillReady(toolName)
        if not toolName then return false end
        local pg = _LP:FindFirstChild("PlayerGui")
        if not pg then return false end
        local skillsFolder = pg:FindFirstChild("Main") and pg.Main:FindFirstChild("Skills")
        if not skillsFolder then return false end
        local toolFrame = skillsFolder:FindFirstChild(toolName)
        if not toolFrame then return false end
        for _, sk in ipairs({"Z","X","C","V"}) do
            local skill = toolFrame:FindFirstChild(sk)
            if skill and skill:FindFirstChild("Cooldown") and skill.Cooldown:IsA("Frame") then
                if skill.Cooldown.Size.X.Scale == 1.0 then return true end
            end
        end
        return false
    end

    -- Render loop
    local function startRenderLoop()
        if renderConn then return end
        renderConn = _RS.RenderStepped:Connect(function()
            local lpChar = _LP.Character
            if not lpChar then return end
            local lpHRP = lpChar:FindFirstChild("HumanoidRootPart")
            if not lpHRP then return end
            if not SilentAimPlayersEnabled and not SilentAimNPCsEnabled then return end

            local targetModel    = nil
            local lookTargetPos  = nil

            if SilentAimPlayersEnabled then
                local tp = getClosestPlayer(lpHRP)
                if tp and tp ~= _LP and tp.Character then
                    playersaimbot = tp.Name
                    PlayersPosition = getPredicted(getHRP(tp.Character))
                    lookTargetPos   = PlayersPosition
                    targetModel     = tp.Character
                    applyHighlight(targetModel)
                else
                    playersaimbot   = nil
                    PlayersPosition = nil
                    if currentTargetType == "player" then clearHighlight() end
                end
            end

            if SilentAimNPCsEnabled then
                local npc = getClosestNPC(lpHRP)
                if npc then
                    NPCaimbot  = npc.Name
                    NPCPosition = getPredicted(getHRP(npc))
                    lookTargetPos = lookTargetPos or NPCPosition
                    if not targetModel then
                        targetModel = npc
                        applyHighlight(npc)
                    end
                else
                    NPCaimbot   = nil
                    NPCPosition = nil
                    if currentTargetType == "NPC" then clearHighlight() end
                end
            end

            -- Auto face target when skill ready
            if currentTool and lookTargetPos and isSkillReady(currentTool.Name) then
                local lv = (Vector3.new(lookTargetPos.X, lpHRP.Position.Y, lookTargetPos.Z) - lpHRP.Position).Unit
                lpHRP.CFrame = CFrame.new(lpHRP.Position, lpHRP.Position + lv)
            end
        end)
    end

    local function stopRenderLoop()
        if renderConn then renderConn:Disconnect(); renderConn = nil end
    end

    -- Tool hook
    local function hookTool(tool)
        currentTool = tool
        table.insert(charConns, tool.AncestryChanged:Connect(function(_, parent)
            if not parent then currentTool = nil end
        end))
    end

    -- hookmetamethod for FireServer / InvokeServer
    spawn(function()
        local ok, hookMeta = pcall(getrawmetatable, game)
        if ok and hookMeta then
            setreadonly(hookMeta, false)
            local OldHook
            OldHook = hookmetamethod(game, "__namecall", function(self, V1, V2, ...)
                local Method = (getnamecallmethod and getnamecallmethod():lower()) or ""
                if tostring(self) == "RemoteEvent" and Method == "fireserver" then
                    if typeof(V1) == "Vector3" then
                        if SilentAimPlayersEnabled and PlayersPosition then
                            return OldHook(self, PlayersPosition, V2, ...)
                        elseif SilentAimNPCsEnabled and NPCPosition then
                            return OldHook(self, NPCPosition, V2, ...)
                        end
                    end
                elseif Method == "invokeserver" then
                    if currentTool and currentTool.Name == "Buddy Sword" then
                        if type(V1) == "string" and table.find(Skills, V1) then
                            if SilentAimPlayersEnabled and PlayersPosition then
                                return OldHook(self, V1, PlayersPosition, nil, ...)
                            elseif SilentAimNPCsEnabled and NPCPosition then
                                return OldHook(self, V1, NPCPosition, nil, ...)
                            end
                        end
                    end
                end
                return OldHook(self, V1, V2, ...)
            end)
            setreadonly(hookMeta, true)
        end
    end)

    -- AutoKen loop
    local function startAutoKenLoop()
        if autoKenRunning then return end
        autoKenRunning = true
        task.spawn(function()
            while AutoKen do
                task.wait(0.1)
                pcall(function()
                    local char = _LP.Character
                    if not char then return end
                    local HasTag = function(tag)
                        return game:GetService("CollectionService"):HasTag(char, tag)
                    end
                    if HasTag("Ken") then
                        local pg = _LP:FindFirstChild("PlayerGui")
                        if pg then
                            local kenBtn = pg:FindFirstChild("MobileContextButtons")
                                and pg.MobileContextButtons.ContextButtonFrame
                                and pg.MobileContextButtons.ContextButtonFrame:FindFirstChild("BoundActionKen")
                            if kenBtn and kenBtn:GetAttribute("Selected") ~= true then
                                kenBtn:SetAttribute("Selected", true)
                            end
                        end
                        local om = getrenv()._G.OM
                        if om and not om.active then
                            om.radius = 0
                            om:setActive(true)
                            if _commE then _commE:FireServer("Ken", true) end
                        end
                    end
                end)
            end
            autoKenRunning = false
        end)
    end

    -- Character handling
    local function onCharAdded(char)
        clearConns()
        for _, c in ipairs(char:GetChildren()) do
            if c:IsA("Tool") then hookTool(c) end
        end
        table.insert(charConns, char.ChildAdded:Connect(function(c)
            if c:IsA("Tool") then hookTool(c) end
        end))
        table.insert(charConns, char.ChildRemoved:Connect(function(c)
            if c == currentTool then currentTool = nil end
        end))
        -- Death reset
        local hum = char:FindFirstChildOfClass("Humanoid")
        if hum then
            hum.Died:Connect(function()
                local wasP = SilentAimPlayersEnabled
                local wasN = SilentAimNPCsEnabled
                SilentAimPlayersEnabled = false
                SilentAimNPCsEnabled    = false
                playersaimbot   = nil
                PlayersPosition = nil
                NPCaimbot       = nil
                NPCPosition     = nil
                task.wait(3)
                SilentAimPlayersEnabled = wasP and UserWantsPlayerAim or false
                SilentAimNPCsEnabled    = wasN and UserWantsNPCAim    or false
            end)
        end
    end

    _LP.CharacterAdded:Connect(onCharAdded)
    if _LP.Character then onCharAdded(_LP.Character) end

    -- Public API
    function M:SetPlayerSilentAim(state)
        UserWantsPlayerAim      = state
        SilentAimPlayersEnabled = state
        if state then startRenderLoop() else
            playersaimbot = nil; PlayersPosition = nil
            if not SilentAimNPCsEnabled then stopRenderLoop() end
        end
    end

    function M:SetNPCSilentAim(state)
        UserWantsNPCAim      = state
        SilentAimNPCsEnabled = state
        if state then startRenderLoop() else
            NPCaimbot = nil; NPCPosition = nil
            if not SilentAimPlayersEnabled then stopRenderLoop() end
        end
    end

    function M:SetMiniToggleNpcSilentAim(state)
        SilentAimNPCsEnabled = state
        if state then startRenderLoop() else
            NPCaimbot = nil; NPCPosition = nil
        end
    end

    function M:SetPrediction(state) PredictionEnabled = state end
    function M:SetPredictionAmount(v) PredictionAmount = v end
    function M:SetDistanceLimit(v) maxRange = v end
    function M:SetSelectedPlayer(name) Selectedplayer = name end
    function M:SetHighlight(state)
        HighlightEnabled = state
        if not state then clearHighlight() end
    end
    function M:SetAutoKen(state)
        AutoKen = state
        if state then startAutoKenLoop() end
    end
    function M:Pause()
        SilentAimPlayersEnabled = false
        SilentAimNPCsEnabled    = false
    end
    function M:Restore()
        SilentAimPlayersEnabled = UserWantsPlayerAim
        SilentAimNPCsEnabled    = UserWantsNPCAim
    end
    function M:IsPlayerAimEnabled() return SilentAimPlayersEnabled end

    return M
end)()

-- ============================================================
--  Z SKILL MODULE 
-- ============================================================
local ZSkillModule = (function()
    local M = {}

    local _Players  = game:GetService("Players")
    local _LP       = _Players.LocalPlayer
    local _RS       = game:GetService("RunService")
    local _UIS      = game:GetService("UserInputService")
    local _PG       = _LP:WaitForChild("PlayerGui")

    local currentTool        = nil
    local godhumanZActive    = false
    local dmgConn            = nil
    local charConns          = {}
    local aimlockActive      = false
    local aimRenderConn      = nil
    local aimTimeoutTask     = nil
    local nearestTarget      = nil
    local ZSkillsEnabled     = false
    local TargetInfo         = false
    local uiConn             = nil

    -- ── V & Z Skill tilt-aimbot state (Dough-Dough / Shark Anchor / Cursed Dual Katana) ──
    local camera             = workspace.CurrentCamera
    local vActive            = false
    local sharkZActive       = false
    local cursedZActive      = false
    local tiltEnabled        = false
    local rightTouches       = {}
    local tiltConn           = nil
    local preTiltCFrame      = nil

    -- Target Info UI
    local screenGui = Instance.new("ScreenGui")
    screenGui.Name = "BBGTargetUI"; screenGui.ResetOnSpawn = false
    screenGui.Parent = _PG

    local targetFrame = Instance.new("Frame", screenGui)
    targetFrame.Name = "TargetFrame"
    targetFrame.Size = UDim2.new(0.25,0,0.08,0)
    targetFrame.Position = UDim2.new(0.5,0,0.05,0)
    targetFrame.AnchorPoint = Vector2.new(0.5,0)
    targetFrame.BackgroundTransparency = 1
    targetFrame.Visible = false

    local targetName = Instance.new("TextLabel", targetFrame)
    targetName.Size = UDim2.new(1,0,0.5,0)
    targetName.BackgroundTransparency = 1
    targetName.TextScaled = true
    targetName.Font = Enum.Font.GothamBold
    targetName.TextColor3 = Color3.new(1,1,1)

    local hpBg = Instance.new("Frame", targetFrame)
    hpBg.Name = "HealthBarBackground"
    hpBg.Size = UDim2.new(1,0,0.35,0)
    hpBg.Position = UDim2.new(0,0,0.55,0)
    hpBg.BackgroundColor3 = Color3.fromRGB(40,40,40)
    hpBg.BorderSizePixel = 0

    local hpFill = Instance.new("Frame", hpBg)
    hpFill.Name = "HealthBarFill"
    hpFill.Size = UDim2.new(1,0,1,0)
    hpFill.BackgroundColor3 = Color3.fromRGB(0,255,0)
    hpFill.BorderSizePixel = 0

    -- Helpers (enemy check same as SA)
    local function isAllyWithMe(tp)
        local myGui = _LP:FindFirstChild("PlayerGui")
        if not myGui then return false end
        local scrolling = myGui:FindFirstChild("Main")
            and myGui.Main:FindFirstChild("Allies")
            and myGui.Main.Allies:FindFirstChild("Container")
            and myGui.Main.Allies.Container:FindFirstChild("Allies")
            and myGui.Main.Allies.Container.Allies:FindFirstChild("ScrollingFrame")
        if scrolling then
            for _, frame in pairs(scrolling:GetDescendants()) do
                if frame:IsA("ImageButton") and frame.Name == tp.Name then return true end
            end
        end
        return false
    end

    local function isEnemy(tp)
        if not tp or tp == _LP then return false end
        local myT = _LP.Team; local tpT = tp.Team
        if myT and tpT then
            if myT.Name == "Pirates" and tpT.Name == "Marines" then return true end
            if myT.Name == "Marines" and tpT.Name == "Pirates" then return true end
            if myT.Name == "Pirates" and tpT.Name == "Pirates" then return not isAllyWithMe(tp) end
            if myT.Name == "Marines" and tpT.Name == "Marines" then return false end
        end
        return true
    end

    local function GetNearestTarget(maxDist)
        local char = _LP.Character
        if not char or not char:FindFirstChild("HumanoidRootPart") then return nil end
        local hrp = char.HumanoidRootPart
        local closest, closestDist = nil, maxDist or 100
        for _, plr in ipairs(_Players:GetPlayers()) do
            if plr ~= _LP and isEnemy(plr) and plr.Character and plr.Character:FindFirstChild("HumanoidRootPart") then
                local oHRP = plr.Character.HumanoidRootPart
                local hum  = plr.Character:FindFirstChild("Humanoid")
                if oHRP and hum and hum.Health > 0 then
                    local dist = (oHRP.Position - hrp.Position).Magnitude
                    if dist < closestDist then closestDist = dist; closest = plr.Character end
                end
            end
        end
        return closest
    end

    local function clearConns()
        for _, c in ipairs(charConns) do pcall(function() c:Disconnect() end) end
        charConns = {}
        if dmgConn then pcall(function() dmgConn:Disconnect() end); dmgConn = nil end
        if aimRenderConn then pcall(function() aimRenderConn:Disconnect() end); aimRenderConn = nil end
        if aimTimeoutTask then pcall(function() task.cancel(aimTimeoutTask) end); aimTimeoutTask = nil end
    end

    local function stopAimlock()
        if not aimlockActive then return end
        aimlockActive = false; nearestTarget = nil; godhumanZActive = false
        if aimRenderConn then pcall(function() aimRenderConn:Disconnect() end); aimRenderConn = nil end
        if aimTimeoutTask then pcall(function() task.cancel(aimTimeoutTask) end); aimTimeoutTask = nil end
    end

    local function startAimlock()
        if not ZSkillsEnabled or aimlockActive then return end
        nearestTarget = GetNearestTarget(1000)
        if not nearestTarget then return end
        aimlockActive = true
        aimRenderConn = _RS.RenderStepped:Connect(function()
            if not ZSkillsEnabled then stopAimlock(); return end
            if aimlockActive and nearestTarget and nearestTarget:FindFirstChild("HumanoidRootPart") then
                local cam = workspace.CurrentCamera
                if cam then cam.CFrame = CFrame.lookAt(cam.CFrame.Position, nearestTarget.HumanoidRootPart.Position) end
            else
                stopAimlock()
            end
        end)
        aimTimeoutTask = task.delay(1, function()
            if aimlockActive then stopAimlock() end
        end)
    end

    local function watchDmgCounter()
        if not ZSkillsEnabled then return end
        if dmgConn then pcall(function() dmgConn:Disconnect() end); dmgConn = nil end
        local gui = _LP:WaitForChild("PlayerGui"):WaitForChild("Main", 5)
        if not gui then return end
        local dmgCounter = gui:FindFirstChild("DmgCounter")
        if not dmgCounter then
            table.insert(charConns, gui.ChildAdded:Connect(function(child)
                if child.Name == "DmgCounter" then task.wait(); watchDmgCounter() end
            end))
            return
        end
        local dmgText = dmgCounter:FindFirstChild("Text")
        if not dmgText then
            table.insert(charConns, dmgCounter.ChildAdded:Connect(function(child)
                if child.Name == "Text" then task.wait(); watchDmgCounter() end
            end))
            return
        end
        dmgConn = dmgText:GetPropertyChangedSignal("Text"):Connect(function()
            if not ZSkillsEnabled then return end
            local n = tonumber(dmgText.Text) or 0
            if n > 0 and aimlockActive then stopAimlock() end

            -- Enable tilt-aimbot for V/Z skill fruits on damage
            if n > 0 and canTilt() then
                tiltEnabled = true
                if next(rightTouches) then startTilt() end
            else
                tiltEnabled = false
                stopTiltSmooth()
            end
        end)
    end

    local function hookTool(tool)
        if not tool then return end
        currentTool = tool
        table.insert(charConns, tool.AncestryChanged:Connect(function(_, parent)
            if not parent then
                currentTool = nil; godhumanZActive = false; aimlockActive = false
                vActive = false; sharkZActive = false; cursedZActive = false
                tiltEnabled = false; rightTouches = {}
            end
        end))
    end

    -- ── V & Z Skill tilt-aimbot helpers ────────────────────────
    local function canTilt()
        return (currentTool and currentTool.Name == "Dough-Dough" and vActive)
            or (currentTool and currentTool.Name == "Shark Anchor" and sharkZActive)
            or (currentTool and currentTool.Name == "Cursed Dual Katana" and cursedZActive)
    end

    local function disconnectTiltConn()
        if tiltConn then
            pcall(function() tiltConn:Disconnect() end)
            tiltConn = nil
        end
    end

    local function stopTiltSmooth()
        disconnectTiltConn()
        if not preTiltCFrame then return end
        local startCF = camera.CFrame
        local endCF   = preTiltCFrame
        preTiltCFrame = nil
        local a = 0
        local restoreConn
        restoreConn = _RS.RenderStepped:Connect(function(dt)
            a = math.min(a + dt * 5, 1)
            camera.CFrame = startCF:Lerp(endCF, a)
            if a >= 1 then restoreConn:Disconnect() end
        end)
    end

    local function startTilt()
        disconnectTiltConn()
        preTiltCFrame = preTiltCFrame or camera.CFrame
        local char = _LP.Character
        local hrp  = char and char:FindFirstChild("HumanoidRootPart")
        local hum  = char and char:FindFirstChildOfClass("Humanoid")
        if not hrp or not hum then return end

        local startCF = camera.CFrame
        local camPos  = startCF.Position

        local tiltOffset
        if hum.FloorMaterial ~= Enum.Material.Air then
            tiltOffset = Vector3.new(0, 6, 0)
        else
            tiltOffset = Vector3.new(0, 40, 0)
        end

        local downLook = hrp.Position - tiltOffset
        local targetCF = CFrame.new(camPos, downLook)

        local alpha = 0
        tiltConn = _RS.RenderStepped:Connect(function(dt)
            if not (tiltEnabled and next(rightTouches) and hrp.Parent) then
                stopTiltSmooth()
                return
            end
            if alpha < 1 then
                alpha = math.min(alpha + dt * 2, 1)
                camera.CFrame = startCF:Lerp(targetCF, alpha)
            else
                camera.CFrame = targetCF
            end
        end)
    end

    -- Touch input for Godhuman Z
    _UIS.TouchEnded:Connect(function(touch)
        if not ZSkillsEnabled then return end
        local cam = workspace.CurrentCamera
        if not cam or not touch or not touch.Position then return end
        if touch.Position.X > cam.ViewportSize.X / 2 then
            if currentTool and currentTool.Name == "Godhuman" and godhumanZActive then
                if not aimlockActive then startAimlock() end
            end
        end
    end)

    -- ── Touch tracking for V/Z skill tilt-aimbot ────────────────
    _UIS.TouchStarted:Connect(function(touch)
        if not ZSkillsEnabled then return end
        camera = workspace.CurrentCamera
        if not camera then return end
        if touch.Position.X > camera.ViewportSize.X / 2 then
            rightTouches[touch] = true
            if tiltEnabled and canTilt() then
                startTilt()
            end
        end
    end)

    _UIS.TouchEnded:Connect(function(touch)
        if not ZSkillsEnabled then return end
        if rightTouches[touch] then
            rightTouches[touch] = nil
            if not next(rightTouches) then
                stopTiltSmooth()
                tiltEnabled = false
                vActive = false; sharkZActive = false; cursedZActive = false
            end
        end
    end)

    -- hookmetamethod for Z/V skill detection
    if not getgenv().ZSkillHooked then
        getgenv().ZSkillHooked = true
        pcall(function()
            local oldNC
            oldNC = hookmetamethod(game, "__namecall", function(self, ...)
                local method = getnamecallmethod()
                local args   = {...}
                if method == "InvokeServer" or method == "FireServer" then
                    local a1 = args[1]

                    if typeof(a1) == "string" and a1:upper() == "Z" then
                        if currentTool and currentTool.Name == "Godhuman" then
                            godhumanZActive = true
                        end
                        if currentTool and currentTool.Name == "Shark Anchor" then
                            sharkZActive = true
                            local stamp = os.clock()
                            task.delay(2, function()
                                if os.clock() - stamp >= 2 then
                                    sharkZActive = false
                                    if tiltEnabled and next(rightTouches) then
                                        tiltEnabled = false; stopTiltSmooth(); rightTouches = {}
                                    end
                                end
                            end)
                        end
                        if currentTool and currentTool.Name == "Cursed Dual Katana" then
                            cursedZActive = true
                            local stamp = os.clock()
                            task.delay(2, function()
                                if os.clock() - stamp >= 2 then
                                    cursedZActive = false
                                    if tiltEnabled and next(rightTouches) then
                                        tiltEnabled = false; stopTiltSmooth(); rightTouches = {}
                                    end
                                end
                            end)
                        end
                    end

                    if typeof(a1) == "string" and a1:upper() == "V" then
                        if currentTool and currentTool.Name == "Dough-Dough" then
                            vActive = true
                            local stamp = os.clock()
                            task.delay(2, function()
                                if os.clock() - stamp >= 2 then
                                    vActive = false
                                    if tiltEnabled and next(rightTouches) then
                                        tiltEnabled = false; stopTiltSmooth(); rightTouches = {}
                                    end
                                end
                            end)
                        end
                    end
                end
                return oldNC(self, ...)
            end)
        end)
    end

    -- Character handling
    local function onCharAdded(char)
        if char ~= _LP.Character then return end
        clearConns()
        godhumanZActive = false
        vActive = false; sharkZActive = false; cursedZActive = false
        tiltEnabled = false; rightTouches = {}
        camera = workspace.CurrentCamera
        for _, c in ipairs(char:GetChildren()) do
            if c:IsA("Tool") then hookTool(c) end
        end
        table.insert(charConns, char.ChildAdded:Connect(function(c)
            if c:IsA("Tool") then hookTool(c) end
        end))
        table.insert(charConns, char.ChildRemoved:Connect(function(c)
            if c == currentTool then
                currentTool = nil; godhumanZActive = false
                vActive = false; sharkZActive = false; cursedZActive = false
                tiltEnabled = false; rightTouches = {}
            end
        end))
        watchDmgCounter()
    end

    _LP.CharacterAdded:Connect(onCharAdded)
    if _LP.Character then onCharAdded(_LP.Character) end

    -- Public API
    function M:SetZSkills(state)
        ZSkillsEnabled = state
        if not state then stopAimlock(); clearConns() end
    end

    function M:SetInfo(state)
        TargetInfo = state
        if state then
            if not uiConn then
                uiConn = _RS.RenderStepped:Connect(function()
                    local target = GetNearestTarget(1000)
                    if target and target:FindFirstChild("Humanoid") then
                        local hp = target.Humanoid
                        targetName.Text = target.Name
                        local fill = math.clamp(hp.Health / hp.MaxHealth, 0, 1)
                        hpFill.Size = UDim2.new(fill, 0, 1, 0)
                        hpBg.Visible = true; hpFill.Visible = true
                        targetFrame.Visible = true
                    else
                        targetName.Text = "No target"
                        hpBg.Visible = false; hpFill.Visible = false
                        targetFrame.Visible = true
                    end
                end)
            end
        else
            if uiConn then uiConn:Disconnect(); uiConn = nil end
            targetFrame.Visible = false
        end
    end

    return M
end)()

-- ============================================================
--  WIRE SA VARIABLES to existing BBG hooks
-- ============================================================
-- Override SA_Playersaimbot and SA_PlayersPosition to use module values
-- (BBG's metatable hook reads these)
local SA_Enabled     = false
local SA_AimLock     = false
local SA_FOVEnabled  = false
local SA_FOVSize     = 100
local SA_MaxDist     = 1000
local SA_TeamCheck   = false
local SA_Playersaimbot   = nil
local SA_PlayersPosition = nil

-- Sync from module every frame
RunService.Heartbeat:Connect(function()
    SA_Playersaimbot   = SilentAimModule._getPlayersAimbot()
    SA_PlayersPosition = SilentAimModule._getPlayersPosition()
        or SilentAimModule._getNPCPosition()
end)

-- ============================================================
--  AIM LOCK — Team Check supported
-- ============================================================
local function SA_IsTeammate(p)
    -- Team check: agar dono same team pe hain toh true return karo
    if not SA_TeamCheck then return false end
    local ok, result = pcall(function()
        return LP.Team ~= nil and p.Team ~= nil and LP.Team == p.Team
    end)
    return ok and result or false
end

local function SA_GetClosestForLock()
    local myHRP = LP.Character and LP.Character:FindFirstChild("HumanoidRootPart")
    if not myHRP then return nil end
    local best, bestDist = nil, SA_MaxDist
    for _, p in ipairs(Players:GetPlayers()) do
        if p ~= LP and p.Character then
            -- Team Check: teammate ko skip karo
            if SA_IsTeammate(p) then continue end
            local hum = p.Character:FindFirstChildOfClass("Humanoid")
            local hrp = p.Character:FindFirstChild("HumanoidRootPart")
            if hum and hrp and hum.Health > 0 then
                local d = (myHRP.Position - hrp.Position).Magnitude
                if d < bestDist then bestDist = d; best = p end
            end
        end
    end
    return best
end

-- Fix target: stable lock — sirf switch ho jab target dead/out of range ho
local _lockedTarget = nil

local function isTargetValid(p)
    if not p or not p.Character then return false end
    -- Re-check team status on every validation
    if SA_IsTeammate(p) then return false end
    local hum = p.Character:FindFirstChildOfClass("Humanoid")
    local hrp = p.Character:FindFirstChild("HumanoidRootPart")
    if not hum or not hrp or hum.Health <= 0 then return false end
    local myHRP = LP.Character and LP.Character:FindFirstChild("HumanoidRootPart")
    if not myHRP then return false end
    return (myHRP.Position - hrp.Position).Magnitude <= SA_MaxDist
end

RunService.Heartbeat:Connect(function()
    if not SA_AimLock then
        _lockedTarget = nil
        return
    end
    -- Only find new target if current one is invalid
    if not isTargetValid(_lockedTarget) then
        _lockedTarget = SA_GetClosestForLock()
    end
    if not _lockedTarget or not _lockedTarget.Character then return end
    local part = _lockedTarget.Character:FindFirstChild("Head")
             or _lockedTarget.Character:FindFirstChild("HumanoidRootPart")
    if not part then return end
    Camera.CFrame = CFrame.new(Camera.CFrame.Position, part.Position)
end)

-- ============================================================
--  AIMBOT LOCK MINI FLOATING WINDOW 
--  Exact same pattern: draggable gradient button, ON/OFF toggle
-- ============================================================
local aimbotLockEnabled = false

local abGui = Instance.new("ScreenGui")
abGui.Name           = "BBGAimLock"
abGui.ResetOnSpawn   = false
abGui.IgnoreGuiInset = true
abGui.DisplayOrder   = 1003
abGui.Enabled        = false
abGui.Parent         = game:GetService("CoreGui")

local abBtn = Instance.new("TextButton")
abBtn.Size           = UDim2.new(0, 140, 0, 45)
abBtn.Position       = UDim2.new(0, 20, 0.42, 0)
abBtn.TextScaled     = true
abBtn.TextColor3              = Color3.new(1, 1, 1)
abBtn.TextStrokeColor3        = Color3.fromRGB(0,0,0)
abBtn.TextStrokeTransparency  = 0.4
abBtn.BorderSizePixel= 0
abBtn.Font           = Enum.Font.GothamBold
abBtn.AutoButtonColor= false
abBtn.Parent         = abGui

local abCorner = Instance.new("UICorner", abBtn)
abCorner.CornerRadius = UDim.new(0, 8)

local abGrad = Instance.new("UIGradient", abBtn)
abGrad.Rotation = 45

local function refreshAbBtn()
    abBtn.Text = "🎯 Aim Lock  " .. (aimbotLockEnabled and "ON" or "OFF")
    abGrad.Color = ColorSequence.new{
        ColorSequenceKeypoint.new(0, Color3.fromRGB(100, 10, 10)),
        ColorSequenceKeypoint.new(1, Color3.fromRGB(180, 30, 30)),
    }
end

abBtn.MouseButton1Click:Connect(function()
    aimbotLockEnabled = not aimbotLockEnabled
    SA_AimLock        = aimbotLockEnabled
    refreshAbBtn()
end)

-- Draggable (exact same as EClaw boost)
local _abDrag, _abStart, _abPos = false, nil, nil
abBtn.InputBegan:Connect(function(i)
    if i.UserInputType == Enum.UserInputType.Touch
    or i.UserInputType == Enum.UserInputType.MouseButton1 then
        _abDrag = true; _abStart = i.Position; _abPos = abBtn.Position
        i.Changed:Connect(function()
            if i.UserInputState == Enum.UserInputState.End then _abDrag = false end
        end)
    end
end)
abBtn.InputChanged:Connect(function(i)
    if _abDrag and (i.UserInputType == Enum.UserInputType.Touch
    or i.UserInputType == Enum.UserInputType.MouseMovement) then
        local d = i.Position - _abStart
        local vp = Camera.ViewportSize
        abBtn.Position = UDim2.new(0,
            math.clamp(_abPos.X.Offset + d.X, 0, vp.X - abBtn.AbsoluteSize.X),
            0,
            math.clamp(_abPos.Y.Offset + d.Y, 0, vp.Y - abBtn.AbsoluteSize.Y))
    end
end)

refreshAbBtn()


-- ============================================================
--  ANTI LAVA ENGINE  (Sacred source)
-- ============================================================
local function startAntiLava()
    if antiLavaConnection then antiLavaConnection:Disconnect() end
    antiLavaConnection = RunService.Stepped:Connect(function()
        local char = LP.Character
        if not (char and antiLavaActive) then return end
        for _, part in pairs(char:GetDescendants()) do
            if part:IsA("BasePart") and part.Name ~= "HumanoidRootPart"
            and part.Name ~= "Torso" and part.Name ~= "UpperTorso"
            and part.Name ~= "LowerTorso" and part.Name ~= "Head" then
                part.CanTouch = false
            end
        end
    end)
end
local function stopAntiLava()
    if antiLavaConnection then antiLavaConnection:Disconnect(); antiLavaConnection = nil end
end

-- ============================================================
--  DELETE GHOST SHIP ENGINE  (Sea 2 — Sacred source)
-- ============================================================
local function deleteShipStructure()
    if not deleteShipActive then return end
    task.spawn(function()
        local shipNames     = {"CursedShip","Cursed Ship","Ship"}
        local exteriorNames = {"Wall","Floor","Ceiling","Base","Hull","Window","DoorFrame"}
        for _, obj in pairs(workspace:GetDescendants()) do
            for _, sName in pairs(shipNames) do
                if obj.Name:find(sName) and (obj:IsA("Model") or obj:IsA("Folder")) then
                    for _, child in pairs(obj:GetDescendants()) do
                        if child:IsA("BasePart") and not child.Parent:FindFirstChild("Humanoid") then
                            local isExterior = false
                            for _, ext in pairs(exteriorNames) do
                                if child.Name:find(ext) then isExterior = true; break end
                            end
                            if not isExterior then child:Destroy() end
                        end
                    end
                end
            end
        end
    end)
end
local function startDeleteShipLoop()
    if deleteShipRunning then return end
    deleteShipRunning = true
    task.spawn(function()
        while deleteShipActive do
            deleteShipStructure()
            task.wait(3)
        end
        deleteShipRunning = false
    end)
end

-- ============================================================
--  NO COOLDOWN ENGINE  (Sacred source — item switch during combat)
-- ============================================================
local function enableNoCooldown()
    NoCooldownEnabled = true
    pcall(function()
        local pgui = LP:FindFirstChild("PlayerGui")
        local main = pgui and pgui:FindFirstChild("Main")
        if main then
            local notifFrame = main:FindFirstChild("Notificaciones") or main:FindFirstChild("Notification")
            if notifFrame then notifFrame:Destroy() end
        end
    end)
    if LP.Character then LP.Character:SetAttribute("AllCooldown", 3) end
end
local function disableNoCooldown()
    NoCooldownEnabled = false
    if LP.Character then LP.Character:SetAttribute("AllCooldown", 0) end
end
LP.CharacterAdded:Connect(function(char)
    if NoCooldownEnabled then char:SetAttribute("AllCooldown", 3) end
end)

-- Hook into __namecall to bypass cooldown notification + item switching mid-combat
do
    local mt = getrawmetatable(game)
    local oldNamecall = mt.__namecall
    setreadonly(mt, false)
    mt.__namecall = newcclosure(function(self, ...)
        local method = getnamecallmethod()
        local args = {...}

        if NoCooldownEnabled and method == "InvokeServer"
        and tostring(self) == "CommF_" then
            if args[1] == "Notification" then return nil end
        end

        return oldNamecall(self, ...)
    end)
    setreadonly(mt, true)
end

task.spawn(function()
    while true do
        task.wait(0.5)
        if NoCooldownEnabled then
            local char = LP.Character
            if not char then continue end
            local function isInCombat()
                local gui    = LP:FindFirstChild("PlayerGui")
                local main   = gui and gui:FindFirstChild("Main")
                local hud    = main and main:FindFirstChild("BottomHUDList")
                local combat = hud  and hud:FindFirstChild("InCombat")
                return combat and combat.Visible == true
            end
            if isInCombat() then
                char:SetAttribute("AllCooldown", 0)
                repeat task.wait(0.1) until not isInCombat()
                char:SetAttribute("AllCooldown", 3)
            end
        end
    end
end)

-- ============================================================
--  TAB: BBG STRAP
-- ============================================================

-- ============================================================
--  RAJAWARE ELITE MINI WINDOW  (pure red gradient, Sang Z style)
-- ============================================================
local function BuildRajawareWindow()
    if _RajawareGui then _RajawareGui:Destroy(); _RajawareGui = nil end

    local ACCENT = Color3.fromRGB(220, 30, 30)
    local ON1, ON2   = Color3.fromRGB(100, 10, 10), Color3.fromRGB(180, 30, 30)
    local OFF1, OFF2 = Color3.fromRGB(100, 10, 10), Color3.fromRGB(180, 30, 30)

    local sg = Instance.new("ScreenGui")
    sg.Name = "BBGRajawareFloat"
    sg.ResetOnSpawn = false
    sg.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    sg.IgnoreGuiInset = true
    sg.DisplayOrder = 1010
    sg.Parent = game:GetService("CoreGui")
    _RajawareGui = sg

    local fr = Instance.new("Frame", sg)
    fr.Size = UDim2.new(0, 170, 0, 96)
    fr.Position = UDim2.new(0, 20, 0.72, 0)
    fr.BackgroundColor3 = Color3.fromRGB(12, 8, 8)
    fr.BorderSizePixel = 0
    fr.Active = true
    fr.Draggable = true
    Instance.new("UICorner", fr).CornerRadius = UDim.new(0, 10)
    local fs = Instance.new("UIStroke", fr)
    fs.Color = ACCENT; fs.Thickness = 1.5

    local title = Instance.new("TextLabel", fr)
    title.Size = UDim2.new(1, -28, 0, 24)
    title.Position = UDim2.new(0, 0, 0, 4)
    title.BackgroundTransparency = 1
    title.Text = "Rajaware Elite"
    title.TextColor3 = ACCENT
    title.TextStrokeColor3 = Color3.fromRGB(0,0,0)
    title.TextStrokeTransparency = 0.4
    title.Font = Enum.Font.GothamBold
    title.TextSize = 12

    local minimized = false
    local minBtn = Instance.new("TextButton", fr)
    minBtn.Size = UDim2.new(0, 22, 0, 22)
    minBtn.Position = UDim2.new(1, -26, 0, 4)
    minBtn.Text = "–"
    minBtn.TextColor3 = ACCENT
    minBtn.TextStrokeColor3 = Color3.fromRGB(0,0,0)
    minBtn.TextStrokeTransparency = 0.4
    minBtn.Font = Enum.Font.GothamBold
    minBtn.TextSize = 14
    minBtn.BackgroundColor3 = Color3.fromRGB(28, 14, 14)
    minBtn.BorderSizePixel = 0
    minBtn.AutoButtonColor = false
    Instance.new("UICorner", minBtn).CornerRadius = UDim.new(0, 6)

    local cf = Instance.new("Frame", fr)
    cf.Size = UDim2.new(1, 0, 1, -30)
    cf.Position = UDim2.new(0, 0, 0, 30)
    cf.BackgroundTransparency = 1
    cf.ClipsDescendants = true

    minBtn.MouseButton1Click:Connect(function()
        minimized = not minimized
        if minimized then
            minBtn.Text = "+"
            fr.Size = UDim2.new(0, 170, 0, 30)
            cf.Visible = false
        else
            minBtn.Text = "–"
            fr.Size = UDim2.new(0, 170, 0, 96)
            cf.Visible = true
        end
    end)

    -- Big Lag ON/OFF gradient button
    local lagBtn = Instance.new("TextButton", cf)
    lagBtn.Size = UDim2.new(1, -16, 0, 50)
    lagBtn.Position = UDim2.new(0, 8, 0, 8)
    lagBtn.BorderSizePixel = 0
    lagBtn.Font = Enum.Font.GothamBold
    lagBtn.TextSize = 16
    lagBtn.TextColor3 = Color3.new(1,1,1)
    lagBtn.TextStrokeColor3 = Color3.fromRGB(0,0,0)
    lagBtn.TextStrokeTransparency = 0.4
    lagBtn.AutoButtonColor = false
    Instance.new("UICorner", lagBtn).CornerRadius = UDim.new(0, 9)
    local lagGrad = Instance.new("UIGradient", lagBtn)
    lagGrad.Rotation = 45

    local function refreshLagBtn()
        lagBtn.Text = "Lag  " .. (RajawareLagEnabled and "ON" or "OFF")
        lagGrad.Color = ColorSequence.new{
            ColorSequenceKeypoint.new(0, RajawareLagEnabled and ON1 or OFF1),
            ColorSequenceKeypoint.new(1, RajawareLagEnabled and ON2 or OFF2),
        }
    end
    refreshLagBtn()

    lagBtn.MouseButton1Click:Connect(function()
        RajawareLagEnabled = not RajawareLagEnabled
        refreshLagBtn()
        if RajawareLagEnabled then
            startRajawareLag()
        else
            stopRajawareLag()
        end
        Rayfield:Notify({Title="Rajaware Elite", Content="Lag "..(RajawareLagEnabled and "ON — continuous lag active" or "OFF — lag stopped"), Duration=2})
    end)

    -- Draggable (touch + mouse)
    local drag, dStart, dPos = false, nil, nil
    fr.InputBegan:Connect(function(i)
        if i.UserInputType == Enum.UserInputType.Touch
        or i.UserInputType == Enum.UserInputType.MouseButton1 then
            drag = true; dStart = i.Position; dPos = fr.Position
            i.Changed:Connect(function()
                if i.UserInputState == Enum.UserInputState.End then drag = false end
            end)
        end
    end)
    fr.InputChanged:Connect(function(i)
        if drag and (i.UserInputType == Enum.UserInputType.Touch
        or i.UserInputType == Enum.UserInputType.MouseMovement) then
            local d = i.Position - dStart
            local vp = workspace.CurrentCamera.ViewportSize
            fr.Position = UDim2.new(0,
                math.clamp(dPos.X.Offset + d.X, 0, vp.X - fr.AbsoluteSize.X),
                0,
                math.clamp(dPos.Y.Offset + d.Y, 0, vp.Y - fr.AbsoluteSize.Y)
            )
        end
    end)
end

-- ============================================================
--  TAB: RAJAWARE ELITE
-- ============================================================
local RajawareTab = Window:CreateTab("Rajaware Elite", 4483362458)

RajawareTab:CreateSection("Rajaware Elite")

RajawareTab:CreateToggle({
    Name="Rajaware Elite", CurrentValue=false, Flag="Rajaware_Main",
    Callback=function(v)
        RajawareEliteEnabled = v
        if v then
            BuildRajawareWindow()
            Rayfield:Notify({Title="Rajaware Elite", Content="ON", Duration=2})
        else
            if _RajawareGui then _RajawareGui:Destroy(); _RajawareGui = nil end
            RajawareLagEnabled = false
            stopRajawareLag()
            Rayfield:Notify({Title="Rajaware Elite", Content="OFF", Duration=2})
        end
    end,
})

-- ============================================================
--  TAB: BBG STRAP
-- ============================================================
local BBGStrapTab = Window:CreateTab("BBG Strap", 4483362458)

-- ── Section: BBG Strap ──────────────────────────────────────
BBGStrapTab:CreateSection("BBG Strap")

-- BBG Strap Window Toggle (default OFF)
local _bbgStrapGui = nil

BBGStrapTab:CreateToggle({
    Name = "BBG Strap Window",
    CurrentValue = false,
    Flag = "BBGS_Window",
    Callback = function(v)
        if v then
            -- BBG Strap mini floating window kholo
            if _bbgStrapGui then
                _bbgStrapGui.Enabled = true
                return
            end

            local Players    = game:GetService("Players")
            local HttpService = game:GetService("HttpService")
            local StarterGui  = game:GetService("StarterGui")
            local LP          = Players.LocalPlayer

            local C = {
                bg      = Color3.fromRGB(10, 10, 12),
                card    = Color3.fromRGB(18, 18, 20),
                cardHov = Color3.fromRGB(26, 26, 30),
                accent  = Color3.fromRGB(220, 30, 30),
                selBtn  = Color3.fromRGB(160, 20, 20),
                muted   = Color3.fromRGB(140, 135, 140),
                white   = Color3.fromRGB(235, 235, 235),
                btnOff  = Color3.fromRGB(30, 30, 34),
                stroke  = Color3.fromRGB(80, 80, 88),
            }

            local function _mkFrame(parent, size, pos, color, radius)
                local f = Instance.new("Frame")
                f.Size, f.Position, f.BackgroundColor3 = size, pos, color or C.bg
                f.BorderSizePixel = 0
                f.Parent = parent
                if radius then Instance.new("UICorner", f).CornerRadius = UDim.new(0, radius) end
                return f
            end
            local function _mkText(parent, text, size, pos, color, fontSize, bold)
                local l = Instance.new("TextLabel")
                l.Size, l.Position = size, pos
                l.Text, l.TextColor3 = text, color or C.white
                l.TextSize = fontSize or 13
                l.Font = bold and Enum.Font.GothamBold or Enum.Font.Gotham
                l.BackgroundTransparency, l.BorderSizePixel = 1, 0
                l.Parent = parent
                return l
            end
            local function _mkBtn(parent, text, size, pos, bgColor, txtColor, radius)
                local b = Instance.new("TextButton")
                b.Size, b.Position = size, pos
                b.Text, b.TextColor3 = text, txtColor or C.white
                b.TextSize, b.Font = 13, Enum.Font.GothamBold
                b.BackgroundColor3 = bgColor or C.card
                b.BorderSizePixel, b.AutoButtonColor = 0, false
                b.Parent = parent
                if radius then Instance.new("UICorner", b).CornerRadius = UDim.new(0, radius) end
                return b
            end
            local function _mkTextBox(parent, placeholder, size, pos, fontSize)
                local t = Instance.new("TextBox")
                t.Size, t.Position = size, pos
                t.PlaceholderText = placeholder
                t.Text = ""
                t.TextColor3 = C.white
                t.PlaceholderColor3 = C.muted
                t.BackgroundColor3 = C.cardHov
                t.BorderSizePixel = 0
                t.Font = Enum.Font.Gotham
                t.TextSize = fontSize or 12
                t.TextXAlignment = Enum.TextXAlignment.Left
                t.TextYAlignment = Enum.TextYAlignment.Top
                t.MultiLine = true
                t.ClearTextOnFocus = false
                t.Parent = parent
                Instance.new("UICorner", t).CornerRadius = UDim.new(0, 8)
                local pad = Instance.new("UIPadding", t)
                pad.PaddingLeft = UDim.new(0, 6)
                pad.PaddingTop  = UDim.new(0, 4)
                return t
            end
            local function _addStroke(parent, color, thickness)
                local s = Instance.new("UIStroke", parent)
                s.Color = color or C.stroke
                s.Thickness = thickness or 1
            end
            local function _makeDraggable(target, handle)
                local dragging, dragStart, startX, startY
                handle.InputBegan:Connect(function(inp)
                    if inp.UserInputType == Enum.UserInputType.Touch
                    or inp.UserInputType == Enum.UserInputType.MouseButton1 then
                        dragging = true
                        dragStart = inp.Position
                        startX = target.Position.X.Offset
                        startY = target.Position.Y.Offset
                    end
                end)
                handle.InputChanged:Connect(function(inp)
                    if dragging and (inp.UserInputType == Enum.UserInputType.MouseMovement
                    or inp.UserInputType == Enum.UserInputType.Touch) then
                        local d = inp.Position - dragStart
                        local vp = workspace.CurrentCamera.ViewportSize
                        local newX = math.clamp(startX + d.X, 0, vp.X - target.AbsoluteSize.X)
                        local newY = math.clamp(startY + d.Y, -(target.AbsoluteSize.Y - 36), vp.Y - 36)
                        target.Position = UDim2.new(0, newX, 0, newY)
                    end
                end)
                handle.InputEnded:Connect(function(inp)
                    if inp.UserInputType == Enum.UserInputType.Touch
                    or inp.UserInputType == Enum.UserInputType.MouseButton1 then
                        dragging = false
                    end
                end)
            end
            local function _notify(title, text, duration)
                StarterGui:SetCore("SendNotification", { Title=title, Text=text, Duration=duration or 3 })
            end

            local DEFAULT_FFLAGS = [[{"FFlagEnableAccessibilitySettingsEffectsInExperienceChat":"True","FFlagEnableToastLiteRender":"true","FFlagRenderEnableGlobalInstancingD3D11":"true","DFFlagTeleportPreloadingMetrics5":"true","FFlagReduceTextureMemory":"True","DFFlagRakNetDetectNetUnreachable":"True","DFIntReplicationBatchSize":"32","DFFlagQueueDataPingFromSendData":"True","DFIntRenderThrottlePercentage":"100","DFFlagFixUIRenderModifierUnibarBug":"true","DFIntMemoryCleanupDelay":"1000","DFIntTexturePoolSize":"512","FFlagPushFrameTimeToHarmony":"true","FFlagRenderFixULGlassRefraction":"true","DFFlagPerformanceControlEnableMemoryProbing3":"true","DFIntMobileTextureQuality":"2","FFlagQuaternionPoseCorrection":"true","DFFlagRakNetEnablePoll":"true","FFlagLuauCodegen":"true","FFlagDisablePostFx":"true","FFlagOptimizeMobileRendering":"True","FFlagOptimizeAvatarLoading":"True","DFIntTaskSchedulerTargetFps":"29383","FFlagFixInputLag":"True","FFlagEnablePingOptimizations":"True","FFlagDebugDisableTelemetryV2Stat":"True","FFlagDebugDisableTelemetryEphemeralStat":"True","FFlagDebugDisableTelemetryV2Counter":"True","FFlagDebugDisableTelemetryV2Event":"True","FFlagDebugDisableTelemetryPoint":"True","FIntRomarkStartWithGraphicQualityLevel":"1","DFIntDebugFRMQualityLevelOverride":"1","DFFlagTextureQualityOverrideEnabled":"true","DFIntTextureQualityOverride":"1"}]]

            local function _applyFflags(jsonStr)
                local ok, decoded = pcall(function() return HttpService:JSONDecode(jsonStr) end)
                if not ok or type(decoded) ~= "table" then
                    _notify("BBG Strap", "Invalid JSON!", 3)
                    return 0
                end
                local count = 0
                for k, val in pairs(decoded) do
                    pcall(function()
                        setfflag(
                            tostring(k:gsub("^[DF]*Flag",""):gsub("^[DF]*Int",""):gsub("^[DF]*String","")),
                            tostring(val)
                        )
                    end)
                    count = count + 1
                end
                return count
            end

            -- GUI
            local gui = Instance.new("ScreenGui")
            gui.Name = "BBG_Strap"
            gui.ResetOnSpawn = false
            gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
            gui.Parent = game:GetService("CoreGui")
            _bbgStrapGui = gui

            local FRAME_W, FRAME_H = 300, 310
            local main = _mkFrame(gui,
                UDim2.new(0, FRAME_W, 0, FRAME_H),
                UDim2.new(0.5, -FRAME_W/2, 0.5, -FRAME_H/2),
                C.bg, 14)
            _addStroke(main, C.accent, 1.5)
            main.ClipsDescendants = true

            local titleBar = _mkFrame(main, UDim2.new(1,0,0,36), UDim2.new(0,0,0,0), C.card, 14)
            titleBar.ZIndex = 3
            _mkText(titleBar, "BBG STRAP",
                UDim2.new(1,-42,1,0), UDim2.new(0,14,0,0), C.accent, 13, true).ZIndex = 4

            local minBtn = Instance.new("TextButton", titleBar)
            minBtn.Size = UDim2.new(0,28,0,28)
            minBtn.Position = UDim2.new(1,-34,0,4)
            minBtn.Text = "–"
            minBtn.TextColor3             = Color3.fromRGB(220, 30, 30)
            minBtn.TextStrokeColor3       = Color3.fromRGB(0, 0, 0)
            minBtn.TextStrokeTransparency = 0.4
            minBtn.Font = Enum.Font.GothamBold
            minBtn.TextSize = 18
            minBtn.BackgroundColor3 = C.cardHov
            minBtn.BorderSizePixel = 0
            minBtn.AutoButtonColor = false
            minBtn.ZIndex = 5
            Instance.new("UICorner", minBtn).CornerRadius = UDim.new(0, 6)

            _makeDraggable(main, main)

            local minimized = false
            local contentFrame = _mkFrame(main, UDim2.new(1,0,1,-36), UDim2.new(0,0,0,36), C.bg)
            contentFrame.BackgroundTransparency = 1

            minBtn.MouseButton1Click:Connect(function()
                minimized = not minimized
                main.Size = minimized and UDim2.new(0,FRAME_W,0,36) or UDim2.new(0,FRAME_W,0,FRAME_H)
                contentFrame.Visible = not minimized
                minBtn.Text = minimized and "+" or "–"
            end)

            local urlCard = _mkFrame(contentFrame, UDim2.new(1,-16,0,38), UDim2.new(0,8,0,10), C.card, 8)
            _addStroke(urlCard)
            local urlBox = Instance.new("TextBox", urlCard)
            urlBox.Size = UDim2.new(1,-12,1,-10)
            urlBox.Position = UDim2.new(0,6,0,5)
            urlBox.PlaceholderText = "Paste Raw GitHub URL here..."
            urlBox.Text = ""
            urlBox.TextColor3 = C.white
            urlBox.PlaceholderColor3 = C.muted
            urlBox.BackgroundTransparency = 1
            urlBox.BorderSizePixel = 0
            urlBox.Font = Enum.Font.Gotham
            urlBox.TextSize = 12
            urlBox.TextXAlignment = Enum.TextXAlignment.Left
            urlBox.ClearTextOnFocus = false

            local row1 = _mkFrame(contentFrame, UDim2.new(1,-16,0,38), UDim2.new(0,8,0,56), C.bg)
            row1.BackgroundTransparency = 1
            local openEditorBtn = _mkBtn(row1, "Open Editor", UDim2.new(0,134,0,34), UDim2.new(0,0,0,2), C.btnOff, C.white, 8)
            _addStroke(openEditorBtn, C.stroke)
            openEditorBtn.TextStrokeColor3       = Color3.fromRGB(255,255,255)
            openEditorBtn.TextStrokeTransparency = 0.7
            local defaultFflagsBtn = _mkBtn(row1, "Default Fflags", UDim2.new(0,134,0,34), UDim2.new(1,-134,0,2), C.btnOff, C.white, 8)
            _addStroke(defaultFflagsBtn, C.stroke)
            defaultFflagsBtn.TextStrokeColor3       = Color3.fromRGB(255,255,255)
            defaultFflagsBtn.TextStrokeTransparency = 0.7

            local applyUrlBtn = _mkBtn(contentFrame, "Apply URL", UDim2.new(1,-16,0,38), UDim2.new(0,8,0,102), C.selBtn, C.white, 8)
            do
                local g = Instance.new("UIGradient", applyUrlBtn)
                g.Rotation = 45
                g.Color = ColorSequence.new{
                    ColorSequenceKeypoint.new(0, Color3.fromRGB(100, 10, 10)),
                    ColorSequenceKeypoint.new(1, Color3.fromRGB(180, 30, 30)),
                }
            end
            local rejoinBtn = _mkBtn(contentFrame, "Rejoin", UDim2.new(1,-16,0,38), UDim2.new(0,8,0,148), C.btnOff, C.white, 8)
            _addStroke(rejoinBtn, C.stroke)
            rejoinBtn.TextStrokeColor3       = Color3.fromRGB(255,255,255)
            rejoinBtn.TextStrokeTransparency = 0.7

            local statCard = _mkFrame(contentFrame, UDim2.new(1,-16,0,26), UDim2.new(0,8,0,194), C.card, 8)
            _addStroke(statCard)
            local statusLbl = _mkText(statCard, "Status: Ready", UDim2.new(1,-10,1,0), UDim2.new(0,8,0,0), Color3.fromRGB(235,235,235), 11)
            statusLbl.TextStrokeColor3       = Color3.fromRGB(150,150,150)
            statusLbl.TextStrokeTransparency = 0.5

            -- Editor window
            local EDIT_W, EDIT_H = 300, 260
            local editorFrame = _mkFrame(gui,
                UDim2.new(0,EDIT_W,0,EDIT_H),
                UDim2.new(0.5,-EDIT_W/2,0.5,-EDIT_H/2+180),
                C.bg, 14)
            _addStroke(editorFrame, C.accent, 1.5)
            editorFrame.Visible = false
            editorFrame.ZIndex = 10
            editorFrame.ClipsDescendants = true

            local editTitleBar = _mkFrame(editorFrame, UDim2.new(1,0,0,36), UDim2.new(0,0,0,0), C.card, 14)
            _mkText(editTitleBar, "FFLAG EDITOR", UDim2.new(1,-42,1,0), UDim2.new(0,14,0,0), C.accent, 12, true)
            local editCloseBtn = Instance.new("TextButton", editTitleBar)
            editCloseBtn.Size = UDim2.new(0,28,0,28)
            editCloseBtn.Position = UDim2.new(1,-34,0,4)
            editCloseBtn.Text = "–"
            editCloseBtn.TextColor3 = C.muted
            editCloseBtn.Font = Enum.Font.GothamBold
            editCloseBtn.TextSize = 14
            editCloseBtn.BackgroundColor3 = C.cardHov
            editCloseBtn.BorderSizePixel = 0
            editCloseBtn.AutoButtonColor = false
            editCloseBtn.ZIndex = 15
            Instance.new("UICorner", editCloseBtn).CornerRadius = UDim.new(0, 6)
            _makeDraggable(editorFrame, editTitleBar)

            local scrollFrame = Instance.new("ScrollingFrame", editorFrame)
            scrollFrame.Size = UDim2.new(1,-16,0,140)
            scrollFrame.Position = UDim2.new(0,8,0,44)
            scrollFrame.BackgroundColor3 = C.cardHov
            scrollFrame.BorderSizePixel = 0
            scrollFrame.ScrollBarThickness = 4
            scrollFrame.CanvasSize = UDim2.new(0,0,3,0)
            scrollFrame.AutomaticCanvasSize = Enum.AutomaticSize.Y
            scrollFrame.ZIndex = 11
            Instance.new("UICorner", scrollFrame).CornerRadius = UDim.new(0, 8)
            local jsonBox = _mkTextBox(scrollFrame, "Paste JSON here...", UDim2.new(1,0,1,0), UDim2.new(0,0,0,0), 11)
            jsonBox.BackgroundTransparency = 1
            jsonBox.ZIndex = 12

            local editRow = _mkFrame(editorFrame, UDim2.new(1,-16,0,36), UDim2.new(0,8,0,194), C.bg)
            editRow.BackgroundTransparency = 1
            local editCloseBtn2 = _mkBtn(editRow, "Close", UDim2.new(0,130,0,34), UDim2.new(0,0,0,0), C.btnOff, C.white, 8)
            _addStroke(editCloseBtn2, C.stroke)
            editCloseBtn2.TextStrokeColor3       = Color3.fromRGB(255,255,255)
            editCloseBtn2.TextStrokeTransparency = 0.7
            local applyFlagBtn = _mkBtn(editRow, "Apply FFlag", UDim2.new(0,130,0,34), UDim2.new(1,-130,0,0), C.selBtn, C.white, 8)
            do
                local g = Instance.new("UIGradient", applyFlagBtn)
                g.Rotation = 45
                g.Color = ColorSequence.new{
                    ColorSequenceKeypoint.new(0, Color3.fromRGB(100, 10, 10)),
                    ColorSequenceKeypoint.new(1, Color3.fromRGB(180, 30, 30)),
                }
            end

            -- Button logic
            openEditorBtn.MouseButton1Click:Connect(function() editorFrame.Visible = true end)
            local function _closeEditor() editorFrame.Visible = false end
            editCloseBtn.MouseButton1Click:Connect(_closeEditor)
            editCloseBtn2.MouseButton1Click:Connect(_closeEditor)

            defaultFflagsBtn.MouseButton1Click:Connect(function()
                statusLbl.Text = "Status: Applying defaults..."
                statusLbl.TextColor3 = Color3.fromRGB(235,235,235)
                    statusLbl.TextStrokeColor3       = Color3.fromRGB(150,150,150)
                    statusLbl.TextStrokeTransparency = 0.5
                task.spawn(function()
                    local count = _applyFflags(DEFAULT_FFLAGS)
                    _notify("BBG Strap", "Applied "..count.." default FFlags!", 3)
                    statusLbl.Text = "Status: Applied "..count.." flags"
                    statusLbl.TextColor3 = Color3.fromRGB(235,235,235)
                    statusLbl.TextStrokeColor3       = Color3.fromRGB(150,150,150)
                    statusLbl.TextStrokeTransparency = 0.5
                end)
            end)

            applyUrlBtn.MouseButton1Click:Connect(function()
                local url = urlBox.Text
                if url == "" then _notify("BBG Strap","Please paste a URL first!",3) return end
                statusLbl.Text = "Status: Downloading..."
                statusLbl.TextColor3 = Color3.fromRGB(235,235,235)
                    statusLbl.TextStrokeColor3       = Color3.fromRGB(150,150,150)
                    statusLbl.TextStrokeTransparency = 0.5
                task.spawn(function()
                    local ok, result = pcall(function() return game:HttpGet(url) end)
                    if not ok then
                        _notify("BBG Strap","Failed to fetch URL!",3)
                        statusLbl.Text = "Status: Fetch failed"
                        statusLbl.TextColor3 = Color3.fromRGB(235,235,235)
                    statusLbl.TextStrokeColor3       = Color3.fromRGB(150,150,150)
                    statusLbl.TextStrokeTransparency = 0.5
                        return
                    end
                    local count = _applyFflags(result)
                    _notify("BBG Strap","Applied "..count.." FFlags from URL!",3)
                    statusLbl.Text = "Status: Applied "..count.." flags"
                    statusLbl.TextColor3 = Color3.fromRGB(235,235,235)
                    statusLbl.TextStrokeColor3       = Color3.fromRGB(150,150,150)
                    statusLbl.TextStrokeTransparency = 0.5
                end)
            end)

            applyFlagBtn.MouseButton1Click:Connect(function()
                local txt = jsonBox.Text
                if txt == "" then _notify("BBG Strap","JSON box is empty!",3) return end
                task.spawn(function()
                    local count = _applyFflags(txt)
                    _notify("BBG Strap","Applied "..count.." FFlags!",3)
                    statusLbl.Text = "Status: Applied "..count.." flags"
                    statusLbl.TextColor3 = Color3.fromRGB(235,235,235)
                    statusLbl.TextStrokeColor3       = Color3.fromRGB(150,150,150)
                    statusLbl.TextStrokeTransparency = 0.5
                    _closeEditor()
                end)
            end)

            rejoinBtn.MouseButton1Click:Connect(function()
                statusLbl.Text = "Status: Rejoining..."
                statusLbl.TextColor3 = Color3.fromRGB(235,235,235)
                    statusLbl.TextStrokeColor3       = Color3.fromRGB(150,150,150)
                    statusLbl.TextStrokeTransparency = 0.5
                task.wait(0.5)
                pcall(function()
                    game:GetService("TeleportService"):Teleport(game.PlaceId, LP)
                end)
            end)

        else
            -- Toggle OFF hone par window chhupao
            if _bbgStrapGui then
                _bbgStrapGui.Enabled = false
            end
        end
    end,
})

-- ── Section: Font Changer ────────────────────────────────────
BBGStrapTab:CreateSection("Font Changer")

BBGStrapTab:CreateDropdown({
    Name = "Select Font",
    Options = {
        "Arcade",
        "Cartoon",
        "SciFi",
        "Fantasy",
        "Antique",
        "Garamond",
        "RobotoMono",
        "FredokaOne",
        "LuckiestGuy",
        "PermanentMarker",
        "SpecialElite",
        "Oswald",
        "Nunito",
        "Gotham",
        "GothamBold",
        "GothamBlack",
        "Arial",
        "ArialBold",
        "SourceSans",
        "SourceSansBold",
        "SourceSansSemibold",
        "Code",
        "Highway",
        "Legacy",
        "Merriweather",
    },
    CurrentOption = {"Gotham"},
    MultipleOptions = false,
    Flag = "BBGS_GlobalFont",
    Callback = function(v)
        local selected = type(v) == "table" and v[1] or v
        local fontEnum = Enum.Font[selected]
        if fontEnum then
            -- Saare ESP / UI TextLabels pe font apply karo
            pcall(function()
                for _, obj in ipairs(game:GetService("CoreGui"):GetDescendants()) do
                    if obj:IsA("TextLabel") or obj:IsA("TextButton") or obj:IsA("TextBox") then
                        obj.Font = fontEnum
                    end
                end
            end)
            -- Agar ESPModule available hai toh wahan bhi apply karo
            pcall(function()
                if ESPModule and ESPModule.SetGlobalFont then
                    ESPModule:SetGlobalFont(fontEnum)
                end
            end)
            -- Settings save karo
            pcall(function()
                if Settings then Settings["GlobalFont"] = selected end
            end)
            game:GetService("StarterGui"):SetCore("SendNotification", {
                Title = "BBG Strap",
                Text = "Font changed to: " .. selected,
                Duration = 2,
            })
        else
            warn("[BBG Strap] Font not found:", selected)
        end
    end,
})

-- ============================================================
--  TAB: SILENT AIM
-- ============================================================
local SATab = Window:CreateTab("Silent Aim", 4483362458)

-- ── Silent Aim Players ──────────────────────────────────────
SATab:CreateSection("Silent Aim")

SATab:CreateToggle({
    Name="Silent Aim Players", CurrentValue=false, Flag="SA_Main",
    Callback=function(v)
        SA_Enabled = v
        SilentAimModule:SetPlayerSilentAim(v)
        Rayfield:Notify({Title="Silent Aim", Content=v and "ON — Players" or "OFF", Duration=2})
    end,
})


SATab:CreateToggle({
    Name="Silent Aim NPCs", CurrentValue=false, Flag="SA_NPC",
    Callback=function(v)
        SilentAimModule:SetNPCSilentAim(v)
        Rayfield:Notify({Title="Silent Aim NPC", Content=v and "ON" or "OFF", Duration=2})
    end,
})


SATab:CreateSection("Prediction")

SATab:CreateToggle({
    Name="Silent Aim Prediction", CurrentValue=false, Flag="SA_Pred",
    Callback=function(v)
        SilentAimModule:SetPrediction(v)
    end,
})

SATab:CreateDropdown({
    Name="Prediction Amount",
    Options={"0.1","0.2","0.3","0.4"},
    CurrentOption={"0.1"}, MultipleOptions=false, Flag="SA_PredAmt",
    Callback=function(v)
        local n = tonumber(type(v)=="table" and v[1] or v)
        if n then SilentAimModule:SetPredictionAmount(n) end
    end,
})

SATab:CreateDropdown({
    Name="Distance Limit",
    Options={"200","400","600","800","1000"},
    CurrentOption={"1000"}, MultipleOptions=false, Flag="SA_DistLimit",
    Callback=function(v)
        local n = tonumber(type(v)=="table" and v[1] or v)
        if n then SilentAimModule:SetDistanceLimit(n); SA_MaxDist = n end
    end,
})


SATab:CreateSection("Skill Aimbot")

SATab:CreateToggle({
    Name="Z/V Skill Aimbot", CurrentValue=false, Flag="SA_GodZ",
    Callback=function(v)
        ZSkillModule:SetZSkills(v)
        Rayfield:Notify({Title="Z/V Skill Aimbot", Content=v and "ON" or "OFF", Duration=2})
    end,
})

SATab:CreateToggle({
    Name="Target Info (Name/Health)", CurrentValue=false, Flag="SA_TargetInfo",
    Callback=function(v)
        ZSkillModule:SetInfo(v)
    end,
})

SATab:CreateSection("Visuals")

SATab:CreateToggle({
    Name="Highlight Current Target", CurrentValue=false, Flag="SA_Highlight",
    Callback=function(v)
        SilentAimModule:SetHighlight(v)
    end,
})

SATab:CreateToggle({
    Name="Auto Ken", CurrentValue=false, Flag="SA_AutoKen",
    Callback=function(v)
        SilentAimModule:SetAutoKen(v)
        Rayfield:Notify({Title="Auto Ken", Content=v and "ON" or "OFF", Duration=2})
    end,
})



-- ── FOV Circle ───────────────────────────────────────────────
SATab:CreateSection("Aim Lock")

SATab:CreateToggle({
    Name="Aim Lock", CurrentValue=false, Flag="SA_AimLock",
    Callback=function(v)
        SA_AimLock        = v
        aimbotLockEnabled = v
        abGui.Enabled     = v
        refreshAbBtn()
        Rayfield:Notify({Title="Aim Lock", Content=v and "Locking nearest player" or "OFF", Duration=2})
    end,
})

SATab:CreateToggle({
    Name="Team Check (Skip Teammates)", CurrentValue=false, Flag="SA_AimLock_TeamCheck",
    Callback=function(v)
        SA_TeamCheck = v
        _lockedTarget = nil
        Rayfield:Notify({Title="Aim Lock", Content=v and "Team Check ON — teammates skipped" or "Team Check OFF", Duration=2})
    end,
})

SATab:CreateSlider({
    Name="Max Distance", Range={50,2000}, Increment=50,
    Suffix=" studs", CurrentValue=500, Flag="SA_MaxDist",
    Callback=function(v) SA_MaxDist = v end,
})

SATab:CreateSection("FOV Circle")

SATab:CreateToggle({
    Name="FOV Circle", CurrentValue=false, Flag="SA_FOV",
    Callback=function(v)
        SA_FOVEnabled   = v
        FOVCircleEnabled = v
        InnerCircle.Visible = v
        FillCircle.Visible  = v and GradientFillEnabled
        if not v then
            sa_fovCircle.Visible  = false
            InnerCircle.Visible   = false
            FillCircle.Visible    = false
        end
    end,
})

SATab:CreateSlider({
    Name="FOV Radius", Range={50,800}, Increment=10,
    Suffix="", CurrentValue=300, Flag="SA_FOVRadius",
    Callback=function(v)
        SA_FOVSize      = v
        FOVCircleSize   = v
        sa_fovCircle.Radius  = v
        InnerCircle.Radius   = v
        FillCircle.Radius    = v
    end,
})

SATab:CreateToggle({
    Name="Gradient Fill FOV", CurrentValue=false, Flag="SA_FOVGradient",
    Callback=function(v)
        GradientFillEnabled = v
        FillCircle.Visible  = FOVCircleEnabled and v
    end,
})

SATab:CreateSlider({
    Name="Fill Transparency", Range={0,100}, Increment=5,
    Suffix="%", CurrentValue=50, Flag="SA_FOVFillTrans",
    Callback=function(v)
        FOVFillTransparency    = v / 100
        FillCircle.Transparency = v / 100
    end,
})

-- G key shortcut: toggle SA Players (MKU style)
UserInputService.InputBegan:Connect(function(input, gp)
    if gp then return end
    if input.KeyCode == Enum.KeyCode.G then
        SA_Enabled = not SA_Enabled
        Rayfield:Notify({Title="Silent Aim", Content=SA_Enabled and "ON (G)" or "OFF (G)", Duration=1})
    end
end)




-- ============================================================
--  COMBAT TAB — Fast Attack + Kill Aura + Movement
-- ============================================================

-- Combat globals
getgenv().FastAttackEnabled  = false
getgenv().FastAttackRange    = 2000
getgenv().WalkSpeedEnabled   = false
getgenv().WalkSpeedValue     = 40
getgenv().DashIncreaseEnabled = false
getgenv().DashRange           = 150
getgenv().NoclipEnabled      = false
getgenv().PowerJumpEnabled   = false
getgenv().PowerJumpValue     = 50
getgenv().SpinBotEnabled     = false
getgenv().SpinBotSpeed       = 20
getgenv().InfiniteJumpEnabled = false
getgenv().WalkOnWaterEnabled  = false
getgenv().SmartAutoV4         = false
getgenv().AutoKenEnabled      = false

-- ── Fast Attack Remotes (Yeo Fixed source) ──────────────────
local RegisterHit    = nil
local RegisterAttack = nil

task.spawn(function()
    -- Try original path first
    local ok = pcall(function()
        local Modules = ReplicatedStorage:WaitForChild("Modules", 5)
        local Net     = Modules and Modules:WaitForChild("Net", 5)
        if Net then
            RegisterHit    = Net:FindFirstChild("RE/RegisterHit")
            RegisterAttack = Net:FindFirstChild("RE/RegisterAttack")
        end
    end)
    -- Fallback: search all descendants
    if not RegisterHit or not RegisterAttack then
        for _, v in pairs(ReplicatedStorage:GetDescendants()) do
            if v:IsA("RemoteEvent") then
                if v.Name == "RE/RegisterHit"    then RegisterHit    = v end
                if v.Name == "RE/RegisterAttack" then RegisterAttack = v end
            end
        end
    end
end)

local function AttackMultipleTargets(targets)
    if not RegisterHit or not RegisterAttack then return end
    pcall(function()
        if not targets or #targets == 0 then return end
        local allTargets = {}
        for _, char in pairs(targets) do
            local head = char:FindFirstChild("Head")
            if head then table.insert(allTargets, {char, head}) end
        end
        if #allTargets == 0 then return end
        RegisterAttack:FireServer(0)
        RegisterHit:FireServer(allTargets[1][2], allTargets)
    end)
end

local FastAttackConn = nil
local function StartFastAttack()
    if FastAttackConn then task.cancel(FastAttackConn) end
    FastAttackConn = task.spawn(function()
        while getgenv().FastAttackEnabled do
            RunService.Stepped:Wait()
            local myChar = LP.Character
            local myHRP  = myChar and myChar:FindFirstChild("HumanoidRootPart")
            if not myHRP then continue end
            local targets = {}
            local range   = getgenv().FastAttackRange
            -- Players
            for _, p in pairs(Players:GetPlayers()) do
                if p ~= LP and p.Character then
                    local hum = p.Character:FindFirstChild("Humanoid")
                    local hrp = p.Character:FindFirstChild("HumanoidRootPart")
                    if hum and hrp and hum.Health > 0
                    and (hrp.Position - myHRP.Position).Magnitude <= range then
                        table.insert(targets, p.Character)
                    end
                end
            end
            -- NPCs
            local enemies = workspace:FindFirstChild("Enemies")
            if enemies then
                for _, npc in pairs(enemies:GetChildren()) do
                    local hum = npc:FindFirstChild("Humanoid")
                    local hrp = npc:FindFirstChild("HumanoidRootPart")
                    if hum and hrp and hum.Health > 0
                    and (hrp.Position - myHRP.Position).Magnitude <= range then
                        table.insert(targets, npc)
                    end
                end
            end
            if #targets > 0 then AttackMultipleTargets(targets) end
        end
    end)
end

-- ── Anti Stun Engine (Guillermo Method) ──────────────────────
getgenv().AntiStunEnabled = false
local _antiStunActive = false

-- Z key triggers a 1.6s anti-stun window (same as guillermo)
UserInputService.InputBegan:Connect(function(input, gp)
    if gp and UserInputService:GetFocusedTextBox() then return end
    if not getgenv().AntiStunEnabled then return end
    if input.KeyCode == Enum.KeyCode.Z then
        _antiStunActive = true
        task.delay(1.6, function() _antiStunActive = false end)
    end
end)

-- RunService.Stepped: restore WalkSpeed/JumpPower + destroy stun forces
RunService.Stepped:Connect(function()
    if not getgenv().AntiStunEnabled then return end
    pcall(function()
        local char = LP.Character
        if not char then return end
        local root = char:FindFirstChild("HumanoidRootPart")
        local hum  = char:FindFirstChildOfClass("Humanoid")
        if hum then
            if hum.WalkSpeed < 16 then hum.WalkSpeed = 16 end
            if hum.JumpPower  < 50 then hum.JumpPower  = 50 end
        end
        if root then
            for _, o in ipairs(root:GetChildren()) do
                if o:IsA("BodyVelocity") or o:IsA("BodyPosition")
                or o:IsA("BodyForce")    or o:IsA("LinearVelocity")
                or o:IsA("AlignPosition") then
                    o:Destroy()
                end
            end
        end
    end)
end)

local NoclipConn = nil
local function SetNoclip(state)
    getgenv().NoclipEnabled = state
    if state then
        NoclipConn = RunService.Stepped:Connect(function()
            local char = LP.Character
            if char and getgenv().NoclipEnabled then
                for _, part in pairs(char:GetDescendants()) do
                    if part:IsA("BasePart") then part.CanCollide = false end
                end
            end
        end)
    else
        if NoclipConn then NoclipConn:Disconnect(); NoclipConn = nil end
        local char = LP.Character
        if char then
            for _, part in pairs(char:GetDescendants()) do
                if part:IsA("BasePart") then part.CanCollide = true end
            end
        end
    end
end
LP.CharacterAdded:Connect(function()
    if getgenv().NoclipEnabled then task.wait(0.5); SetNoclip(true) end
end)

-- Movement loop (WalkSpeed persistent — re-applies every frame including during dash)
RunService.RenderStepped:Connect(function()
    if getgenv().WalkSpeedEnabled then
        pcall(function()
            local hum = LP.Character and LP.Character:FindFirstChildOfClass("Humanoid")
            -- Re-apply every frame so dash animation reset cannot reduce speed
            if hum then hum.WalkSpeed = getgenv().WalkSpeedValue end
        end)
    end
end)

-- Extra: re-apply walkspeed when any animation plays (BF dash resets speed)
LP.CharacterAdded:Connect(function(char)
    local hum = char:WaitForChild("Humanoid")
    hum.AnimationPlayed:Connect(function()
        if getgenv().WalkSpeedEnabled then
            hum.WalkSpeed = getgenv().WalkSpeedValue
        end
    end)
end)
if LP.Character then
    local hum = LP.Character:FindFirstChildOfClass("Humanoid")
    if hum then
        hum.AnimationPlayed:Connect(function()
            if getgenv().WalkSpeedEnabled then
                hum.WalkSpeed = getgenv().WalkSpeedValue
            end
        end)
    end
end

RunService.RenderStepped:Connect(function()
    if getgenv().PowerJumpEnabled then
        pcall(function()
            local hum = LP.Character and LP.Character:FindFirstChildOfClass("Humanoid")
            if hum then
                hum.JumpPower    = getgenv().PowerJumpValue
                hum.UseJumpPower = true
            end
        end)
    end
end)

-- SpinBot logic (Matcha style)
RunService.Heartbeat:Connect(function()
    if not getgenv().SpinBotEnabled then return end
    local char = LP.Character
    local hrp  = char and char:FindFirstChild("HumanoidRootPart")
    if not hrp then return end
    hrp.CFrame = hrp.CFrame * CFrame.Angles(0, math.rad(getgenv().SpinBotSpeed), 0)
end)

-- ============================================================
--  DASH ENGINE  (dash_range.lua source)
-- ============================================================
local DashEnabled    = false
local DashConnection = nil
local DashLengthDist = 1

local function startDashLoop()
    if DashConnection then task.cancel(DashConnection); DashConnection = nil end
    DashConnection = task.spawn(function()
        while DashEnabled do
            task.wait(0.1)
            pcall(function()
                local char = LP.Character
                if char then
                    if char:GetAttribute("DashLength") ~= DashLengthDist then
                        char:SetAttribute("DashLength",    DashLengthDist)
                        char:SetAttribute("DashLengthAir", DashLengthDist)
                    end
                end
            end)
        end
    end)
end

local function stopDashLoop()
    DashEnabled = false
    if DashConnection then task.cancel(DashConnection); DashConnection = nil end
    pcall(function()
        local char = LP.Character
        if char then
            char:SetAttribute("DashLength",    1)
            char:SetAttribute("DashLengthAir", 1)
        end
    end)
end


-- ============================================================
--  INFINITE JUMP ENGINE  (inf_jump source)
-- ============================================================
local InfJumpConn = nil

local function getHum()
    local char = LP.Character
    return char and char:FindFirstChildOfClass("Humanoid")
end

local function startInfJump()
    if InfJumpConn then InfJumpConn:Disconnect() end
    InfJumpConn = UserInputService.JumpRequest:Connect(function()
        if not getgenv().InfiniteJumpEnabled then return end
        pcall(function()
            local hum = getHum()
            if hum then hum:ChangeState(Enum.HumanoidStateType.Jumping) end
        end)
    end)
end

startInfJump()

-- ============================================================
--  WALK ON WATER ENGINE
-- ============================================================
task.spawn(function()
    local WaterPlatform = Instance.new("Part")
    WaterPlatform.Size        = Vector3.new(200, 1, 200)
    WaterPlatform.Transparency= 1
    WaterPlatform.Anchored    = true
    WaterPlatform.CanCollide  = false
    WaterPlatform.Name        = "BBGWaterBlock"
    WaterPlatform.Parent      = workspace
    while true do
        task.wait(0.05)
        if getgenv().WalkOnWaterEnabled and LP.Character
           and LP.Character:FindFirstChild("HumanoidRootPart") then
            local hrp = LP.Character.HumanoidRootPart
            WaterPlatform.Position   = Vector3.new(hrp.Position.X, 0, hrp.Position.Z)
            WaterPlatform.CanCollide = true
        else
            WaterPlatform.CanCollide = false
        end
    end
end)

-- ============================================================
--  SMART AUTO V4 ENGINE
-- ============================================================
task.spawn(function()
    while true do
        task.wait(1)
        if getgenv().SmartAutoV4 then
            pcall(function()
                if LP.Character and LP.Character:GetAttribute("RaceEnergy")
                   and LP.Character:GetAttribute("RaceEnergy") >= 100 then
                    LP.Backpack.Awakening.RemoteFunction:InvokeServer(true)
                elseif LP.Backpack:FindFirstChild("Awakening") then
                    LP.Backpack.Awakening.RemoteFunction:InvokeServer(true)
                end
            end)
        end
    end
end)

-- ============================================================
--  Auto Buso ENGINE  — ts file source
-- ============================================================
local _CommF_ = nil
task.spawn(function()
    local remotes = ReplicatedStorage:FindFirstChild("Remotes")
    if remotes then
        _CommF_ = remotes:FindFirstChild("CommF_")
    end
    if not _CommF_ then
        for _, v in pairs(ReplicatedStorage:GetDescendants()) do
            if v:IsA("RemoteFunction") and v.Name == "CommF_" then
                _CommF_ = v
                break
            end
        end
    end
end)

-- AutoHaki function (ts file source — only fires if HasBuso not present)
local function AutoHaki()
    pcall(function()
        local char = LP.Character
        -- Only invoke if Buso not already active (ts file logic)
        local hasNoBuso = char and not char:FindFirstChild("HasBuso")
        if hasNoBuso and _CommF_ then
            _CommF_:InvokeServer("Buso")
        end
    end)
end

task.spawn(function()
    while true do
        task.wait(0.5)
        -- Only runs when explicitly enabled — stops completely when OFF
        if getgenv().AutoKenEnabled then
            AutoHaki()
        end
    end
end)

-- ============================================================
--  COMBAT TAB UI
-- ============================================================
local CombatTab = Window:CreateTab("Combat", 4483362458)

CombatTab:CreateSection("Fast Attack")

CombatTab:CreateToggle({
    Name="Fast Attack", CurrentValue=false, Flag="Combat_FastAttack",
    Callback=function(v)
        getgenv().FastAttackEnabled = v
        if v then StartFastAttack()
        else if FastAttackConn then task.cancel(FastAttackConn); FastAttackConn = nil end end
        Rayfield:Notify({Title="Fast Attack", Content=v and "Enabled" or "Disabled", Duration=2})
    end,
})

CombatTab:CreateSlider({
    Name="Attack Range", Range={50,5000}, Increment=50,
    Suffix=" studs", CurrentValue=2000, Flag="Combat_FARange",
    Callback=function(v) getgenv().FastAttackRange = v end,
})

CombatTab:CreateSection("Anti Stun")

CombatTab:CreateToggle({
    Name="Anti Stun", CurrentValue=false, Flag="Combat_AntiStun",
    Callback=function(v)
        getgenv().AntiStunEnabled = v
        Rayfield:Notify({
            Title="Anti Stun",
            Content=v and "ON — Stun/Ragdoll blocked" or "OFF",
            Duration=2
        })
    end,
})

CombatTab:CreateSection("Movement")

CombatTab:CreateToggle({
    Name="Walk Speed", CurrentValue=false, Flag="Combat_WalkSpeed",
    Callback=function(v)
        getgenv().WalkSpeedEnabled = v
        if not v then
            pcall(function()
                local hum = LP.Character and LP.Character:FindFirstChildOfClass("Humanoid")
                if hum then hum.WalkSpeed = 16 end
            end)
        end
        Rayfield:Notify({Title="Walk Speed", Content=v and "Enabled" or "Disabled", Duration=2})
    end,
})

CombatTab:CreateSlider({
    Name="Speed Value", Range={16,500}, Increment=1,
    Suffix="", CurrentValue=40, Flag="Combat_SpeedVal",
    Callback=function(v) getgenv().WalkSpeedValue = v end,
})

CombatTab:CreateToggle({
    Name="Dash Length", CurrentValue=false, Flag="Combat_DashLength",
    Callback=function(v)
        DashEnabled = v
        if v then startDashLoop()
        else stopDashLoop() end
        Rayfield:Notify({Title="Dash Length", Content=v and "ON" or "OFF", Duration=2})
    end,
})

CombatTab:CreateSlider({
    Name="Dash Distance", Range={1,300}, Increment=1,
    Suffix="", CurrentValue=1, Flag="Combat_DashDist",
    Callback=function(v) DashLengthDist = v end,
})

CombatTab:CreateToggle({
    Name="Noclip", CurrentValue=false, Flag="Combat_Noclip",
    Callback=function(v)
        SetNoclip(v)
        Rayfield:Notify({Title="Noclip", Content=v and "Enabled" or "Disabled", Duration=2})
    end,
})

CombatTab:CreateToggle({
    Name="Power Jump", CurrentValue=false, Flag="Combat_PowerJump",
    Callback=function(v)
        getgenv().PowerJumpEnabled = v
        if not v then
            pcall(function()
                local hum = LP.Character and LP.Character:FindFirstChildOfClass("Humanoid")
                if hum then hum.JumpPower = 50 end
            end)
        end
        Rayfield:Notify({Title="Power Jump", Content=v and "Enabled" or "Disabled", Duration=2})
    end,
})

CombatTab:CreateSlider({
    Name="Jump Power Value", Range={50,500}, Increment=10,
    Suffix="", CurrentValue=50, Flag="Combat_JumpVal",
    Callback=function(v) getgenv().PowerJumpValue = v end,
})

CombatTab:CreateSection("Extra Movement")

CombatTab:CreateToggle({
    Name="SpinBot", CurrentValue=false, Flag="Combat_SpinBot",
    Callback=function(v)
        getgenv().SpinBotEnabled = v
        Rayfield:Notify({Title="SpinBot", Content=v and "Enabled" or "Disabled", Duration=2})
    end,
})

CombatTab:CreateSlider({
    Name="Spin Speed", Range={1,100}, Increment=1,
    Suffix="", CurrentValue=20, Flag="Combat_SpinSpeed",
    Callback=function(v) getgenv().SpinBotSpeed = v end,
})

CombatTab:CreateSection("Mobility Extras")

CombatTab:CreateToggle({
    Name="Infinite Jump", CurrentValue=false, Flag="Combat_InfJump",
    Callback=function(v)
        getgenv().InfiniteJumpEnabled = v
        if v then startInfJump() end
        Rayfield:Notify({Title="Infinite Jump", Content=v and "Enabled" or "Disabled", Duration=2})
    end,
})

CombatTab:CreateToggle({
    Name="Walk On Water", CurrentValue=false, Flag="Combat_WalkWater",
    Callback=function(v)
        getgenv().WalkOnWaterEnabled = v
        Rayfield:Notify({Title="Walk On Water", Content=v and "Enabled" or "Disabled", Duration=2})
    end,
})

CombatTab:CreateToggle({
    Name="Smart Auto V4", CurrentValue=false, Flag="Combat_SmartV4",
    Callback=function(v)
        getgenv().SmartAutoV4 = v
        Rayfield:Notify({Title="Smart Auto V4", Content=v and "Enabled" or "Disabled", Duration=2})
    end,
})

CombatTab:CreateSection("Buso Haki")

CombatTab:CreateToggle({
    Name="Auto Buso", CurrentValue=false, Flag="Combat_AutoKen",
    Callback=function(v)
        getgenv().AutoKenEnabled = v
        Rayfield:Notify({Title="Auto Ken", Content=v and "Auto Buso Haki ON" or "OFF", Duration=2})
    end,
})

CombatTab:CreateSection("Glitches")

CombatTab:CreateToggle({
    Name="Anti Lava", CurrentValue=false, Flag="Combat_AntiLava",
    Callback=function(v)
        antiLavaActive = v
        if v then startAntiLava() else stopAntiLava() end
        Rayfield:Notify({Title="Anti Lava", Content=v and "ON" or "OFF", Duration=2})
    end,
})

CombatTab:CreateToggle({
    Name="Delete Ghost Ship", CurrentValue=false, Flag="Combat_DeleteShip",
    Callback=function(v)
        deleteShipActive = v
        if v then startDeleteShipLoop() end
        Rayfield:Notify({Title="Delete Ghost Ship", Content=v and "ON — Sea 2" or "OFF", Duration=2})
    end,
})

CombatTab:CreateToggle({
    Name="No Cooldown (Silent)", CurrentValue=false, Flag="Combat_NoCooldown",
    Callback=function(v)
        if v then enableNoCooldown() else disableNoCooldown() end
        Rayfield:Notify({Title="No Cooldown", Content=v and "ON" or "OFF", Duration=2})
    end,
})


-- ============================================================
--  TAB: ESP
-- ============================================================
local ESPTab = Window:CreateTab("ESP", 4483362458)

local esp
pcall(function()
    esp = loadstring(game:HttpGet(
        "https://raw.githubusercontent.com/Chilicly/ScriptModules/refs/heads/main/BBGPanelESPLibrary.lua"
    ))()
end)

if esp then
    pcall(function() esp:Initialize() end)
    -- Force TeamCheck OFF on load (lib default is ON)
    pcall(function()
        if esp.Config then esp.Config.TeamCheck = false end
        if esp.State  then esp.State.TeamCheck  = false end
    end)

    -- ── Box ESP ──────────────────────────────────────────────
    ESPTab:CreateSection("Box ESP")

    ESPTab:CreateToggle({
        Name="Box ESP", CurrentValue=false, Flag="ESP_Box",
        Callback=function(v)
            esp.State.BoxEnabled = v
        end,
    })

    ESPTab:CreateToggle({
        Name="Box Gradient", CurrentValue=false, Flag="ESP_BoxGrad",
        Callback=function(v)
            esp.Config.BoxGradientEnabled = v
        end,
    })

    ESPTab:CreateToggle({
        Name="Box Outline", CurrentValue=true, Flag="ESP_BoxOutline",
        Callback=function(v)
            esp.Config.BoxOutlineEnabled = v
            for _, o in pairs(esp.Caches.BoxCache) do
                if o.Stroke then o.Stroke.Enabled = v end
                if o.BoxOutline then o.BoxOutline.Visible = v and not esp.Config.BoxGradientEnabled end
            end
        end,
    })

    ESPTab:CreateSlider({
        Name="Box Fill Transparency", Range={0,100}, Increment=1,
        Suffix="%", CurrentValue=50, Flag="ESP_BoxFill",
        Callback=function(v)
            local t = v / 100
            esp.Config.BoxFillTransparency = t
            for _, o in pairs(esp.Caches.BoxCache) do
                if o.FillFrame then o.FillFrame.BackgroundTransparency = t end
            end
        end,
    })

    -- ── Players ───────────────────────────────────────────────
    ESPTab:CreateSection("Players")

    ESPTab:CreateToggle({
        Name="Name ESP", CurrentValue=false, Flag="ESP_Name",
        Callback=function(v) esp:InitiateName(v) end,
    })

    ESPTab:CreateToggle({
        Name="Distance ESP", CurrentValue=false, Flag="ESP_Dist",
        Callback=function(v) esp:InitiateDistance(v) end,
    })

    ESPTab:CreateToggle({
        Name="Health Bar ESP", CurrentValue=false, Flag="ESP_HealthBar",
        Callback=function(v)
            esp.State.HealthBarEnabled = v
        end,
    })

    ESPTab:CreateToggle({
        Name="Health Text ESP", CurrentValue=false, Flag="ESP_HealthText",
        Callback=function(v)
            esp.State.HealthTextEnabled = v
        end,
    })

    ESPTab:CreateToggle({
        Name="Ring ESP", CurrentValue=false, Flag="ESP_Ring",
        Callback=function(v)
            if v then esp:InitiateRing(Color3.fromRGB(255,255,255))
            else esp.State.RingEnabled = false end
        end,
    })

    -- ── Skeleton & Chams ─────────────────────────────────────
    ESPTab:CreateSection("Skeleton & Chams")

    ESPTab:CreateToggle({
        Name="Skeleton ESP", CurrentValue=false, Flag="ESP_Skeleton",
        Callback=function(v)
            if v then esp:InitiateSkeleton(Color3.fromRGB(103,89,179))
            else esp.State.SkeletonEnabled = false end
        end,
    })

    ESPTab:CreateToggle({
        Name="Chams", CurrentValue=false, Flag="ESP_Chams",
        Callback=function(v)
            if v then esp:InitiateChams(Color3.fromRGB(103,89,179))
            else esp.State.ChamsEnabled = false end
        end,
    })

    ESPTab:CreateSlider({
        Name="Chams Transparency", Range={0,100}, Increment=1,
        Suffix="%", CurrentValue=50, Flag="ESP_ChamsTrans",
        Callback=function(v)
            local t = v / 100
            esp.Config.ChamsFillTransparency = t
            for _, c in pairs(esp.Caches.ChamsCache) do
                c.FillTransparency = t
            end
        end,
    })

    -- ── Tracer ───────────────────────────────────────────────
    ESPTab:CreateSection("Tracer")

    ESPTab:CreateToggle({
        Name="Tracer ESP", CurrentValue=false, Flag="ESP_Tracer",
        Callback=function(v)
            if v then esp:InitiateTracer(Color3.fromRGB(103,89,179), esp.Config.TracerOrigin)
            else esp.State.TracerEnabled = false end
        end,
    })

    ESPTab:CreateDropdown({
        Name="Tracer Origin",
        Options={"Bottom Screen","Cursor","Top Screen"},
        CurrentOption={"Bottom Screen"}, MultipleOptions=false, Flag="ESP_TracerOrigin",
        Callback=function(v)
            esp.Config.TracerOrigin = type(v) == "table" and v[1] or v
        end,
    })

    -- ── Team Check ───────────────────────────────────────────
    ESPTab:CreateSection("Settings")

    ESPTab:CreateToggle({
        Name="Team Check (Skip teammates)", CurrentValue=false, Flag="ESP_TeamCheck",
        Callback=function(v)
            if esp.Config then esp.Config.TeamCheck = v end
        end,
    })

    -- ESP Distance — auto max on load, updates live
    local function applyESPDist(v)
        pcall(function()
            if esp.Config then
                esp.Config.MaxDistance    = v
                esp.Config.RenderDistance = v
                esp.Config.Distance       = v
            end
            if esp.State then
                esp.State.MaxDistance    = v
                esp.State.RenderDistance = v
            end
            if esp.SetDistance then esp:SetDistance(v) end
        end)
    end

    -- Apply max distance immediately on load + re-apply every 3s
    task.spawn(function()
        task.wait(1)
        applyESPDist(9999999)
        while true do
            task.wait(3)
            if esp and esp.Config then
                applyESPDist(9999999)
            end
        end
    end)

    ESPTab:CreateSlider({
        Name="ESP Distance", Range={100,9999999}, Increment=50,
        Suffix=" studs", CurrentValue=9999999, Flag="ESP_MaxDist",
        Callback=function(v)
            applyESPDist(v)
        end,
    })

else
    ESPTab:CreateSection("Error")
    ESPTab:CreateLabel("ESP lib failed to load. Check HTTP settings.")
end


print("[BBG Panel v16] Loaded — Soru Silent + Glitches + Silent Aim + ESP active")
