/*
 * Copyright (c) 2025, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

//  these disables are required for the semantic kernel libraries
#pragma warning disable SKEXP0010, SKEXP0001, SKEXP0050, SKEXP0020, SKEXP0070;

using gov.llnl.wintap;
#if !WINTAP_CORE
using gov.llnl.wintap.core.api;
#endif
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.etl.load;
using gov.llnl.wintap.core.shared;
using EtlPaths = gov.llnl.wintap.core.etl.shared.Paths;
using gov.llnl.wintap.Properties;
#if !WINTAP_CORE
using Microsoft.AspNetCore.Builder;
#endif
#if !WINTAP_CORE
using Microsoft.AspNetCore.Hosting;
#endif
#if !WINTAP_CORE
using Microsoft.Extensions.AI;
#endif
using Microsoft.Extensions.DependencyInjection;
#if !WINTAP_CORE
using ModelContextProtocol.Client;
#endif
#if !WINTAP_CORE
using OpenAI;
#endif
using System;
#if !WINTAP_CORE
using System.ClientModel;
#endif
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using static gov.llnl.wintap.Interfaces;
using Microsoft.Extensions.Hosting;

#if WINDOWS
using gov.llnl.wintap.platform.windows.infrastructure;
#endif

#if LINUX
using gov.llnl.wintap.platform.linux.infrastructure;
#endif

#if MACOS
using gov.llnl.wintap.platform.macos.infrastructure;
#endif


#if WINDOWS
using gov.llnl.wintap.platform.windows.infrastructure;
#endif




// ═══════════════════════════════════════════════════════════════════════════
// APPLICATION INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════

string earlyVal = ConfigManager.GetValue<string>("WINTAP_EARLY_CONSOLE");
if (string.Equals(earlyVal, "true", StringComparison.OrdinalIgnoreCase) ||
    string.Equals(earlyVal, "1", StringComparison.OrdinalIgnoreCase))
{
    Console.WriteLine($"EARLY: starting {Env.AppName} pid={Environment.ProcessId} WINTAP_DATA_ROOT={ConfigManager.GetValue<string>("DataRoot") ?? ""}");
}

#if WINTAP_CORE
var builder = Host.CreateApplicationBuilder(args);
#else
var builder = WebApplication.CreateBuilder(args);
#endif

string settingsVal = ConfigManager.GetValue<string>("WINTAP_DISABLE_SETTINGS");
bool settingsDisabled = string.Equals(settingsVal, "true", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(settingsVal, "1", StringComparison.OrdinalIgnoreCase);

// ─── Configure Wintap to listen on port 8099 ───────────────────────────────
// Bind explicitly to IPv4 loopback to avoid hostname resolution stalls in some environments.
#if !WINTAP_CORE
builder.WebHost.UseUrls("http://127.0.0.1:8099");

builder.Services.AddControllers();

// ═══════════════════════════════════════════════════════════════════════════
// AI INTEGRATION CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

// ─── AI Provider Selection ─────────────────────────────────────────────────
string aiProvider = "OpenAI"; // "OpenAI" or "Ollama"
string configuredUrl = string.Empty;
if (!settingsDisabled)
{
    configuredUrl = Settings.Default.AiApiUrl;
}

WintapLogger.Log.Append($"Configured AI URL: {configuredUrl}", LogLevel.Info);

if (configuredUrl.Contains("localhost"))
{
    aiProvider = "Ollama";
}

IMcpClient mcpClient = null;
IChatClient chatClient = null;
PluginMcpManager pluginMcpManager = null;
string mcpVal = ConfigManager.GetValue<string>("WINTAP_DISABLE_MCP");
bool mcpDisabled = string.Equals(mcpVal, "true", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(mcpVal, "1", StringComparison.OrdinalIgnoreCase);

if (mcpDisabled)
{
    WintapLogger.Log.Append("MCP/AI initialization disabled by WINTAP_DISABLE_MCP", LogLevel.Warn);
}
else try
{
    // ─── MCP Server Configuration ──────────────────────────────────────────
    string fileRootPath = Env.FileRootPath;
    string exeName;

    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        exeName = "wintap_mcp_server.exe";
    }
    else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
             RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
    {
        exeName = "wintap_mcp_server"; // No .exe extension
    }
    else
    {
        throw new PlatformNotSupportedException("Unsupported OS");
    }

    string commandPath = Path.Combine(fileRootPath, "mcp", exeName);

    WintapLogger.Log.Append($"MCP server path: {commandPath}", LogLevel.Info);

    mcpClient = await McpClientFactory.CreateAsync(
        new StdioClientTransport(new()
        {
            Command = commandPath,
            Arguments = [],
            Name = "ai_mcp_server",
        })
    );

    WintapLogger.Log.Append("MCP client initialized successfully", LogLevel.Info);

    IList<McpClientTool> mcpTools = await mcpClient.ListToolsAsync();
    WintapLogger.Log.Append($"MCP tool count: {mcpTools.Count}", LogLevel.Info);
    foreach (McpClientTool tool in mcpTools)
    {
        WintapLogger.Log.Append($"MCP tool: {tool.Name}", LogLevel.Info);
    }

    // ─── Chat Client Configuration (Provider-Specific) ────────────────────
    if (aiProvider.Equals("Ollama", StringComparison.OrdinalIgnoreCase))
    {
        // Ollama (Local LLM) Configuration
        string ollamaEndpoint = Settings.Default.AiApiUrl;
        string ollamaModel = Settings.Default.AiModel;

        WintapLogger.Log.Append($"Using Ollama provider: {ollamaEndpoint} with model {ollamaModel}", LogLevel.Info);

        IChatClient ollamaClient = new OllamaChatClient(ollamaEndpoint, ollamaModel);

        chatClient = ollamaClient
            .AsBuilder()
            .UseFunctionInvocation()
            .Build();

        WintapLogger.Log.Append("Ollama chat client built successfully", LogLevel.Info);
    }
    else
    {
        // OpenAI-Compatible API Configuration (including Open-WebUI)
        string apiUrl = Settings.Default.AiApiUrl;
        string apiKey = Settings.Default.AiApiKey;
        string model = Settings.Default.AiModel;

        WintapLogger.Log.Append($"Configuring OpenAI-compatible endpoint", LogLevel.Info);
        WintapLogger.Log.Append($"  Endpoint: {apiUrl}", LogLevel.Info);
        WintapLogger.Log.Append($"  Model: {model}", LogLevel.Info);
        WintapLogger.Log.Append($"  API Key: {(string.IsNullOrEmpty(apiKey) ? "NOT SET" : "***" + apiKey.Substring(Math.Max(0, apiKey.Length - 4)))}", LogLevel.Info);

        OpenAIClientOptions openAIOptions = new OpenAIClientOptions()
        {
            Endpoint = new Uri(apiUrl)
        };

        ApiKeyCredential cred = new ApiKeyCredential(apiKey);

        WintapLogger.Log.Append($"Creating OpenAI client...", LogLevel.Info);

        var openAIClient = new OpenAIClient(cred, openAIOptions).GetChatClient(model);

        chatClient = openAIClient
            .AsIChatClient()
            .AsBuilder()
            .UseFunctionInvocation()
            .Build();

        WintapLogger.Log.Append("OpenAI-compatible chat client built successfully", LogLevel.Info);
    }

    // ─── Chat History Initialization ───────────────────────────────────────
    string systemPromptPath = Path.Combine(Env.FileRootPath, "systemprompt.txt");
    WintapLogger.Log.Append($"Loading system prompt from: {systemPromptPath}", LogLevel.Info);

    List<ChatMessage> chatHistory = [
        new ChatMessage(ChatRole.System,
            File.ReadAllText(systemPromptPath)),
    ];

    WintapLogger.Log.Append("System prompt loaded successfully", LogLevel.Info);

    // ─── Create Plugin MCP Manager ─────────────────────────────────────────
    WintapLogger.Log.Append("Creating Plugin MCP Manager", LogLevel.Info);
    pluginMcpManager = new PluginMcpManager(mcpClient, WintapLogger.Log);

    // ─── AI Service Registration ──────────────────────────────────────────
    builder.Services.AddSingleton(chatHistory);

    if (mcpClient != null)
    {
        builder.Services.AddSingleton<IMcpClient>(mcpClient);
    }

    if (chatClient != null)
    {
        builder.Services.AddSingleton<IChatClient>(chatClient);
    }

    if (pluginMcpManager != null)
    {
        builder.Services.AddSingleton<PluginMcpManager>(pluginMcpManager);
    }

    WintapLogger.Log.Append("AI services registered in DI container", LogLevel.Info);

}
catch (Exception ex)
{
    WintapLogger.Log.Append($"Error loading AI Client: {ex.Message}", LogLevel.Error);
    WintapLogger.Log.Append($"AI initialization stack trace: {ex.StackTrace}", LogLevel.Error);
}

// ═══════════════════════════════════════════════════════════════════════════
// SERVICE CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

#endif

WintapLogger.Log.Append("Configuring dependencies", LogLevel.Info);

string esperReproVal = ConfigManager.GetValue<string>("WINTAP_ESPER_REPRO");
if (string.Equals(esperReproVal, "true", StringComparison.OrdinalIgnoreCase) ||
    string.Equals(esperReproVal, "1", StringComparison.OrdinalIgnoreCase))
{
    string[] reproQueries =
    {
        "SELECT * FROM WintapMessage",
        "SELECT * FROM WintapMessage WHERE CAST(MessageType, string) = 'Process'",
        "SELECT * FROM WintapMessage WHERE CAST(MessageType, string) <> 'ProcessPartial'",
        "SELECT * FROM WintapMessage WHERE CAST(MessageType, string) = 'SessionChange'",
        "@Name(\"Every10Seconds Context DDL\")\ncreate context Every10Seconds initiated @now and pattern [every timer:interval(10 seconds)] terminated after 10 seconds\n"
    };

    Console.WriteLine("WINTAP_ESPER_REPRO_BEGIN");
    for (int i = 0; i < reproQueries.Length; i++)
    {
        string name = "esper_repro_" + i;
        try
        {
            EventChannel.CompileDeploy(reproQueries[i], name);
            Console.WriteLine($"WINTAP_ESPER_REPRO_RESULT|{i}|OK|{reproQueries[i].Replace('\n', ' ')}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"WINTAP_ESPER_REPRO_RESULT|{i}|FAIL|{ex.GetType().FullName}|{ex.Message.Replace('\n', ' ')}|{reproQueries[i].Replace('\n', ' ')}");
        }
    }
    Console.WriteLine("WINTAP_ESPER_REPRO_END");
    WintapLogger.Log.Close();
    return;
}

// ─── Logger Registration ───────────────────────────────────────────────────
// Register WintapLogger as IWintapLogger for plugin dependency injection
builder.Services.AddSingleton<IWintapLogger>(sp => WintapLogger.Log);

// ─── Inference Registration ────────────────────────────────────────────────
// Register WintapInference as IInfer for plugin AI access
#if !WINTAP_CORE
builder.Services.AddSingleton<IInfer>(sp =>
{
    var chatClient = sp.GetService<IChatClient>();
    var mcpManager = sp.GetService<PluginMcpManager>();
    var logger = sp.GetService<IWintapLogger>();

    if (chatClient == null || mcpManager == null)
    {
        WintapLogger.Log.Append("Warning: AI/MCP services not available. IInfer will not be available to plugins.", LogLevel.Warn);
        return null;
    }

    return new WintapInference(chatClient, mcpManager, logger);
});

// ─── Process Resolver Registration (Platform-Specific) ────────────────────
WintapLogger.Log.Append("Registering platform-specific process resolver", LogLevel.Info);

// ─── Process Resolver Registration (cross-platform) ────────────────────
WintapLogger.Log.Append("Registering cross-platform process resolver", LogLevel.Info);

#endif

string disableProcessResolverVal = ConfigManager.GetValue<string>("WINTAP_DISABLE_PROCESS_RESOLVER");
bool disableProcessResolver = string.Equals(disableProcessResolverVal, "true", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(disableProcessResolverVal, "1", StringComparison.OrdinalIgnoreCase);

// Direct-parquet mode bypasses resolver/Esper anyway, so allow running without DuckDB.
if (DirectParquetSink.IsEnabled || disableProcessResolver)
{
    WintapLogger.Log.Append("Process resolver disabled (direct-parquet or WINTAP_DISABLE_PROCESS_RESOLVER)", LogLevel.Warn);
}
else
{
    IProcessResolver processResolver = new ProcessResolver();
    builder.Services.AddSingleton<IProcessResolver>(processResolver);
}


// ─── Windows Service & Hosted Services ─────────────────────────────────────
#if WINDOWS
builder.Services.AddWindowsService();
#elif LINUX
builder.Services.AddSystemd();  // For Linux systemd integration
#elif MACOS
// macOS doesn't need a service wrapper for now
#endif
builder.Services.AddHostedService<WinTapSvc>();

// ─── SignalR Configuration ─────────────────────────────────────────────────
#if !WINTAP_CORE
builder.Services.AddSignalR();
builder.Services.AddSpaStaticFiles(configuration =>
{
    configuration.RootPath = Path.Combine(Env.FileRootPath, "Workbench");
});

// ═══════════════════════════════════════════════════════════════════════════
// APPLICATION PIPELINE CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

#endif
WintapLogger.Log.Append("Building app container", LogLevel.Info);
var app = builder.Build();

// Make service provider available as singleton for dependency access
ServiceProviderAccessor.Services = app.Services;

// ─── Middleware Pipeline ───────────────────────────────────────────────────
#if !WINTAP_CORE
if (!settingsDisabled && Settings.Default.EnableWorkbench)
{
    app.UseStaticFiles();
    app.UseSpaStaticFiles();
}

app.UseRouting();
app.UseAuthorization();
app.MapControllers();  // Map routes to API controllers

// ─── SPA Configuration (Serve Angular Static Files) ───────────────────────
if (!settingsDisabled && Settings.Default.EnableWorkbench)
{
    app.UseSpa(spa =>
    {
        spa.Options.SourcePath = Path.Combine(Env.FileRootPath, "Workbench");
        WintapLogger.Log.Append($"Workbench enabled, serving static files from {spa.Options.SourcePath}", LogLevel.Info);
    });
}
else
{
    WintapLogger.Log.Append("Workbench disabled and will not be served.", LogLevel.Info);
}

// ─── SignalR Hub Endpoints ─────────────────────────────────────────────────
WintapLogger.Log.Append("Setting up API endpoints", LogLevel.Info);
app.UseEndpoints(endpoints =>
{
    #if WINDOWS
        {
            // Windows-specific
            //endpoints.MapHub<ExplorerHub>("/signalr/ExplorerHub");
        }
    #endif

    endpoints.MapHub<WorkbenchHub>("/signalr/WorkbenchHub");
    endpoints.MapHub<InferenceHub>("/signalr/inferenceHub");
});

// ═══════════════════════════════════════════════════════════════════════════
// APPLICATION STARTUP
// ═══════════════════════════════════════════════════════════════════════════

#endif
app.Lifetime.ApplicationStarted.Register(() =>
{
    string parquetPath = EtlPaths.ParquetDataPath;
    string rawSensorPath = Path.Combine(parquetPath, "raw_sensor");
    Console.WriteLine($"Wintap parquet data path: {parquetPath}");
    Console.WriteLine($"Wintap raw_sensor data path: {rawSensorPath}");
    WintapLogger.Log.Append($"Wintap parquet data path: {parquetPath}", LogLevel.Info);
    WintapLogger.Log.Append($"Wintap raw_sensor data path: {rawSensorPath}", LogLevel.Info);
});

WintapLogger.Log.Append("Running app", LogLevel.Info);
app.Run();
