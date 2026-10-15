
#pragma warning disable SKEXP0010, SKEXP0001, SKEXP0050;

using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using gov.llnl.wintap.core.etl.shared;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.AI;
using ModelContextProtocol.Client;
using Newtonsoft.Json;
using OpenAI;
using System;
using System.ClientModel;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;



namespace gov.llnl.wintap.core.api
{
    public class Inference
    {
        public string Prompt { get; set; }
        public string Response { get; set; }
        public int TokensUsed { get; set; }
    }

    public class InferenceHub : Hub
    {

        public async Task Send(Inference inference)
        {
            StateManager.LastWorkbenchActivity = DateTime.Now;
            await Clients.All.SendAsync("ReceiveMessage", inference);
        }
    }

    [ApiController]
    [Route("api/[controller]")]
    public class LLMController : ControllerBase
    {
        private readonly IHubContext<InferenceHub> hubContext;
        private IMcpClient mcpClient;
        private IChatClient chatClient;
        private List<ChatMessage> chatHistory;

        public LLMController(IHubContext<InferenceHub> _hubContext, IMcpClient _mcpClient, IChatClient _chatClient, List<ChatMessage> _chatHistory)
        {
            this.hubContext = _hubContext;
            mcpClient = _mcpClient;
            chatClient = _chatClient;
            chatHistory = _chatHistory;
        }

        [HttpPut("Inference")]
        public async Task Put([FromBody] PromptModel promptModel)
        {
            string question = promptModel.Prompt;
            WintapLogger.Log.Append($"Got inference request with question: {question}", LogLevel.Info);

            // System prompt override
            if (question == "An application recently stopped working, can you help me diagnose it?")
            {
                string existingPrompt = chatHistory.First().Text;
                chatHistory.RemoveAt(0);
                chatHistory.Add(new ChatMessage(ChatRole.System, existingPrompt));
            }

            IList<McpClientTool> tools = await mcpClient.ListToolsAsync();
            chatHistory.Add(new ChatMessage(ChatRole.User, question));

            try
            {
                var chatOptions = new ChatOptions
                {
                    Tools = [.. tools], // MCP tools work with both providers!
                    Temperature = 1.0f,
                    ToolMode = ChatToolMode.Auto
                };

                if (chatOptions.AdditionalProperties == null)
                {
                    chatOptions.AdditionalProperties = new AdditionalPropertiesDictionary()
                    {
                        ["reasoning_effort"] = "minimal"  // OpenAI-specific, ignored by Ollama
                    };
                }

                chatOptions.AdditionalProperties["disabled_params"] = new Dictionary<string, object>
                {
                    ["parallel_tool_calls"] = null
                };

                // This works for BOTH OpenAI and Ollama!
                var response = await chatClient.GetResponseAsync(
                    chatHistory,
                    chatOptions
                );

                Inference inf = new Inference()
                {
                    Prompt = question,
                    Response = response.Text,
                    TokensUsed = 0
                };

                WintapLogger.Log.Append($"Inference response: {response.Text}", LogLevel.Info);

                string jsonString = JsonConvert.SerializeObject(inf);
                await this.hubContext.Clients.All.SendAsync("ReceiveMessage", inf, "OK");

                chatHistory.Add(new ChatMessage(ChatRole.Assistant, response.Messages[0].Text));
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error on inference: {ex.Message}", LogLevel.Error);
            }

            WintapLogger.Log.Append($"Inference complete", LogLevel.Info);
        }

        [HttpGet("tools")]
        public async Task<IActionResult> GetTools()
        {
            try
            {
                IList<McpClientTool> tools = await mcpClient.ListToolsAsync();

                return Ok(new
                {
                    mcpInitialized = true,
                    toolCount = tools.Count,
                    tools = tools.Select(tool => new
                    {
                        name = tool.Name,
                        description = tool.Description
                    })
                });
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append($"Error listing MCP tools: {ex.Message}", LogLevel.Error);

                return StatusCode(500, new
                {
                    mcpInitialized = false,
                    error = ex.Message,
                    tools = Array.Empty<object>()
                });
            }
        }


        [HttpPost("Clear")]
        public void Post()
        {
            WintapLogger.Log.Append($"LLM Clear method called", LogLevel.Info);

            OpenAIClientOptions openAIOptions = new OpenAIClientOptions();
            openAIOptions = new OpenAIClientOptions() { Endpoint = new Uri(Properties.Settings.Default.AiApiUrl) };

            string? key = "";
            key = System.IO.File.ReadAllText(Path.Combine(Paths.AiDataPath, "api-key.txt"));

            ApiKeyCredential cred = new ApiKeyCredential(key!);
            var openAIClient = new OpenAIClient(cred, openAIOptions).GetChatClient(Properties.Settings.Default.AiModel);

            // Create a sampling client.
            using IChatClient chatClient = openAIClient.AsIChatClient()
                .AsBuilder()
                .UseFunctionInvocation()
                .Build();

            List<ChatMessage> chatHistory = [new ChatMessage(ChatRole.System, System.IO.File.ReadAllText(Path.Combine(Env.FileRootPath, "systemprompt.txt"))),];
        }
    }

    public class PromptModel
    {
        public string Prompt { get; set; }
    }

}

