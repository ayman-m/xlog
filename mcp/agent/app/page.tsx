'use client';

import { useMemo, useRef, useState, useEffect } from 'react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Textarea } from '@/components/ui/textarea';
import { useChatSessions } from '@/components/chat/chat-session-context';

const promptSuggestions = [
  'List available tools',
  'Generate 20 firewall logs with src IP 10.0.0.12',
  'Show me available simulation skills',
  'Create a port scan scenario against 10.10.20.5',
];

export default function Home() {
  const { activeSession, activeSessionId, updateSessionMessages, updateSessionTitle, createSession } =
    useChatSessions();
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const composerRef = useRef<HTMLTextAreaElement>(null);
  const messages = activeSession?.messages ?? [];

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const latestAssistant = useMemo(
    () => [...messages].reverse().find((msg) => msg.role === 'assistant'),
    [messages]
  );
  const toolErrorSignals = useMemo(() => {
    const calls = latestAssistant?.toolCalls || [];
    const errors: Array<{ tool: string; label: string }> = [];
    for (const call of calls) {
      const toolName = String(call.tool || '');
      const resultText = String(call.result || '');
      if (!resultText) continue;
      const lowerTool = toolName.toLowerCase();
      const lowerResult = resultText.toLowerCase();
      const errorLines = resultText
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => /error|errors|exception|failed|failure/.test(line.toLowerCase()));
      const hasError = errorLines.length > 0;
      if (!hasError) continue;

      let label = '';
      if (lowerTool.includes('graphql')) {
        label = 'GraphQL';
      } else if (lowerTool.includes('caldera')) {
        label = 'CALDERA';
      } else if (lowerTool.includes('xsiam')) {
        label = 'XSIAM';
      } else {
        const errorText = errorLines.join(' ').toLowerCase();
        if (errorText.includes('graphql')) {
          label = 'GraphQL';
        } else if (errorText.includes('caldera')) {
          label = 'CALDERA';
        } else if (errorText.includes('xsiam')) {
          label = 'XSIAM';
        }
      }

      if (label) {
        errors.push({ tool: toolName, label });
      }
    }
    return errors;
  }, [latestAssistant?.toolCalls]);

  const handleExport = () => {
    if (!activeSession) return;
    const lines: string[] = [
      `# ${activeSession.title || 'XLog Chat Session'}`,
      `- Session ID: ${activeSession.id}`,
      `- Updated: ${activeSession.updatedAt}`,
      '',
    ];

    for (const msg of activeSession.messages) {
      lines.push(`## ${msg.role === 'user' ? 'User' : 'XLog Agent'}`);
      lines.push(msg.content || '');
      lines.push('');

      if (msg.toolCalls && msg.toolCalls.length > 0) {
        lines.push('### Tool Calls');
        for (const call of msg.toolCalls) {
          lines.push(`- Tool: ${call.tool}`);
          lines.push('```json');
          lines.push(JSON.stringify(call.args, null, 2));
          lines.push('```');
          lines.push('```text');
          lines.push(call.result || '');
          lines.push('```');
        }
        lines.push('');
      }
    }

    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${activeSession.title || 'xlog-chat'}.md`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!input.trim() || isLoading) return;

    const userMessage = input.trim();
    setInput('');
    setIsLoading(true);

    let sessionId = activeSessionId;
    if (!sessionId) {
      sessionId = createSession();
    }

    let assistantIndex = -1;
    let nextMessages = messages;
    const baseMessages = messages;
    nextMessages = [
      ...baseMessages,
      { role: 'user' as const, content: userMessage },
      {
        role: 'assistant' as const,
        content: '',
        toolCalls: [],
        debugSteps: [],
      },
    ];
    assistantIndex = nextMessages.length - 1;
    updateSessionMessages(sessionId, nextMessages);

    if (activeSession?.title === 'New chat') {
      const nextTitle = userMessage.length > 38 ? `${userMessage.slice(0, 38)}...` : userMessage;
      updateSessionTitle(sessionId, nextTitle);
    }

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message: userMessage }),
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(errorData || 'Failed to get response');
      }

      if (!response.body) {
        throw new Error('No response body from server');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      const updateAssistant = (updater: (message: typeof nextMessages[number]) => typeof nextMessages[number]) => {
        nextMessages = nextMessages.map((msg, idx) => {
          if (idx !== assistantIndex) return msg;
          return updater(msg);
        });
        updateSessionMessages(sessionId!, nextMessages);
      };

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n\n');
        buffer = parts.pop() || '';

        for (const part of parts) {
          const line = part.trim();
          if (!line.startsWith('data:')) continue;

          const payload = line.slice(5).trim();
          if (!payload) continue;

          const event = JSON.parse(payload) as {
            type: string;
            [key: string]: unknown;
          };

          if (event.type === 'delta') {
            const text = String(event.text || '');
            updateAssistant((msg) => ({
              ...msg,
              content: msg.content + text,
            }));
          } else if (event.type === 'debug') {
            updateAssistant((msg) => ({
              ...msg,
              debugSteps: [
                ...(msg.debugSteps || []),
                {
                  time: String(event.time || ''),
                  stage: String(event.stage || ''),
                  detail: String(event.detail || ''),
                },
              ],
            }));
          } else if (event.type === 'tool_call') {
            updateAssistant((msg) => ({
              ...msg,
              toolCalls: [
                ...(msg.toolCalls || []),
                {
                  tool: String(event.tool || ''),
                  args: (event.args as Record<string, unknown>) || {},
                  result: '',
                },
              ],
            }));
          } else if (event.type === 'tool_result') {
            updateAssistant((msg) => {
              const toolCalls = [...(msg.toolCalls || [])];
              for (let i = toolCalls.length - 1; i >= 0; i -= 1) {
                if (toolCalls[i].tool === event.tool && !toolCalls[i].result) {
                  toolCalls[i] = {
                    ...toolCalls[i],
                    result: String(event.result || ''),
                  };
                  break;
                }
              }
              return {
                ...msg,
                toolCalls,
              };
            });
          } else if (event.type === 'error') {
            throw new Error(String(event.error || 'Unknown error'));
          }
        }
      }
    } catch (error) {
      console.error('Error:', error);
      nextMessages = nextMessages.map((msg, idx) => {
        if (idx !== assistantIndex) return msg;
        return {
          ...msg,
          content: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        };
      });
      if (sessionId) {
        updateSessionMessages(sessionId, nextMessages);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleSuggestion = (suggestion: string) => {
    setInput(suggestion);
    composerRef.current?.focus();
  };

  return (
    <div className="mx-auto flex h-full min-h-0 w-full max-w-6xl flex-col gap-6">
      <header className="flex shrink-0 flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
            XLog Security Studio
          </p>
          <h1 className="text-3xl font-semibold text-slate-900 md:text-4xl">
            Log simulation and live tool telemetry.
          </h1>
        </div>
        <div className="flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-2 text-sm font-medium text-slate-600 shadow-sm">
          <span className="h-2 w-2 rounded-full bg-emerald-500" />
          {isLoading ? 'Streaming response' : 'MCP connected'}
        </div>
      </header>

      <div className="grid flex-1 min-h-0 grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_340px]">
        <Card className="glass-panel flex min-h-0 flex-col">
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <CardTitle>Conversation</CardTitle>
                <CardDescription>
                  Ask for log generation, XSIAM queries, or CALDERA operations and watch the tool activity live.
                </CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={handleExport} disabled={!messages.length}>
                Export MD
              </Button>
            </div>
          </CardHeader>
          <CardContent className="flex-1 min-h-0">
            <div className="flex h-full flex-col gap-6 min-h-0">
              <div className="min-h-0 flex-1 space-y-6 overflow-y-auto pr-2">
                {messages.length === 0 && (
                  <div className="rounded-2xl border border-dashed border-slate-200 bg-white/80 p-6 text-slate-600">
                    <p className="text-sm font-medium">Start with a prompt:</p>
                    <div className="mt-4 flex flex-wrap gap-3">
                      {promptSuggestions.map((suggestion) => (
                        <button
                          key={suggestion}
                          type="button"
                          onClick={() => handleSuggestion(suggestion)}
                          className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 transition hover:border-slate-300 hover:text-slate-900"
                        >
                          {suggestion}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {messages.map((msg, idx) => (
                  <div
                    key={idx}
                    className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                  >
                    <div
                      className={`max-w-[80%] rounded-2xl px-5 py-4 text-sm shadow-sm ${
                        msg.role === 'user'
                          ? 'bg-gradient-to-br from-slate-900 to-slate-800 text-white'
                          : 'bg-white/90 text-slate-900'
                      }`}
                    >
                      <div className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">
                        {msg.role === 'user' ? 'You' : 'XLog Agent'}
                      </div>
                      <div className="whitespace-pre-wrap leading-relaxed">{msg.content}</div>

                      {msg.toolCalls && msg.toolCalls.length > 0 && (
                        <div className="mt-4 space-y-2 text-xs text-slate-600">
                          {msg.toolCalls.map((call, callIdx) => (
                            <details key={callIdx} className="rounded-xl border border-slate-200 bg-white/80 p-3">
                              <summary className="cursor-pointer font-semibold text-slate-800">
                                {call.tool}
                              </summary>
                              <div className="mt-3 space-y-2">
                                <div>
                                  <p className="font-medium text-slate-500">Arguments</p>
                                  <pre className="mt-1 whitespace-pre-wrap rounded-lg bg-slate-100 p-2 text-[11px] text-slate-700">
                                    {JSON.stringify(call.args, null, 2)}
                                  </pre>
                                </div>
                                <div>
                                  <p className="font-medium text-slate-500">Result</p>
                                  <pre className="mt-1 max-h-40 overflow-y-auto rounded-lg bg-slate-100 p-2 text-[11px] text-slate-700">
                                    {call.result}
                                  </pre>
                                </div>
                              </div>
                            </details>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                ))}

                {isLoading && (
                  <div className="flex justify-start">
                    <div className="rounded-2xl border border-slate-200 bg-white/80 px-5 py-4 text-sm text-slate-600">
                      Streaming response...
                    </div>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>

              <form onSubmit={handleSubmit} className="space-y-3">
                <Textarea
                  ref={composerRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Describe the scenario, data source, or XSIAM question..."
                  disabled={isLoading}
                />
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <p className="text-xs text-slate-500">
                    Tip: include a log type (SYSLOG, CEF, JSON) and observables for precision.
                  </p>
                  <Button
                    type="submit"
                    disabled={isLoading || !input.trim()}
                    className="bg-gradient-to-r from-sky-500 via-blue-500 to-indigo-500 text-white shadow-lg"
                  >
                    {isLoading ? 'Sending...' : 'Send to XLog'}
                  </Button>
                </div>
              </form>
            </div>
          </CardContent>
        </Card>

        <Card className="glass-panel flex min-h-0 flex-1 flex-col">
          <CardHeader>
            <CardTitle>Live telemetry</CardTitle>
            <CardDescription>See each MCP and model step as it happens.</CardDescription>
          </CardHeader>
          <CardContent className="flex-1 min-h-0 overflow-hidden">
            <div className="h-full space-y-3 overflow-y-auto pr-1">
              {(latestAssistant?.debugSteps || []).length === 0 && toolErrorSignals.length === 0 && (
                <p className="text-sm text-slate-500">No telemetry yet. Send a prompt to begin.</p>
              )}
              {toolErrorSignals.map((signal, idx) => (
                <div
                  key={`${signal.tool}-${idx}`}
                  className="rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-sm font-semibold text-rose-700"
                >
                  Tool error detected ({signal.label})
                </div>
              ))}
              {latestAssistant?.debugSteps?.map((step, idx) => (
                <div key={idx} className="rounded-xl border border-slate-200 bg-white/80 p-3">
                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <span className="font-mono">{step.time}</span>
                    <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-semibold uppercase">
                      {step.stage}
                    </span>
                  </div>
                  <p className="mt-2 text-sm text-slate-700">{step.detail}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
