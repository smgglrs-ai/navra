import { useState, useRef, useEffect, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import Markdown from 'react-markdown';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import type { ServerStatus, ChatEvent } from '../types/api';

interface SessionInfo {
  id: string;
  turn_count: number;
  created_at: number;
  last_turn_at: number | null;
}

interface TurnMessage {
  role: string;
  content: string;
  timestamp: number;
  metadata?: string;
}

interface TurnInfo {
  turn_id: string;
  messages: TurnMessage[];
}

interface Message {
  role: 'user' | 'assistant' | 'system';
  content: string;
  toolCalls?: { name: string; arguments: string; result?: string }[];
}

export function ChatPage() {
  const { token } = useAuth();
  const queryClient = useQueryClient();
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([
    { role: 'system', content: 'Welcome to navra. Select a persona and start chatting.' },
  ]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [persona, setPersona] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const { data: status } = useQuery({
    queryKey: ['status'],
    queryFn: () => fetchJson<ServerStatus>('/api/status', token),
    refetchInterval: 30_000,
  });

  const { data: sessionsData } = useQuery({
    queryKey: ['chat-sessions'],
    queryFn: () => fetchJson<{ sessions: SessionInfo[] }>('/api/sessions', token),
    refetchInterval: 10_000,
    retry: false,
  });

  const sessions = sessionsData?.sessions ?? [];

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(scrollToBottom, [messages, scrollToBottom]);

  const loadSession = async (id: string) => {
    setSessionId(id);
    try {
      const data = await fetchJson<{ session_id: string; turns: TurnInfo[] }>(`/api/sessions/${id}`, token);
      const loaded: Message[] = [];
      for (const turn of data.turns) {
        for (const msg of turn.messages) {
          loaded.push({
            role: msg.role as Message['role'],
            content: msg.content,
          });
        }
      }
      if (loaded.length === 0) {
        loaded.push({ role: 'system', content: 'Session loaded. No messages yet.' });
      }
      setMessages(loaded);
    } catch {
      setMessages([{ role: 'system', content: 'Failed to load session history.' }]);
    }
  };

  const newSession = () => {
    setSessionId(null);
    setMessages([
      { role: 'system', content: 'Welcome to navra. Select a persona and start chatting.' },
    ]);
  };

  const deleteSession = async (id: string) => {
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    await fetch(`/api/sessions/${id}`, { method: 'DELETE', headers });
    queryClient.invalidateQueries({ queryKey: ['chat-sessions'] });
    if (sessionId === id) newSession();
  };

  const sendMessage = async () => {
    const text = input.trim();
    if (!text || sending) return;

    setSending(true);
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: text }]);

    const assistantIdx = messages.length + 1;
    setMessages(prev => [...prev, { role: 'assistant', content: '' }]);

    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const body: Record<string, unknown> = {
        prompt: text,
        persona: persona || undefined,
      };
      if (sessionId) body.session_id = sessionId;

      const resp = await fetch('/api/chat/agent', {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
      });

      if (!resp.ok) {
        const err = await resp.text();
        setMessages(prev => {
          const updated = [...prev];
          updated[assistantIdx] = { role: 'assistant', content: `**Error:** ${err}` };
          return updated;
        });
        return;
      }

      const reader = resp.body!.getReader();
      const decoder = new TextDecoder();
      let fullText = '';
      let buffer = '';
      const toolCalls: Message['toolCalls'] = [];

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop()!;

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const event: ChatEvent = JSON.parse(line);
            if (event.type === 'text' && event.content) {
              fullText += event.content;
              setMessages(prev => {
                const updated = [...prev];
                updated[assistantIdx] = { role: 'assistant', content: fullText, toolCalls: [...toolCalls] };
                return updated;
              });
            } else if (event.type === 'tool_call') {
              toolCalls.push({
                name: event.name || 'unknown',
                arguments: event.arguments || '{}',
                result: event.result,
              });
              setMessages(prev => {
                const updated = [...prev];
                updated[assistantIdx] = { role: 'assistant', content: fullText, toolCalls: [...toolCalls] };
                return updated;
              });
            } else if (event.type === 'done') {
              const sid = (event as Record<string, unknown>).session_id as string | undefined;
              if (sid && !sessionId) setSessionId(sid);
            }
          } catch {
            fullText += line;
          }
        }
      }

      setMessages(prev => {
        const updated = [...prev];
        updated[assistantIdx] = { role: 'assistant', content: fullText, toolCalls: [...toolCalls] };
        return updated;
      });
      queryClient.invalidateQueries({ queryKey: ['chat-sessions'] });
    } catch (err) {
      setMessages(prev => {
        const updated = [...prev];
        updated[assistantIdx] = { role: 'assistant', content: `**Error:** ${err}` };
        return updated;
      });
    } finally {
      setSending(false);
      inputRef.current?.focus();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="chat-container" style={{ display: 'flex', gap: '0' }}>
      <div className="chat-sidebar">
        <button className="btn primary" style={{ width: '100%', marginBottom: '12px' }} onClick={newSession}>
          New Chat
        </button>
        {sessions.length === 0 ? (
          <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)', padding: '8px' }}>
            No sessions yet
          </div>
        ) : (
          sessions.map(s => (
            <div
              key={s.id}
              className={`chat-session-item ${sessionId === s.id ? 'active' : ''}`}
              onClick={() => loadSession(s.id)}
            >
              <div style={{ fontSize: '0.8rem', fontWeight: sessionId === s.id ? 600 : 400 }}>
                {s.id.slice(0, 8)}...
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', display: 'flex', justifyContent: 'space-between' }}>
                <span>{s.turn_count} turns</span>
                <button
                  className="btn-icon"
                  title="Delete session"
                  onClick={e => { e.stopPropagation(); deleteSession(s.id); }}
                  style={{ fontSize: '0.7rem', color: 'var(--danger)', background: 'none', border: 'none', cursor: 'pointer', padding: '0 2px' }}
                >
                  ✕
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div className="chat-toolbar">
          <label>Persona</label>
          <select value={persona} onChange={e => setPersona(e.target.value)}>
            <option value="">default</option>
            {status?.personas?.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
          {sessionId && (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginLeft: 'auto' }}>
              Session: {sessionId.slice(0, 8)}
            </span>
          )}
        </div>

        <div className="chat-messages">
          {messages.map((msg, i) => (
            <div key={i} className={`message ${msg.role}`}>
              {msg.role === 'assistant' ? (
                <Markdown>{msg.content}</Markdown>
              ) : (
                msg.content
              )}
              {msg.toolCalls?.map((tc, j) => (
                <div key={j} className="tool-call" onClick={e => {
                  const el = (e.currentTarget as HTMLElement);
                  el.classList.toggle('open');
                }}>
                  <div className="tool-call-header">
                    <span><span className="tool-name">{tc.name}</span>()</span>
                  </div>
                  <div className="tool-call-body">
                    <pre>{formatJson(tc.arguments)}</pre>
                    {tc.result && (
                      <div style={{ marginTop: '8px' }}>
                        <strong>Result:</strong>
                        <pre>{tc.result}</pre>
                      </div>
                    )}
                  </div>
                </div>
              ))}
              {sending && i === messages.length - 1 && msg.role === 'assistant' && !msg.content && (
                <span className="spinner" />
              )}
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        <div className="chat-input-area">
          <textarea
            ref={inputRef}
            className="chat-input"
            placeholder="Ask something..."
            rows={1}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
          />
          <button className="chat-send" onClick={sendMessage} disabled={sending}>
            Send
          </button>
        </div>
      </div>
    </div>
  );
}

function formatJson(s: string): string {
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}
