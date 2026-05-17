import { useState, useRef, useEffect, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import type { ServerStatus, ChatEvent } from '../types/api';

interface Message {
  role: 'user' | 'assistant' | 'system';
  content: string;
  toolCalls?: { name: string; arguments: string; result?: string }[];
}

export function ChatPage() {
  const { token } = useAuth();
  const [messages, setMessages] = useState<Message[]>([
    { role: 'system', content: 'Welcome to smgglrs. Select a persona and start chatting.' },
  ]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [persona, setPersona] = useState('');
  const [model, setModel] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const { data: status } = useQuery({
    queryKey: ['status'],
    queryFn: () => fetchJson<ServerStatus>('/api/status', token),
    refetchInterval: 30_000,
  });

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(scrollToBottom, [messages, scrollToBottom]);

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

      const resp = await fetch('/api/chat', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          prompt: text,
          persona: persona || null,
          model: model || null,
        }),
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
    <div className="chat-container">
      <div className="chat-toolbar">
        <label>Persona</label>
        <select value={persona} onChange={e => setPersona(e.target.value)}>
          <option value="">default</option>
          {status?.personas?.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        <label>Model</label>
        <select value={model} onChange={e => setModel(e.target.value)}>
          <option value="">auto</option>
          {status?.models?.map(m => <option key={m} value={m}>{m}</option>)}
        </select>
      </div>

      <div className="chat-messages">
        {messages.map((msg, i) => (
          <div key={i} className={`message ${msg.role}`}>
            {msg.role === 'assistant' ? (
              <div dangerouslySetInnerHTML={{ __html: renderMarkdown(msg.content) }} />
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
                  <span className="ifc-label trusted">Trusted</span>
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
  );
}

function renderMarkdown(text: string): string {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/^(\d+)\. (.+)$/gm, '<li>$2</li>')
    .replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/\n/g, '<br>')
    .replace(/^/, '<p>')
    .replace(/$/, '</p>');
}

function formatJson(s: string): string {
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}
