"use client";

import React, { createContext, useContext, useEffect, useMemo, useState } from "react";

interface Message {
  role: "user" | "assistant";
  content: string;
  toolCalls?: Array<{
    tool: string;
    args: Record<string, unknown>;
    result: string;
  }>;
  debugSteps?: Array<{
    time: string;
    stage: string;
    detail: string;
  }>;
}

interface ChatSession {
  id: string;
  title: string;
  messages: Message[];
  createdAt: string;
  updatedAt: string;
}

interface ChatSessionContextValue {
  sessions: ChatSession[];
  activeSessionId: string | null;
  activeSession: ChatSession | null;
  createSession: () => string;
  selectSession: (id: string) => void;
  updateSessionMessages: (id: string, messages: Message[]) => void;
  updateSessionTitle: (id: string, title: string) => void;
  deleteSession: (id: string) => void;
}

const ChatSessionContext = createContext<ChatSessionContextValue | undefined>(undefined);

const STORAGE_KEY = "xlog.chat.sessions.v1";

const createSessionId = () =>
  `session_${Date.now()}_${Math.random().toString(16).slice(2)}`;

const createSession = (): ChatSession => {
  const now = new Date().toISOString();
  return {
    id: createSessionId(),
    title: "New chat",
    messages: [],
    createdAt: now,
    updatedAt: now,
  };
};

export const ChatSessionProvider = ({ children }: { children: React.ReactNode }) => {
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);

  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        const parsed = JSON.parse(stored) as ChatSession[];
        if (parsed.length > 0) {
          setSessions(parsed);
          setActiveSessionId(parsed[0].id);
          return;
        }
      } catch {
        // Ignore parse errors and fallback to new session.
      }
    }

    const initial = createSession();
    setSessions([initial]);
    setActiveSessionId(initial.id);
  }, []);

  useEffect(() => {
    if (sessions.length > 0) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(sessions));
    }
  }, [sessions]);

  const activeSession = useMemo(
    () => sessions.find((session) => session.id === activeSessionId) || null,
    [sessions, activeSessionId]
  );

  const createSessionAndSelect = () => {
    const session = createSession();
    setSessions((prev) => [session, ...prev]);
    setActiveSessionId(session.id);
    return session.id;
  };

  const selectSession = (id: string) => {
    setActiveSessionId(id);
  };

  const updateSessionMessages = (id: string, messages: Message[]) => {
    const now = new Date().toISOString();
    setSessions((prev) =>
      prev.map((session) =>
        session.id === id
          ? {
              ...session,
              messages,
              updatedAt: now,
            }
          : session
      )
    );
  };

  const updateSessionTitle = (id: string, title: string) => {
    const now = new Date().toISOString();
    setSessions((prev) =>
      prev.map((session) =>
        session.id === id
          ? {
              ...session,
              title,
              updatedAt: now,
            }
          : session
      )
    );
  };

  const deleteSession = (id: string) => {
    setSessions((prev) => {
      const next = prev.filter((session) => session.id !== id);
      if (next.length === 0) {
        const fresh = createSession();
        setActiveSessionId(fresh.id);
        return [fresh];
      }
      if (activeSessionId === id) {
        setActiveSessionId(next[0].id);
      }
      return next;
    });
  };

  const value = useMemo(
    () => ({
      sessions,
      activeSessionId,
      activeSession,
      createSession: createSessionAndSelect,
      selectSession,
      updateSessionMessages,
      updateSessionTitle,
      deleteSession,
    }),
    [sessions, activeSessionId, activeSession]
  );

  return <ChatSessionContext.Provider value={value}>{children}</ChatSessionContext.Provider>;
};

export const useChatSessions = () => {
  const context = useContext(ChatSessionContext);
  if (!context) {
    throw new Error("useChatSessions must be used within ChatSessionProvider");
  }
  return context;
};
