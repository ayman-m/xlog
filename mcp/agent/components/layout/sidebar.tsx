"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useMemo, useState } from "react";

import { useChatSessions } from "@/components/chat/chat-session-context";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

const navItems = [
  { label: "Chat", href: "/" },
  { label: "Skills", href: "/skills" },
];

export const Sidebar = () => {
  const pathname = usePathname();
  const {
    sessions,
    activeSessionId,
    createSession,
    selectSession,
    updateSessionTitle,
    deleteSession,
  } = useChatSessions();
  const [filter, setFilter] = useState("");

  const filteredSessions = useMemo(() => {
    const term = filter.trim().toLowerCase();
    if (!term) return sessions;
    return sessions.filter((session) => session.title.toLowerCase().includes(term));
  }, [filter, sessions]);

  const handleRename = (id: string, current: string) => {
    const nextTitle = window.prompt("Rename chat session", current);
    if (nextTitle && nextTitle.trim()) {
      updateSessionTitle(id, nextTitle.trim());
    }
  };

  const handleDelete = (id: string) => {
    if (window.confirm("Delete this chat session?")) {
      deleteSession(id);
    }
  };

  const handleLogout = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.reload();
  };

  return (
    <aside className="flex w-full flex-col border-b border-slate-800/80 bg-slate-950/95 px-4 py-5 text-slate-200 backdrop-blur-xl md:h-screen md:w-72 md:border-b-0 md:border-r">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">
            XLog Agent
          </p>
          <div className="mt-2 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-white shadow-sm">
              <Image src="/logo.png" alt="XLog logo" width={32} height={32} />
            </div>
            <h2 className="text-lg font-semibold text-white">XLog Agent</h2>
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => createSession()}
          className="border-slate-700 text-slate-100 hover:bg-slate-800"
        >
          New
        </Button>
      </div>

      <nav className="mt-6 flex gap-2">
        {navItems.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className={cn(
              "rounded-full px-4 py-2 text-sm font-medium transition",
              pathname === item.href
                ? "bg-white text-slate-900"
                : "text-slate-300 hover:bg-slate-800"
            )}
          >
            {item.label}
          </Link>
        ))}
      </nav>

      <div className="mt-6 flex-1 overflow-y-auto">
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">
          Sessions
        </p>
        <div className="mt-3 space-y-3">
          <Input
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            placeholder="Search chats..."
            className="border-slate-700 bg-slate-900/80 text-slate-100 placeholder:text-slate-500"
          />
          <div className="flex flex-col gap-2">
            {filteredSessions.map((session) => (
              <div
                key={session.id}
                className={cn(
                  "rounded-2xl border px-4 py-3 text-left text-sm transition",
                  session.id === activeSessionId
                    ? "border-white/20 bg-slate-800 text-white"
                    : "border-slate-800 bg-slate-900/60 text-slate-200 hover:border-slate-700"
                )}
              >
                <button
                  type="button"
                  onClick={() => selectSession(session.id)}
                  className="w-full text-left"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-medium">{session.title}</span>
                    <span className="text-[10px] uppercase tracking-[0.2em] text-slate-400">
                      {session.messages.length}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-slate-400">
                    {new Date(session.updatedAt).toLocaleTimeString()}
                  </p>
                </button>
                <div className="mt-3 flex gap-2">
                  <button
                    type="button"
                    onClick={() => handleRename(session.id, session.title)}
                    className="rounded-full border border-transparent px-3 py-1 text-xs font-semibold text-slate-300 transition hover:border-white/20 hover:text-white"
                  >
                    Rename
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDelete(session.id)}
                    className="rounded-full border border-transparent px-3 py-1 text-xs font-semibold text-rose-200 transition hover:border-white/20 hover:text-white"
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
            {filteredSessions.length === 0 && (
              <div className="rounded-xl border border-dashed border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-400">
                No sessions match that search.
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="mt-4">
        <Button
          variant="outline"
          size="sm"
          onClick={handleLogout}
          className="w-full border-slate-700 text-slate-100 hover:bg-slate-800"
        >
          Sign out
        </Button>
      </div>
    </aside>
  );
};
