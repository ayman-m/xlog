"use client";

import { useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { CardBody, CardContainer, CardItem } from "@/components/ui/3d-card";

type SkillListItem = {
  name: string;
  category: string;
  file_path: string;
  size_bytes?: number;
  modified_at?: string;
};

const categories = ["foundation", "scenarios", "validation", "workflows"];
const categoryStyles: Record<string, string> = {
  foundation: "bg-emerald-50/70 border-emerald-200/70",
  scenarios: "bg-sky-50/70 border-sky-200/70",
  validation: "bg-amber-50/70 border-amber-200/70",
  workflows: "bg-violet-50/70 border-violet-200/70",
};

export default function SkillsPage() {
  const [skills, setSkills] = useState<SkillListItem[]>([]);
  const [selected, setSelected] = useState<SkillListItem | null>(null);
  const [content, setContent] = useState("");
  const [filter, setFilter] = useState("");
  const [activeTab, setActiveTab] = useState<"list" | "create">("list");
  const [editing, setEditing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [newCategory, setNewCategory] = useState(categories[0]);
  const [newFilename, setNewFilename] = useState("");
  const [newContent, setNewContent] = useState("");

  const filteredSkills = useMemo(() => {
    const term = filter.trim().toLowerCase();
    if (!term) return skills;
    return skills.filter(
      (skill) =>
        skill.name.toLowerCase().includes(term) ||
        skill.category.toLowerCase().includes(term)
    );
  }, [filter, skills]);

  const loadSkills = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("/api/skills");
      const data = await response.json();
      if (!data.success) {
        throw new Error(data.error || "Failed to load skills");
      }
      setSkills(data.skills || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  const viewSkill = async (skill: SkillListItem, editMode = false) => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/skills?file_path=${encodeURIComponent(skill.file_path)}`);
      const data = await response.json();
      if (!data.success) {
        throw new Error(data.error || "Failed to load skill");
      }
      setSelected(skill);
      setContent(data.content || "");
      setEditing(editMode);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  const saveSkill = async () => {
    if (!selected) return;
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("/api/skills", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file_path: selected.file_path, content }),
      });
      const data = await response.json();
      if (!data.success) {
        throw new Error(data.error || "Failed to update skill");
      }
      setEditing(false);
      await loadSkills();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  const deleteSkill = async (skill: SkillListItem) => {
    if (!window.confirm(`Delete ${skill.name}?`)) return;
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/skills?file_path=${encodeURIComponent(skill.file_path)}`, {
        method: "DELETE",
      });
      const data = await response.json();
      if (!data.success) {
        throw new Error(data.error || "Failed to delete skill");
      }
      if (selected?.file_path === skill.file_path) {
        setSelected(null);
        setContent("");
        setEditing(false);
      }
      await loadSkills();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  const createSkill = async () => {
    if (!newFilename.trim() || !newContent.trim()) {
      setError("Filename and content are required.");
      return;
    }
    if (!newFilename.endsWith(".md")) {
      setError("Filename must end with .md");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const response = await fetch("/api/skills", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          category: newCategory,
          filename: newFilename.trim(),
          content: newContent,
        }),
      });
      const data = await response.json();
      if (!data.success) {
        throw new Error(data.error || "Failed to create skill");
      }
      setNewFilename("");
      setNewContent("");
      await loadSkills();
      setActiveTab("list");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSkills();
  }, []);

  return (
    <div className="mx-auto flex min-h-0 w-full max-w-6xl flex-1 flex-col gap-6">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
            Skills Manager
          </p>
          <h1 className="text-3xl font-semibold text-slate-900 md:text-4xl">
            Manage MCP skills & workflows
          </h1>
        </div>
        <div className="flex items-center gap-2">
          <Button variant={activeTab === "list" ? "default" : "outline"} onClick={() => setActiveTab("list")}>
            Skills List
          </Button>
          <Button variant={activeTab === "create" ? "default" : "outline"} onClick={() => setActiveTab("create")}>
            Create New
          </Button>
        </div>
      </header>

      {error && (
        <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {error}
        </div>
      )}

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-6 lg:grid-cols-[360px_minmax(0,1fr)]">
        <Card className="glass-panel flex h-full min-h-0 flex-col">
          <CardHeader>
            <CardTitle>{activeTab === "list" ? "Available Skills" : "Create a New Skill"}</CardTitle>
            <CardDescription>
              {activeTab === "list"
                ? "Browse, view, edit, and delete skills stored on the MCP server."
                : "Add a new markdown skill to the MCP skills library."}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex-1 min-h-0 overflow-y-auto">
            {activeTab === "list" ? (
              <div className="flex flex-col gap-4">
                <div className="flex flex-wrap gap-3">
                  <Input
                    value={filter}
                    onChange={(event) => setFilter(event.target.value)}
                    placeholder="Search skills..."
                  />
                  <Button variant="outline" onClick={loadSkills} disabled={loading}>
                    {loading ? "Refreshing..." : "Refresh"}
                  </Button>
                </div>

                <div className="space-y-3 pr-1">
                  {filteredSkills.length === 0 && (
                    <p className="text-sm text-slate-500">No skills found.</p>
                  )}
                  {filteredSkills.map((skill) => (
                    <CardContainer key={skill.file_path}>
                      <CardBody className={categoryStyles[skill.category] || "bg-white/80"}>
                        <CardItem translateZ={30} className="flex items-center justify-between gap-3">
                          <div>
                            <p className="text-sm font-semibold text-slate-900">{skill.name}</p>
                            <p className="text-xs text-slate-500">{skill.category}</p>
                          </div>
                          <div className="text-xs text-slate-400">
                            {skill.size_bytes ? `${skill.size_bytes} bytes` : "size n/a"}
                          </div>
                        </CardItem>
                        <CardItem translateZ={50} className="mt-3 flex flex-wrap gap-2">
                          <Button variant="outline" size="sm" onClick={() => viewSkill(skill, false)}>
                            View
                          </Button>
                          <Button variant="outline" size="sm" onClick={() => viewSkill(skill, true)}>
                            Edit
                          </Button>
                          <Button variant="ghost" size="sm" onClick={() => deleteSkill(skill)}>
                            Delete
                          </Button>
                        </CardItem>
                      </CardBody>
                    </CardContainer>
                  ))}
                </div>
              </div>
            ) : (
              <div className="flex h-full flex-col gap-4">
                <div className="grid gap-3 md:grid-cols-2">
                  <div>
                    <label className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
                      Category
                    </label>
                    <select
                      value={newCategory}
                      onChange={(event) => setNewCategory(event.target.value)}
                      className="mt-2 w-full rounded-xl border border-slate-200 bg-white/80 px-3 py-2 text-sm"
                    >
                      {categories.map((category) => (
                        <option key={category} value={category}>
                          {category}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
                      Filename
                    </label>
                    <Input
                      value={newFilename}
                      onChange={(event) => setNewFilename(event.target.value)}
                      placeholder="my_skill.md"
                    />
                  </div>
                </div>
                <div className="flex min-h-0 flex-1 flex-col">
                  <label className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
                    Content
                  </label>
                  <Textarea
                    value={newContent}
                    onChange={(event) => setNewContent(event.target.value)}
                    placeholder="# Skill: My Skill"
                    className="flex-1"
                  />
                </div>
                <Button onClick={createSkill} disabled={loading}>
                  {loading ? "Creating..." : "Create Skill"}
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="glass-panel flex h-full min-h-0 flex-col">
          <CardHeader>
            <CardTitle>{editing ? "Editing Skill" : "Skill Preview"}</CardTitle>
            <CardDescription>
              {selected ? selected.file_path : "Select a skill to view its content."}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex-1 min-h-0 overflow-y-auto">
            {!selected && (
              <p className="text-sm text-slate-500">
                Choose a skill from the list to view or edit its markdown content.
              </p>
            )}
            {selected && (
              <div className="flex flex-col gap-3">
                {editing ? (
                  <>
                    <Textarea
                      value={content}
                      onChange={(event) => setContent(event.target.value)}
                      className="min-h-0 flex-1"
                    />
                    <div className="flex flex-wrap gap-2">
                      <Button onClick={saveSkill} disabled={loading}>
                        Save Changes
                      </Button>
                      <Button variant="outline" onClick={() => setEditing(false)}>
                        Cancel
                      </Button>
                    </div>
                  </>
                ) : (
                  <div className="rounded-2xl border border-slate-200 bg-white/90 p-6">
                    <ReactMarkdown
                      remarkPlugins={[remarkGfm]}
                      components={{
                        h1: ({ children }) => (
                          <h1 className="mb-3 text-2xl font-semibold text-slate-900">{children}</h1>
                        ),
                        h2: ({ children }) => (
                          <h2 className="mb-2 mt-6 text-xl font-semibold text-slate-900">{children}</h2>
                        ),
                        h3: ({ children }) => (
                          <h3 className="mb-2 mt-5 text-lg font-semibold text-slate-900">{children}</h3>
                        ),
                        p: ({ children }) => <p className="mb-3 text-sm text-slate-700">{children}</p>,
                        ul: ({ children }) => (
                          <ul className="mb-3 list-disc space-y-1 pl-5 text-sm text-slate-700">{children}</ul>
                        ),
                        ol: ({ children }) => (
                          <ol className="mb-3 list-decimal space-y-1 pl-5 text-sm text-slate-700">{children}</ol>
                        ),
                        li: ({ children }) => <li className="text-sm text-slate-700">{children}</li>,
                        code: ({ children }) => (
                          <code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-700">
                            {children}
                          </code>
                        ),
                        pre: ({ children }) => (
                          <pre className="mb-3 overflow-x-auto rounded-lg bg-slate-100 p-3 text-xs text-slate-700">
                            {children}
                          </pre>
                        ),
                        a: ({ children, href }) => (
                          <a className="text-sky-600 underline" href={href}>
                            {children}
                          </a>
                        ),
                      }}
                    >
                      {content || "No content to preview."}
                    </ReactMarkdown>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
