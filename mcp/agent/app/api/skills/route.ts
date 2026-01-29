import { NextRequest, NextResponse } from "next/server";

import { XLogMCPClient } from "@/lib/mcp-client";

const MCP_URL = process.env.MCP_URL || "http://localhost:8080/api/v1/stream/mcp";
const MCP_TOKEN = process.env.MCP_TOKEN;

type SkillListItem = {
  name: string;
  category: string;
  file_path: string;
  size_bytes?: number;
  modified_at?: string;
};

const parseToolResult = <T,>(result: { content: Array<{ text: string }> }): T => {
  const raw = result.content?.[0]?.text || "{}";
  return JSON.parse(raw) as T;
};

export async function GET(request: NextRequest) {
  try {
    const mcpClient = new XLogMCPClient(MCP_URL, MCP_TOKEN);
    const { searchParams } = new URL(request.url);
    const filePath = searchParams.get("file_path");

    if (filePath) {
      const result = await mcpClient.callTool("skills_read", { file_path: filePath });
      const parsed = parseToolResult<{ success: boolean; content?: string; error?: string }>(result);
      return NextResponse.json(parsed);
    }

    const result = await mcpClient.callTool("skills_list_all", {});
    const skills = parseToolResult<SkillListItem[]>(result);
    return NextResponse.json({ success: true, skills });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : "Unknown error" },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { category, filename, content } = body || {};

    if (!category || !filename || !content) {
      return NextResponse.json(
        { success: false, error: "category, filename, and content are required." },
        { status: 400 }
      );
    }

    const mcpClient = new XLogMCPClient(MCP_URL, MCP_TOKEN);
    const result = await mcpClient.callTool("skills_create", {
      category,
      filename,
      content,
    });
    const parsed = parseToolResult<{ success: boolean; message?: string; error?: string }>(result);
    return NextResponse.json(parsed);
  } catch (error) {
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : "Unknown error" },
      { status: 500 }
    );
  }
}

export async function PUT(request: NextRequest) {
  try {
    const body = await request.json();
    const { file_path, content } = body || {};

    if (!file_path || !content) {
      return NextResponse.json(
        { success: false, error: "file_path and content are required." },
        { status: 400 }
      );
    }

    const mcpClient = new XLogMCPClient(MCP_URL, MCP_TOKEN);
    const result = await mcpClient.callTool("skills_update", {
      file_path,
      content,
    });
    const parsed = parseToolResult<{ success: boolean; message?: string; error?: string }>(result);
    return NextResponse.json(parsed);
  } catch (error) {
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : "Unknown error" },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const filePath = searchParams.get("file_path");

    if (!filePath) {
      return NextResponse.json(
        { success: false, error: "file_path is required." },
        { status: 400 }
      );
    }

    const mcpClient = new XLogMCPClient(MCP_URL, MCP_TOKEN);
    const result = await mcpClient.callTool("skills_delete", { file_path: filePath });
    const parsed = parseToolResult<{ success: boolean; message?: string; error?: string }>(result);
    return NextResponse.json(parsed);
  } catch (error) {
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : "Unknown error" },
      { status: 500 }
    );
  }
}
