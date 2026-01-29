import type { Metadata } from "next";
import { Space_Grotesk, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";
import { ChatSessionProvider } from "@/components/chat/chat-session-context";
import { AuthGate } from "@/components/auth/auth-gate";

export const metadata: Metadata = {
  title: "XLog Agent",
  description: "AI-powered security log generation agent",
  icons: {
    icon: "/logo.png",
  },
};

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-sans",
});

const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  weight: ["400", "500"],
});

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full overflow-hidden">
      <body
        className={`${spaceGrotesk.variable} ${plexMono.variable} h-full overflow-hidden bg-[hsl(var(--background))] font-sans text-[hsl(var(--foreground))]`}
      >
        <ChatSessionProvider>
          <AuthGate>{children}</AuthGate>
        </ChatSessionProvider>
      </body>
    </html>
  );
}
