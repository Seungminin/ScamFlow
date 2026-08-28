import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ScamFlow · 금융사기 대응 Agent",
  description: "금융사기 의심 상황을 탐지하고 공식 대응 절차를 안내하는 안전 중심 Agent",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="ko">
      <body>{children}</body>
    </html>
  );
}
