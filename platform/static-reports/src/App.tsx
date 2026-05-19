import { useState, useCallback, useEffect } from "react";
import type { ExportData } from "./types";
import { parseExport } from "./utils/parse";
import Layout from "./components/Layout";
import Header, { type TabId } from "./components/Header";
import Footer from "./components/Footer";
import StatisticsTab from "./components/StatisticsTab";
import HttpTrafficTable from "./components/HttpTrafficTable";
import FindingsTable from "./components/FindingsTable";
import FileDropZone from "./components/FileDropZone";
import ReportView from "./components/ReportView";
import BackToTop from "./components/BackToTop";

import rawData from "./data.json";

declare global {
  interface Window {
    __VIGOLIUM_REPORT__?: {
      title?: string;
      generatedAt?: string;
      scanDuration?: string;
      scanTarget?: string;
      vigoliumVersion?: string;
      reportSharedURL?: string;
      results?: unknown[];
    };
  }
}

function loadInitialData(): {
  data: ExportData;
  title?: string;
  generatedAt?: string;
  scanDuration?: string;
  scanTarget?: string;
  vigoliumVersion?: string;
  reportSharedURL?: string;
} {
  const injected = window.__VIGOLIUM_REPORT__;
  if (injected?.results && Array.isArray(injected.results) && injected.results.length > 0) {
    return {
      data: parseExport(injected.results.map((r) => JSON.stringify(r))),
      title: injected.title,
      generatedAt: injected.generatedAt,
      scanDuration: injected.scanDuration,
      scanTarget: injected.scanTarget,
      vigoliumVersion: injected.vigoliumVersion,
      reportSharedURL: injected.reportSharedURL,
    };
  }
  const embedded = rawData as unknown as { raw?: string[] };
  return {
    data: parseExport(
      embedded.raw ?? (rawData as unknown as unknown[]).map((r: unknown) => JSON.stringify(r))
    ),
  };
}

const initial = loadInitialData();

const hashToTab: Record<string, TabId> = {
  "#Statistics": "statistics",
  "#HTTP_Traffic": "traffic",
  "#Findings": "findings",
  "#Full-Report": "report",
};

const tabToHash: Record<TabId, string> = {
  statistics: "#Statistics",
  traffic: "#HTTP_Traffic",
  findings: "#Findings",
  report: "#Full-Report",
};

function getTabFromHash(): TabId {
  const tab = hashToTab[window.location.hash];
  return tab ?? "statistics";
}

export default function App() {
  const [data, setData] = useState<ExportData>(initial.data);
  const [activeTab, setActiveTab] = useState<TabId>(getTabFromHash);

  // Sync hash → tab on back/forward navigation
  useEffect(() => {
    const onHashChange = () => setActiveTab(getTabFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  // Sync tab → hash when activeTab changes (statistics is default, no hash)
  useEffect(() => {
    const desired = activeTab === "statistics" ? "" : tabToHash[activeTab];
    const current = window.location.hash;
    if (current !== desired) {
      const url = desired || window.location.pathname + window.location.search;
      history.replaceState(null, "", url);
    }
    // Scroll to top on tab switch so the hero is always visible
    window.scrollTo({ top: 0 });
  }, [activeTab]);

  const handleDataLoad = useCallback((exportData: ExportData) => {
    setData(exportData);
    setActiveTab("statistics");
  }, []);

  const hasData =
    data.findings.length > 0 || data.httpRecords.length > 0 || data.modules.length > 0;

  if (!hasData) {
    return (
      <Layout>
        <Header reportTitle={initial.title} generatedAt={initial.generatedAt} />
        <main className="wrap">
          <FileDropZone onDataLoad={handleDataLoad} />
        </main>
      </Layout>
    );
  }

  return (
    <Layout>
      <Header
        activeTab={activeTab}
        onTabChange={setActiveTab}
        findingsCount={data.findings.length}
        trafficCount={data.httpRecords.length}
        reportTitle={initial.title}
        generatedAt={initial.generatedAt}
      />
      <main className={`wrap${activeTab === "findings" || activeTab === "traffic" ? " wrap--full" : ""}`}>
        <div key={activeTab} className="tab-content">
          {activeTab === "statistics" && (
            <StatisticsTab data={data} scanDuration={initial.scanDuration} generatedAt={initial.generatedAt} reportTitle={initial.title} scanTarget={initial.scanTarget} reportSharedURL={initial.reportSharedURL} />
          )}

          {activeTab === "traffic" && (
            data.httpRecords.length > 0 ? (
              <HttpTrafficTable data={data.httpRecords} />
            ) : (
              <div className="empty-state">No HTTP traffic records in this export.</div>
            )
          )}

          {activeTab === "findings" && (
            data.findings.length > 0 ? (
              <FindingsTable data={data.findings} httpRecords={data.httpRecords} />
            ) : (
              <div className="empty-state">No findings in this export.</div>
            )
          )}

          {activeTab === "report" && (
            <ReportView
              data={data}
              scanDuration={initial.scanDuration}
              generatedAt={initial.generatedAt}
              scanTarget={initial.scanTarget}
              vigoliumVersion={initial.vigoliumVersion}
              reportTitle={initial.title}
              reportSharedURL={initial.reportSharedURL}
            />
          )}
        </div>
      </main>
      {activeTab !== "report" && (
        <Footer vigoliumVersion={initial.vigoliumVersion} generatedAt={initial.generatedAt} />
      )}
      <BackToTop />
    </Layout>
  );
}
