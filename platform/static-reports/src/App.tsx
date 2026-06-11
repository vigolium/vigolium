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
    // Set by the generator (true) before the data block, so the loader can tell
    // "data was generated but failed to load" apart from the standalone preview.
    __VIGOLIUM_DATA_EXPECTED__?: boolean;
  }
}

const emptyExportData = (): ExportData => ({
  scans: [],
  httpRecords: [],
  findings: [],
  modules: [],
});

function loadInitialData(): {
  data: ExportData;
  error?: string;
  title?: string;
  generatedAt?: string;
  scanDuration?: string;
  scanTarget?: string;
  vigoliumVersion?: string;
  reportSharedURL?: string;
} {
  const injected = window.__VIGOLIUM_REPORT__;
  // The data block assigned successfully — use it. An empty results array is a
  // legitimate "scan found nothing", not an error.
  if (injected && Array.isArray(injected.results)) {
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
  // The generator injected data (sentinel set) but window.__VIGOLIUM_REPORT__ is
  // missing → the data <script> failed to parse (almost always: the embedded
  // result set was too large for the browser). Surface that instead of silently
  // falling back to the built-in demo data.
  if (window.__VIGOLIUM_DATA_EXPECTED__) {
    return {
      data: emptyExportData(),
      error:
        "This report's embedded data could not be loaded — the result set is too large for the browser to parse. The full data is available in the matching .jsonl export next to this file, or drop any Vigolium JSONL export below to view it.",
    };
  }
  // Standalone template (no generated data) → demo preview / drop zone.
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
  const [loadError, setLoadError] = useState<string | undefined>(initial.error);
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
    setLoadError(undefined);
    setActiveTab("statistics");
  }, []);

  const hasData =
    data.findings.length > 0 || data.httpRecords.length > 0 || data.modules.length > 0;

  if (!hasData) {
    return (
      <Layout>
        <Header reportTitle={initial.title} generatedAt={initial.generatedAt} />
        <main className="wrap">
          {loadError && (
            <div
              className="empty-state"
              role="alert"
              style={{
                color: "var(--sev-high, #e34e1c)",
                border: "1px solid var(--sev-high, #e34e1c)",
                borderRadius: 6,
                padding: "16px 20px",
                marginBottom: 16,
                textAlign: "left",
                lineHeight: 1.5,
              }}
            >
              <strong>⚠ Report data failed to load</strong>
              <div style={{ marginTop: 6, fontSize: 13 }}>{loadError}</div>
            </div>
          )}
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
