import {
  Activity,
  Bot,
  Boxes,
  BrainCircuit,
  Check,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  CircleHelp,
  Clock3,
  Code2,
  Database,
  FileCode2,
  Filter,
  Fingerprint,
  Gauge,
  GitBranch,
  LayoutDashboard,
  Link2,
  ListFilter,
  Menu,
  MessageSquareText,
  Mountain,
  Network,
  PanelLeftClose,
  RefreshCw,
  Search,
  ServerCog,
  ShieldCheck,
  Sparkles,
  Waypoints,
  X,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api";
import type { Asset, AssetDetail, Coverage, Relationship, Summary } from "./types";

type Page = "dashboard" | "inventory" | "sources";
type DetailTab = "overview" | "relationships" | "evidence";

const KIND_META: Record<string, { label: string; plural: string; icon: LucideIcon; color: string }> = {
  ai_agent: { label: "AI agent", plural: "AI agents", icon: Bot, color: "coral" },
  ai_model: { label: "AI model", plural: "AI models", icon: BrainCircuit, color: "violet" },
  mcp_server: { label: "MCP server", plural: "MCP servers", icon: ServerCog, color: "teal" },
  ai_tool: { label: "AI tool", plural: "AI tools", icon: Zap, color: "amber" },
  ai_guardrail: { label: "Guardrail", plural: "Guardrails", icon: ShieldCheck, color: "green" },
  ai_framework: { label: "AI framework", plural: "AI frameworks", icon: Boxes, color: "blue" },
  ai_pipeline: { label: "AI pipeline", plural: "AI pipelines", icon: GitBranch, color: "blue" },
  ai_datastore: { label: "AI datastore", plural: "AI datastores", icon: Database, color: "green" },
  ai_workload: { label: "AI workload", plural: "AI workloads", icon: Activity, color: "coral" },
  code_repository: { label: "Code repository", plural: "Code repositories", icon: Code2, color: "slate" },
  identity: { label: "Identity", plural: "Identities", icon: Fingerprint, color: "violet" },
};

const FALLBACK_META = { label: "Resource", plural: "Resources", icon: Boxes, color: "slate" };

function meta(kind: string) {
  return KIND_META[kind] ?? {
    ...FALLBACK_META,
    label: titleCase(kind),
    plural: titleCase(kind),
  };
}

function titleCase(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function shortKey(value: string) {
  const pieces = value.split(":");
  return pieces.at(-1)?.replaceAll("-", " ") ?? value;
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

function App() {
  const [page, setPage] = useState<Page>("dashboard");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [coverage, setCoverage] = useState<Coverage[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const loadAll = useCallback(async () => {
    setError(null);
    try {
      const [summaryResult, assetsResult, coverageResult] = await Promise.all([
        api.summary(),
        api.assets(),
        api.coverage(),
      ]);
      setSummary(summaryResult);
      setAssets(assetsResult.items);
      setCoverage(coverageResult.items);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to reach the Denali API");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  function navigate(next: Page) {
    setPage(next);
    setSidebarOpen(false);
  }

  return (
    <div className="app-shell">
      <Sidebar page={page} onNavigate={navigate} open={sidebarOpen} />
      {sidebarOpen && <button className="sidebar-scrim" aria-label="Close menu" onClick={() => setSidebarOpen(false)} />}

      <main className="main-shell">
        <Topbar page={page} onMenu={() => setSidebarOpen(true)} onRefresh={loadAll} />
        <div className="workspace">
          {error ? (
            <ErrorState message={error} onRetry={loadAll} />
          ) : loading || !summary ? (
            <LoadingState />
          ) : page === "dashboard" ? (
            <Dashboard
              summary={summary}
              assets={assets}
              coverage={coverage}
              onOpenAsset={setSelectedId}
              onViewInventory={() => navigate("inventory")}
              onViewSources={() => navigate("sources")}
            />
          ) : page === "inventory" ? (
            <Inventory assets={assets} onOpenAsset={setSelectedId} />
          ) : (
            <Sources coverage={coverage} />
          )}
        </div>
      </main>

      {selectedId && (
        <ResourceDrawer
          assetId={selectedId}
          onClose={() => setSelectedId(null)}
          onOpenAsset={setSelectedId}
          onUpdated={loadAll}
        />
      )}
    </div>
  );
}

function Sidebar({ page, onNavigate, open }: { page: Page; onNavigate: (page: Page) => void; open: boolean }) {
  return (
    <aside className={`sidebar ${open ? "sidebar--open" : ""}`}>
      <div className="brand">
        <span className="brand-mark"><Mountain size={24} strokeWidth={2.3} /></span>
        <span><strong>Denali</strong><small>AI Security</small></span>
      </div>

      <nav className="nav-stack" aria-label="Primary navigation">
        <NavButton active={page === "dashboard"} icon={LayoutDashboard} label="Overview" onClick={() => onNavigate("dashboard")} />
        <NavButton active={page === "inventory"} icon={Boxes} label="Inventory" onClick={() => onNavigate("inventory")} />
        <NavButton active={page === "sources"} icon={Waypoints} label="Sources & coverage" onClick={() => onNavigate("sources")} />
        <p className="nav-heading">SECURITY</p>
        <NavButton icon={CircleAlert} label="Findings" badge="Soon" disabled />
        <NavButton icon={Network} label="Issues & paths" badge="Soon" disabled />
        <NavButton icon={Activity} label="Threats" badge="Soon" disabled />
      </nav>

      <div className="sidebar-footer">
        <div className="preview-chip"><Sparkles size={14} /> Inventory Preview</div>
        <p>Evidence-led AI discovery</p>
        <span className="open-source-label"><FileCode2 size={15} /> Apache 2.0 · Open source</span>
      </div>
    </aside>
  );
}

function NavButton({
  active = false,
  icon: Icon,
  label,
  badge,
  disabled = false,
  onClick,
}: {
  active?: boolean;
  icon: LucideIcon;
  label: string;
  badge?: string;
  disabled?: boolean;
  onClick?: () => void;
}) {
  return (
    <button className={`nav-button ${active ? "is-active" : ""}`} disabled={disabled} onClick={onClick}>
      <Icon size={18} />
      <span>{label}</span>
      {badge && <small>{badge}</small>}
    </button>
  );
}

function Topbar({ page, onMenu, onRefresh }: { page: Page; onMenu: () => void; onRefresh: () => void }) {
  const titles: Record<Page, { eyebrow: string; title: string }> = {
    dashboard: { eyebrow: "Inventory Preview", title: "AI security overview" },
    inventory: { eyebrow: "Discovery", title: "AI inventory" },
    sources: { eyebrow: "Data confidence", title: "Sources & coverage" },
  };
  const content = titles[page];
  return (
    <header className="topbar">
      <button className="mobile-menu" onClick={onMenu} aria-label="Open menu"><Menu /></button>
      <div><span>{content.eyebrow}</span><h1>{content.title}</h1></div>
      <div className="topbar-actions">
        <button className="icon-button" title="Refresh data" onClick={() => void onRefresh()}><RefreshCw size={17} /></button>
        <div className="environment"><span /> Local demo</div>
        <button className="avatar" aria-label="User menu">KM</button>
      </div>
    </header>
  );
}

function Dashboard({
  summary,
  assets,
  coverage,
  onOpenAsset,
  onViewInventory,
  onViewSources,
}: {
  summary: Summary;
  assets: Asset[];
  coverage: Coverage[];
  onOpenAsset: (id: string) => void;
  onViewInventory: () => void;
  onViewSources: () => void;
}) {
  const unreviewed = summary.by_governance.unreviewed ?? 0;
  const verified = assets.filter((asset) => asset.assertion_type === "externally_verified").length;
  const complete = coverage.filter((item) => item.state === "complete").length;
  const allComplete = coverage.length > 0 && complete === coverage.length;
  const kinds = Object.entries(summary.by_kind).sort(([, left], [, right]) => right - left);

  return (
    <div className="page-stack">
      <section className="hero-panel">
        <div>
          <div className="hero-kicker"><span /> LIVE INVENTORY</div>
          <h2>Know every AI system.<br /><em>Trust every claim.</em></h2>
          <p>One evidence-bearing map of agents, models, tools, identities, data, and the systems around them.</p>
        </div>
        <div className="hero-orbit" aria-hidden="true">
          <div className="orbit orbit-one" /><div className="orbit orbit-two" />
          <span className="orbit-core"><Mountain /></span>
          <span className="orbit-node node-one"><Bot /></span>
          <span className="orbit-node node-two"><BrainCircuit /></span>
          <span className="orbit-node node-three"><Database /></span>
        </div>
      </section>

      <section className="metric-grid">
        <MetricCard icon={Boxes} color="coral" label="Known AI resources" value={summary.total} detail={`${kinds.length} resource types`} />
        <MetricCard icon={CircleHelp} color="amber" label="Awaiting review" value={unreviewed} detail="Needs governance decision" />
        <MetricCard icon={ShieldCheck} color="green" label="Verified assertions" value={verified} detail={`${Math.round((verified / Math.max(assets.length, 1)) * 100)}% of active inventory`} />
        <MetricCard icon={Gauge} color="blue" label="Collection coverage" value={`${complete}/${coverage.length}`} detail={allComplete ? "All declared planes complete" : "Review source coverage"} />
      </section>

      <section className="dashboard-grid">
        <div className="panel inventory-map-panel">
          <PanelHeader eyebrow="VISIBILITY" title="Your AI system" action="Explore inventory" onAction={onViewInventory} />
          <div className="composition-list">
            {kinds.map(([kind, count]) => {
              const itemMeta = meta(kind);
              const Icon = itemMeta.icon;
              return (
                <button key={kind} className="composition-row" onClick={onViewInventory}>
                  <span className={`asset-icon ${itemMeta.color}`}><Icon size={18} /></span>
                  <span className="composition-name"><strong>{itemMeta.plural}</strong><small>{count === 1 ? "1 discovered resource" : `${count} discovered resources`}</small></span>
                  <span className="composition-bar"><i style={{ width: `${Math.max(10, (count / summary.total) * 100)}%` }} /></span>
                  <b>{count}</b><ChevronRight size={16} />
                </button>
              );
            })}
          </div>
        </div>

        <div className="right-stack">
          <div className="panel coverage-panel">
            <PanelHeader eyebrow="CONFIDENCE" title="Collection health" action="View sources" onAction={onViewSources} />
            <div className={`coverage-callout ${allComplete ? "complete" : "attention"}`}>
              {allComplete ? <CircleCheck /> : <CircleAlert />}
              <div><strong>{allComplete ? "Coverage is complete" : "Coverage needs attention"}</strong><span>{complete} of {coverage.length} declared collection planes completed</span></div>
            </div>
            {coverage.slice(0, 3).map((item) => <CoverageRow key={`${item.connector_id}-${item.plane}`} item={item} />)}
          </div>

          <div className="panel recent-panel">
            <PanelHeader eyebrow="RECENTLY SEEN" title="Inventory highlights" />
            {assets.slice(0, 4).map((asset) => <AssetMiniRow key={asset.id} asset={asset} onClick={() => onOpenAsset(asset.id)} />)}
          </div>
        </div>
      </section>
      <p className="fixture-note"><CircleHelp size={15} /> This preview uses clearly labelled fixture evidence. Real connectors will never be presented as demo observations.</p>
    </div>
  );
}

function MetricCard({ icon: Icon, color, label, value, detail }: { icon: LucideIcon; color: string; label: string; value: string | number; detail: string }) {
  return <div className="metric-card"><span className={`metric-icon ${color}`}><Icon /></span><div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div></div>;
}

function PanelHeader({ eyebrow, title, action, onAction }: { eyebrow: string; title: string; action?: string; onAction?: () => void }) {
  return <div className="panel-header"><div><span>{eyebrow}</span><h3>{title}</h3></div>{action && <button onClick={onAction}>{action}<ChevronRight size={15} /></button>}</div>;
}

function CoverageRow({ item }: { item: Coverage }) {
  return <div className="coverage-row"><span className={`status-dot ${item.state}`} /><div><strong>{titleCase(item.plane)}</strong><small>{item.connector_id} · {item.scope}</small></div><span className={`state-badge ${item.state}`}>{titleCase(item.state)}</span></div>;
}

function AssetMiniRow({ asset, onClick }: { asset: Asset; onClick: () => void }) {
  const itemMeta = meta(asset.kind); const Icon = itemMeta.icon;
  return <button className="asset-mini-row" onClick={onClick}><span className={`asset-icon ${itemMeta.color}`}><Icon size={17} /></span><span><strong>{asset.display_name ?? shortKey(asset.natural_key)}</strong><small>{itemMeta.label} · {asset.assertion_type?.replaceAll("_", " ")}</small></span><ChevronRight size={16} /></button>;
}

function Inventory({ assets, onOpenAsset }: { assets: Asset[]; onOpenAsset: (id: string) => void }) {
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState("all");
  const [governance, setGovernance] = useState("all");

  const filtered = useMemo(() => assets.filter((asset) => {
    const haystack = `${asset.display_name ?? ""} ${asset.natural_key} ${asset.kind}`.toLowerCase();
    return haystack.includes(search.toLowerCase()) && (kind === "all" || asset.kind === kind) && (governance === "all" || asset.governance_status === governance);
  }), [assets, governance, kind, search]);

  const kinds = [...new Set(assets.map((asset) => asset.kind))].sort();
  return (
    <div className="page-stack">
      <section className="page-intro"><div><span className="eyebrow">CANONICAL INVENTORY</span><h2>Every AI resource, one trustworthy record.</h2><p>Search normalized inventory while preserving every source assertion and its evidence.</p></div><div className="result-count"><strong>{filtered.length}</strong><span>active resources</span></div></section>
      <section className="panel inventory-panel">
        <div className="filterbar">
          <label className="search-field"><Search size={18} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search name, key, or type…" /></label>
          <label className="select-field"><ListFilter size={16} /><select value={kind} onChange={(event) => setKind(event.target.value)}><option value="all">All resource types</option>{kinds.map((item) => <option key={item} value={item}>{meta(item).plural}</option>)}</select></label>
          <label className="select-field"><Filter size={16} /><select value={governance} onChange={(event) => setGovernance(event.target.value)}><option value="all">All governance</option><option value="approved">Approved</option><option value="unreviewed">Unreviewed</option><option value="unwanted">Unwanted</option></select></label>
          {(search || kind !== "all" || governance !== "all") && <button className="clear-button" onClick={() => { setSearch(""); setKind("all"); setGovernance("all"); }}>Clear filters</button>}
        </div>
        <div className="inventory-table" role="table" aria-label="AI inventory">
          <div className="inventory-table-head" role="row"><span>Resource</span><span>Type</span><span>Verification</span><span>Governance</span><span>Last seen</span><span /></div>
          {filtered.map((asset) => <AssetTableRow key={asset.id} asset={asset} onClick={() => onOpenAsset(asset.id)} />)}
          {filtered.length === 0 && <div className="empty-state"><Search /><strong>No inventory matches these filters</strong><span>Try another name or broaden the selected resource type.</span></div>}
        </div>
      </section>
    </div>
  );
}

function AssetTableRow({ asset, onClick }: { asset: Asset; onClick: () => void }) {
  const itemMeta = meta(asset.kind); const Icon = itemMeta.icon;
  return <button className="inventory-table-row" role="row" onClick={onClick}>
    <span className="resource-cell"><span className={`asset-icon ${itemMeta.color}`}><Icon size={18} /></span><span><strong>{asset.display_name ?? shortKey(asset.natural_key)}</strong><small>{asset.natural_key}</small></span></span>
    <span>{itemMeta.label}</span>
    <span><span className="verification"><Check size={13} />{titleCase(asset.assertion_type ?? "unknown")}</span><small className="confidence">{Math.round((asset.confidence ?? 0) * 100)}% confidence</small></span>
    <span><span className={`governance-badge ${asset.governance_status}`}>{titleCase(asset.governance_status)}</span></span>
    <span>{formatTime(asset.last_seen_at)}</span><span><ChevronRight size={17} /></span>
  </button>;
}

function Sources({ coverage }: { coverage: Coverage[] }) {
  const grouped = coverage.reduce<Map<string, Coverage[]>>((result, item) => {
    const key = `${item.connector_id}:${item.connection_id}`;
    result.set(key, [...(result.get(key) ?? []), item]);
    return result;
  }, new Map());
  return <div className="page-stack"><section className="page-intro"><div><span className="eyebrow">COVERAGE BEFORE COUNTS</span><h2>Know exactly what each source could see.</h2><p>Denali keeps partial, failed, unsupported, and unknown coverage visible—never disguised as zero risk.</p></div></section><section className="source-grid">{[...grouped.entries()].map(([key, items]) => <div className="panel source-card" key={key}><div className="source-card-head"><span className="connector-icon"><Waypoints /></span><div><span>CONNECTOR</span><h3>{items[0].connector_id}</h3><p>{items[0].connection_id}</p></div><span className="source-health"><CircleCheck /> Healthy</span></div><div className="source-meta"><span><Clock3 />Last collection <strong>{formatTime(items[0].collected_at)}</strong></span><span><Fingerprint />Scope <strong>{items[0].scope}</strong></span></div><div className="source-planes"><h4>Declared collection planes</h4>{items.map((item) => <CoverageRow key={item.plane} item={item} />)}</div><div className="fixture-banner"><CircleHelp /><span><strong>Transparent fixture source</strong>This connector exists only to exercise the local product experience.</span></div></div>)}</section></div>;
}

function ResourceDrawer({ assetId, onClose, onOpenAsset, onUpdated }: { assetId: string; onClose: () => void; onOpenAsset: (id: string) => void; onUpdated: () => void }) {
  const [detail, setDetail] = useState<AssetDetail | null>(null);
  const [tab, setTab] = useState<DetailTab>("overview");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setDetail(null); setError(null); setTab("overview");
    api.asset(assetId).then(setDetail).catch((cause) => setError(cause instanceof Error ? cause.message : "Unable to load resource"));
  }, [assetId]);

  async function updateGovernance(status: Asset["governance_status"]) {
    if (!detail || saving) return;
    setSaving(true);
    try {
      await api.governance(detail.id, { status, owner: detail.owner, notes: detail.notes });
      setDetail({ ...detail, governance_status: status });
      void onUpdated();
    } finally { setSaving(false); }
  }

  const itemMeta = detail ? meta(detail.kind) : FALLBACK_META;
  const Icon = itemMeta.icon;
  return <div className="drawer-layer"><button className="drawer-scrim" onClick={onClose} aria-label="Close resource detail" /><aside className="resource-drawer" aria-label="Resource detail">
    {!detail && !error ? <LoadingState compact /> : error ? <ErrorState message={error} /> : detail && <>
      <div className="drawer-header"><button className="drawer-close" onClick={onClose}><X /></button><span className={`asset-icon large ${itemMeta.color}`}><Icon /></span><div><span>{itemMeta.label}</span><h2>{detail.assertions[0]?.display_name ?? shortKey(detail.natural_key)}</h2><p>{detail.natural_key}</p></div><span className={`lifecycle-badge ${detail.lifecycle_state}`}><span />{titleCase(detail.lifecycle_state)}</span></div>
      <div className="drawer-actions"><span>Governance</span>{(["approved", "unreviewed", "unwanted"] as const).map((status) => <button key={status} disabled={saving} className={detail.governance_status === status ? "active" : ""} onClick={() => void updateGovernance(status)}>{status === "approved" ? <CircleCheck /> : status === "unwanted" ? <CircleAlert /> : <CircleHelp />}{titleCase(status)}</button>)}</div>
      <div className="drawer-tabs">{(["overview", "relationships", "evidence"] as const).map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => setTab(item)}>{titleCase(item)}{item === "relationships" && <small>{detail.relationships.length}</small>}{item === "evidence" && <small>{detail.assertions.length}</small>}</button>)}</div>
      <div className="drawer-content">
        {tab === "overview" ? <OverviewTab detail={detail} onOpenAsset={onOpenAsset} /> : tab === "relationships" ? <RelationshipsTab detail={detail} onOpenAsset={onOpenAsset} /> : <EvidenceTab detail={detail} />}
      </div>
    </>}
  </aside></div>;
}

function OverviewTab({ detail, onOpenAsset }: { detail: AssetDetail; onOpenAsset: (id: string) => void }) {
  const assertion = detail.assertions[0];
  return <div className="detail-stack"><div className="insight-strip"><Sparkles /><div><span>DENALI INSIGHT</span><strong>This resource is externally verified and linked to {detail.relationships.length} parts of the AI system.</strong><p>Security conclusions remain separate from this inventory assertion.</p></div></div><DetailSection title="Properties"><div className="property-grid"><Property label="Resource type" value={meta(detail.kind).label} /><Property label="Lifecycle" value={titleCase(detail.lifecycle_state)} /><Property label="Assertion" value={titleCase(assertion.assertion_type)} /><Property label="Confidence" value={`${Math.round(assertion.confidence * 100)}%`} /><Property label="First seen" value={formatTime(detail.first_seen_at)} /><Property label="Last changed" value={formatTime(detail.last_changed_at)} /><Property label="Connector" value={assertion.connector_id} /><Property label="Collection scope" value={assertion.scope_key} /></div></DetailSection>{Object.keys(assertion.attributes).length > 0 && <DetailSection title="Normalized attributes"><div className="attribute-list">{Object.entries(assertion.attributes).map(([key, value]) => <div key={key}><span>{titleCase(key)}</span><strong>{String(value)}</strong></div>)}</div></DetailSection>}<DetailSection title="Connected system"><div className="relationship-preview">{detail.relationships.slice(0, 5).map((relation) => <RelationshipRow key={relation.id} relation={relation} currentId={detail.id} onOpenAsset={onOpenAsset} />)}</div></DetailSection></div>;
}

function RelationshipsTab({ detail, onOpenAsset }: { detail: AssetDetail; onOpenAsset: (id: string) => void }) {
  const topology = detail.relationships.filter((item) => item.category === "topology");
  const capability = detail.relationships.filter((item) => item.category === "capability");
  return <div className="detail-stack"><div className="relationship-summary"><div><Network /><strong>{topology.length}</strong><span>Topology links</span></div><div><Zap /><strong>{capability.length}</strong><span>Capability links</span></div></div>{capability.length > 0 && <DetailSection title="Capabilities"><p className="section-explainer">Capability means an authorized action or access path. It does not claim prompt influence or observed execution.</p>{capability.map((relation) => <RelationshipRow key={relation.id} relation={relation} currentId={detail.id} onOpenAsset={onOpenAsset} />)}</DetailSection>}<DetailSection title="Topology">{topology.map((relation) => <RelationshipRow key={relation.id} relation={relation} currentId={detail.id} onOpenAsset={onOpenAsset} />)}</DetailSection></div>;
}

function RelationshipRow({ relation, currentId, onOpenAsset }: { relation: Relationship; currentId: string; onOpenAsset: (id: string) => void }) {
  const isSource = relation.source_id === currentId;
  const otherId = isSource ? relation.target_id : relation.source_id;
  const otherKind = isSource ? relation.target_kind : relation.source_kind;
  const otherKey = isSource ? relation.target_natural_key : relation.source_natural_key;
  const itemMeta = meta(otherKind); const Icon = itemMeta.icon;
  return <button className="relationship-row" onClick={() => onOpenAsset(otherId)}><span className={`asset-icon ${itemMeta.color}`}><Icon size={17} /></span><span className="relation-direction">{isSource ? "This resource" : shortKey(otherKey)} <b>{titleCase(relation.kind)}</b> {isSource ? shortKey(otherKey) : "this resource"}</span><span className={`relation-category ${relation.category}`}>{titleCase(relation.category)}</span><ChevronRight size={16} /></button>;
}

function EvidenceTab({ detail }: { detail: AssetDetail }) {
  return <div className="detail-stack"><div className="evidence-principle"><ShieldCheck /><div><strong>Evidence, not recollection</strong><p>Every claim retains its source, locator, observation time, assertion class, and confidence.</p></div></div>{detail.assertions.map((assertion, index) => <DetailSection key={`${assertion.connector_id}-${index}`} title={assertion.display_name}><div className="evidence-card"><div className="evidence-badges"><span>{titleCase(assertion.assertion_type)}</span><span>{Math.round(assertion.confidence * 100)}% confidence</span><span>{assertion.lifecycle_state}</span></div><Property label="Source type" value={assertion.evidence.source_type} /><Property label="Evidence locator" value={assertion.evidence.locator} mono /><Property label="Observed at" value={formatTime(assertion.evidence.observed_at)} /><Property label="Coverage plane" value={assertion.coverage_plane} /><details><summary>Raw evidence payload</summary><pre>{JSON.stringify(assertion.evidence.payload, null, 2)}</pre></details></div></DetailSection>)}</div>;
}

function DetailSection({ title, children }: { title: string; children: React.ReactNode }) { return <section className="detail-section"><h3>{title}</h3>{children}</section>; }
function Property({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) { return <div className={`property ${mono ? "mono" : ""}`}><span>{label}</span><strong>{value}</strong></div>; }

function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) { return <div className="state-page"><CircleAlert /><h2>Denali could not load inventory</h2><p>{message}</p>{onRetry && <button onClick={() => void onRetry()}><RefreshCw />Try again</button>}</div>; }
function LoadingState({ compact = false }: { compact?: boolean }) { return <div className={`loading-state ${compact ? "compact" : ""}`}><Mountain /><span /><p>Mapping the AI system…</p></div>; }

export default App;
