/**
 * TheAgentDeck AirLock — Core Packet Types
 * Version: 1.0
 * This is the canonical type definition shared across all AirLock packages.
 * Both scanner-generated and publisher-signed packets use these types.
 */

// ─── Top-Level Packet ───────────────────────────────────────────────────────

export interface AirlockPacket {
  airlock_version: string;
  packet_origin: 'scanner' | 'publisher';
  url: string;
  fetched_at: string;
  source_type: SourceType;
  trust_level: TrustLevel;
  page_risk: RiskLevel;

  publisher_signature: string | null;
  publisher_verified: boolean;

  agent_instruction_policy: AgentInstructionPolicy;

  extracted_content: ExtractedContent;
  suspicious_content: SuspiciousContent[];
  links: ClassifiedLink[];
  forms: ClassifiedForm[];

  blocked_sinks: Sink[];
  allowed_sinks: Sink[];

  recommendation: string;

  packet_hash: string;
  scan_id: string;
}

// ─── Enums (as union types) ──────────────────────────────────────────────────

export type SourceType =
  | 'public_forum'
  | 'news_site'
  | 'blog'
  | 'ecommerce'
  | 'social_media'
  | 'documentation'
  | 'search_engine'
  | 'unknown';

export type TrustLevel = 'high' | 'medium' | 'low' | 'untrusted';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

// ─── Agent Instruction Policy ───────────────────────────────────────────────

export interface AgentInstructionPolicy {
  external_content_has_authority: boolean;
  tool_calls_allowed_from_page: boolean;
  memory_write_allowed: boolean;
  outbound_links_require_review: boolean;
}

// ─── Extracted Content ──────────────────────────────────────────────────────

export interface ExtractedContent {
  title: string;
  visible_text_summary: string;
  key_claims: Claim[];
}

export interface Claim {
  claim: string;
  confidence: 'high' | 'medium' | 'low';
  evidence_type: 'verified' | 'anecdotal' | 'disputed' | 'unverifiable';
  source_hop: string;
  provenance_chain: string;
  memory_status?: MemoryStatus;
}

export type MemoryStatus = 'blocked_by_default' | 'pending_review' | 'approved';

// ─── Suspicious Content ─────────────────────────────────────────────────────

export interface SuspiciousContent {
  type: SuspiciousType;
  severity: RiskLevel;
  text: string;
  lane: ContentLane;
  mitigation: string;
}

export type SuspiciousType =
  | 'prompt_injection'
  | 'credential_request'
  | 'exfiltration_attempt'
  | 'authority_claim'
  | 'hidden_instruction'
  | 'obfuscated_link';

export type ContentLane =
  | 'facts_claims'
  | 'opinions'
  | 'links'
  | 'forms'
  | 'code'
  | 'images'
  | 'hidden_text'
  | 'potential_instructions'
  | 'potential_exfiltration'
  | 'authority_claims';

// ─── Links + Forms ──────────────────────────────────────────────────────────

export interface ClassifiedLink {
  url: string;
  anchor_text?: string;
  risk: RiskLevel;
  reason: string;
  allowed: boolean;
}

export interface ClassifiedForm {
  description: string;
  fields: string[];
  inert: boolean;
  action: 'blocked' | 'requires_approval' | 'allowed';
}

// ─── Sinks ──────────────────────────────────────────────────────────────────

export type Sink =
  | 'summarize'
  | 'classify'
  | 'quote_with_citation'
  | 'add_to_temp_research_notes'
  | 'send_email'
  | 'post_to_social'
  | 'update_database'
  | 'update_listing'
  | 'create_memory'
  | 'run_code'
  | 'call_payment_api'
  | 'reveal_internal_context'
  | 'navigate_to_url'
  | 'fill_form'
  | 'submit_form';

// ─── Scan Request / Response ────────────────────────────────────────────────

export interface ScanRequest {
  url: string;
  agent: string;
  mission: string;
  mode: ScanMode;
  memoryWrite?: boolean;
}

export type ScanMode = 'read' | 'inspect' | 'interact';

export interface ScanResult {
  packet: AirlockPacket;
  read_receipt?: ReadReceipt;
}

export interface ReadReceipt {
  agent: string;
  mission: string;
  decision: 'used' | 'ignored' | 'flagged';
  reason: string;
  timestamp: string;
}

// ─── Discovery Endpoint (Phase 4) ──────────────────────────────────────────

export interface AirlockDiscoveryDocument {
  airlock_version: string;
  publisher: string;
  publisher_name: string;
  trust_signals: TrustSignals;
  feeds: Feed[];
  signing_key: SigningKey;
  instruction_authority: 'none' | 'publisher_attested';
  contact: string;
}

export interface TrustSignals {
  verified_publisher: boolean;
  reputation_score: number;
  verification_method: string;
}

export interface Feed {
  name: string;
  url: string;
  frequency: string;
  tier: 'free' | 'paid';
  pricing_url?: string;
}

export interface SigningKey {
  algorithm: 'ed25519';
  public_key: string;
  rotation_url: string;
}

// ─── Logger Schema ──────────────────────────────────────────────────────────

export interface ScanLogEntry {
  scan_id: string;
  requesting_agent: string;
  mission: string;
  source_url: string;
  packet_origin: 'scanner' | 'publisher';
  risk_level: RiskLevel;
  page_risk: RiskLevel;
  packet_hash: string;
  blocked_sinks: string[];
  allowed_sinks: string[];
  downstream_decision?: string;
  memory_promoted: boolean;
  promoted_by?: string;
  timestamp: string;
}