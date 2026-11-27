export type SemverCageSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type SemverCagePolicyName = 'strict' | 'balanced' | 'ci';
export type SemverCageComparison = -1 | 0 | 1;

export interface SemverVersion {
  readonly version: string;
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly prerelease: readonly string[];
  readonly build: readonly string[];
  readonly isPrerelease: boolean;
  readonly hasBuild: boolean;
}

export interface SemverComparator {
  readonly operator: 'any' | 'none' | 'eq' | 'gt' | 'gte' | 'lt' | 'lte';
  readonly version: SemverVersion | null;
  readonly source: string;
}

export interface SemverRangeUnion {
  readonly source: string;
  readonly comparators: readonly SemverComparator[];
}

export interface SemverRange {
  readonly kind: 'SEMVERCAGE_RANGE';
  readonly input: string;
  readonly unions: readonly SemverRangeUnion[];
  readonly unionCount: number;
  readonly comparatorCount: number;
}

export interface SemverCageFinding {
  readonly code: string;
  readonly severity: SemverCageSeverity;
  readonly message: string;
  readonly remediation: string;
  readonly path?: string;
  readonly packageName?: string;
  readonly specifier?: string;
  readonly dependencyType?: string;
  readonly [key: string]: unknown;
}

export interface SemverCageSeverityCounts {
  readonly critical: number;
  readonly high: number;
  readonly medium: number;
  readonly low: number;
  readonly info: number;
}

export interface SemverCageReport {
  readonly ok: boolean;
  readonly target: string;
  readonly policy: string;
  readonly findings: readonly SemverCageFinding[];
  readonly counts: SemverCageSeverityCounts;
  readonly [key: string]: unknown;
}

export interface SemverCagePolicy {
  readonly name: SemverCagePolicyName;
  readonly failOn: Exclude<SemverCageSeverity, 'info'>;
  readonly maxInputLength: number;
  readonly maxRangeLength: number;
  readonly maxUnions: number;
  readonly maxComparatorsPerUnion: number;
  readonly maxTotalComparators: number;
  readonly maxObjectDepth: number;
  readonly maxObjectKeys: number;
  readonly maxIdentifierLength: number;
  readonly maxVersionLength: number;
  readonly maxVersionIdentifiers: number;
  readonly trustedRegistries: readonly string[];
  readonly privateNamePrefixes: readonly string[];
  readonly allowPrerelease: boolean;
  readonly requireHttps: boolean;
  readonly requireIntegrity: boolean;
  readonly maxMajorJump: number;
}

export interface SemverCagePolicyOverrides {
  readonly failOn?: Exclude<SemverCageSeverity, 'info'>;
  readonly maxInputLength?: number;
  readonly maxRangeLength?: number;
  readonly maxUnions?: number;
  readonly maxComparatorsPerUnion?: number;
  readonly maxTotalComparators?: number;
  readonly maxObjectDepth?: number;
  readonly maxObjectKeys?: number;
  readonly maxIdentifierLength?: number;
  readonly maxVersionLength?: number;
  readonly maxVersionIdentifiers?: number;
  readonly trustedRegistries?: readonly string[];
  readonly privateNamePrefixes?: readonly string[];
  readonly allowPrerelease?: boolean;
  readonly requireHttps?: boolean;
  readonly requireIntegrity?: boolean;
  readonly maxMajorJump?: number;
}

export type SemverParseOptions = Pick<SemverCagePolicyOverrides, 'maxVersionLength' | 'maxIdentifierLength' | 'maxVersionIdentifiers'>;
export type RangeParseOptions = SemverCagePolicyOverrides & { readonly policy?: SemverCagePolicyName };
export type SatisfiesOptions = RangeParseOptions & { readonly includePrerelease?: boolean };
export type AuditOptions = SemverCagePolicyOverrides & {
  readonly policy?: SemverCagePolicyName;
  readonly dependencyType?: string;
  readonly includePrerelease?: boolean;
};
export type UpgradeAuditOptions = AuditOptions | SemverCagePolicyName;

export const SEMVERCAGE_VERSION: string;
export const SEMVERCAGE_ERROR_CODES: Readonly<Record<string, string>>;
export const SEMVERCAGE_FINDING_CODES: Readonly<Record<string, string>>;
export const SEMVERCAGE_SEVERITY: Readonly<Record<string, SemverCageSeverity>>;
export const SEVERITY_RANK: Readonly<Record<SemverCageSeverity, number>>;
export const DEPENDENCY_FIELDS: readonly string[];
export const OVERRIDE_FIELDS: readonly string[];
export const LIFECYCLE_SCRIPTS: readonly string[];
export const POLLUTION_KEYS: readonly string[];
export const SEMVERCAGE_POLICY_PRESETS: Readonly<Record<SemverCagePolicyName, SemverCagePolicy>>;
export const SEMVERCAGE_DEFAULT_POLICY: SemverCagePolicy;

export class SemverCageError extends Error {
  constructor(code: string, message: string, details?: Record<string, unknown>);
  readonly code: string;
  readonly details: Readonly<Record<string, unknown>>;
}

export function semvercageError(code: string, message: string, details?: Record<string, unknown>): SemverCageError;
export function isSemverCageError(value: unknown): value is SemverCageError;
export function createPolicy(base?: SemverCagePolicyName | SemverCagePolicyOverrides, overrides?: SemverCagePolicyOverrides): SemverCagePolicy;
export function getPolicy(name?: SemverCagePolicyName): SemverCagePolicy;
export function resolvePolicy(options?: AuditOptions | SemverCagePolicyName): SemverCagePolicy;
export function parseSemver(input: string, options?: SemverParseOptions): SemverVersion;
export function tryParseSemver(input: unknown, options?: SemverParseOptions): SemverVersion | null;
export function isValidSemver(input: unknown, options?: SemverParseOptions): boolean;
export function compareSemver(left: string | SemverVersion, right: string | SemverVersion): SemverCageComparison;
export function parseRange(input: string, options?: RangeParseOptions): SemverRange;
export function isValidRange(input: unknown, options?: RangeParseOptions): boolean;
export function satisfies(version: string | SemverVersion, range: string | SemverRange, options?: SatisfiesOptions): boolean;
export function auditSpecifier(packageName: string, specifier: string, options?: AuditOptions): SemverCageReport;
export function auditPackageJson(manifest: unknown, options?: AuditOptions): SemverCageReport;
export function auditLockfile(lockfile: unknown, options?: AuditOptions): SemverCageReport;
export function auditUpgrade(fromVersion: string, toVersion: string, options?: UpgradeAuditOptions): SemverCageReport;

declare const semvercage: {
  readonly SEMVERCAGE_VERSION: typeof SEMVERCAGE_VERSION;
  readonly SEMVERCAGE_ERROR_CODES: typeof SEMVERCAGE_ERROR_CODES;
  readonly SEMVERCAGE_FINDING_CODES: typeof SEMVERCAGE_FINDING_CODES;
  readonly SEMVERCAGE_SEVERITY: typeof SEMVERCAGE_SEVERITY;
  readonly SEVERITY_RANK: typeof SEVERITY_RANK;
  readonly SEMVERCAGE_POLICY_PRESETS: typeof SEMVERCAGE_POLICY_PRESETS;
  readonly SEMVERCAGE_DEFAULT_POLICY: typeof SEMVERCAGE_DEFAULT_POLICY;
  readonly SemverCageError: typeof SemverCageError;
  readonly semvercageError: typeof semvercageError;
  readonly isSemverCageError: typeof isSemverCageError;
  readonly createPolicy: typeof createPolicy;
  readonly getPolicy: typeof getPolicy;
  readonly resolvePolicy: typeof resolvePolicy;
  readonly parseSemver: typeof parseSemver;
  readonly tryParseSemver: typeof tryParseSemver;
  readonly isValidSemver: typeof isValidSemver;
  readonly compareSemver: typeof compareSemver;
  readonly parseRange: typeof parseRange;
  readonly isValidRange: typeof isValidRange;
  readonly satisfies: typeof satisfies;
  readonly auditSpecifier: typeof auditSpecifier;
  readonly auditPackageJson: typeof auditPackageJson;
  readonly auditLockfile: typeof auditLockfile;
  readonly auditUpgrade: typeof auditUpgrade;
};

export default semvercage;
