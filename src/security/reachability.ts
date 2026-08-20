/**
 * KiroGraph-Sec Reachability Analyzer
 *
 * Traverses the knowledge graph from application entry points to determine
 * whether vulnerable dependencies are reachable through actual code paths.
 * Produces reachability verdicts and impact summaries enriched with
 * architectural layer context.
 *
 * Requirements: 4.1, 4.2, 4.3, 4.4, 4.6, 5.1, 5.2, 5.3, 5.4, 5.5
 */

import type { GraphDatabase } from '../db/database';
import type { KiroGraphConfig } from '../config';
import type {
  ReachabilityVerdict,
  ReachabilityPath,
  ReachabilityResult,
  ImpactSummary,
} from './types';

/** Edge kinds used for reachability traversal */
const TRAVERSAL_EDGE_KINDS = ['calls', 'imports', 'references'] as const;

/** Maximum unresolved symbols to report */
const MAX_UNRESOLVED_SYMBOLS = 50;

/** Maximum distinct paths to report in impact summary */
const MAX_DISTINCT_PATHS = 100;

/**
 * ReachabilityAnalyzer traverses the knowledge graph from entry points
 * toward affected dependency nodes to determine reachability verdicts.
 */
export class ReachabilityAnalyzer {
  private readonly db: GraphDatabase;
  private readonly config: KiroGraphConfig;

  constructor(db: GraphDatabase, config: KiroGraphConfig) {
    this.db = db;
    this.config = config;
  }

  /**
   * Analyze reachability for a single Vulnerability_Node.
   *
   * 1. Find the Dependency_Node linked via `has_vulnerability` edge
   * 2. Find all Entry_Points in the graph
   * 3. BFS from each entry point toward the dependency node
   * 4. Assign verdict based on path existence and unresolved imports
   *
   * Requirements: 4.1, 4.2, 4.3, 4.4, 4.6
   */
  async analyze(vulnerabilityNodeId: string): Promise<ReachabilityResult> {
    const rawDb = this.db.getRawDb();

    // Step 1: Find the Dependency_Node linked to this vulnerability
    const depEdge = rawDb.get(
      `SELECT source FROM edges WHERE target = ? AND kind = 'has_vulnerability'`,
      [vulnerabilityNodeId],
    );

    if (!depEdge) {
      // No dependency linked — cannot determine reachability
      return {
        verdict: 'under_investigation',
        paths: [],
        unresolvedSymbols: [],
        reachingEntryPointCount: 0,
      };
    }

    const dependencyNodeId: string = depEdge.source;

    // Step 2: Find all Entry_Points
    // Entry points are: nodes with kind='route' OR nodes with kind='function' that are exported
    const entryPoints: Array<{ id: string }> = rawDb.all(
      `SELECT id FROM nodes WHERE kind = 'route'
       UNION
       SELECT id FROM nodes WHERE kind = 'function' AND is_exported = 1`,
    );

    if (entryPoints.length === 0) {
      // No entry points — cannot determine reachability
      return {
        verdict: 'not_affected',
        paths: [],
        unresolvedSymbols: [],
        reachingEntryPointCount: 0,
      };
    }

    // Step 3: Reverse BFS from the dependency node through INCOMING edges
    // to find which entry points can reach it. This is O(V+E) per vulnerability
    // instead of O(entryPoints × (V+E)) for forward BFS from each entry point.
    const reachingPaths: ReachabilityPath[] = [];
    const allUnresolvedSymbols = new Set<string>();
    const entryPointIds = new Set(entryPoints.map(ep => ep.id));
    const reachableFrom = this.reverseBfsToEntryPoints(rawDb, dependencyNodeId, entryPointIds);
    for (const { entryPointId, path } of reachableFrom) {
      reachingPaths.push({
        entryPoint: entryPointId,
        path,
      });
    }

    // Step 4: Assign verdict
    const unresolvedSymbols = Array.from(allUnresolvedSymbols).slice(0, MAX_UNRESOLVED_SYMBOLS);

    let verdict: ReachabilityVerdict;
    if (reachingPaths.length > 0) {
      verdict = 'affected';
    } else if (allUnresolvedSymbols.size > 0) {
      verdict = 'under_investigation';
    } else {
      verdict = 'not_affected';
    }

    const result: ReachabilityResult = {
      verdict,
      paths: reachingPaths,
      unresolvedSymbols: verdict === 'under_investigation' ? unresolvedSymbols : [],
      reachingEntryPointCount: reachingPaths.length,
    };

    // Store result in sec_reachability table
    this.storeReachabilityResult(rawDb, vulnerabilityNodeId, result);

    return result;
  }

  /**
   * Produce impact summary for an affected vulnerability.
   *
   * Returns null if the vulnerability is not affected.
   * Reads layer assignments from `arch_file_layers` table.
   *
   * Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
   */
  async getImpactSummary(vulnerabilityNodeId: string): Promise<ImpactSummary | null> {
    const rawDb = this.db.getRawDb();

    // Check if the vulnerability has verdict 'affected'
    const reachRow = rawDb.get(
      `SELECT verdict, paths, reaching_entry_point_count FROM sec_reachability WHERE vulnerability_node_id = ?`,
      [vulnerabilityNodeId],
    );

    if (!reachRow || reachRow.verdict !== 'affected') {
      return null;
    }

    const paths: ReachabilityPath[] = reachRow.paths ? JSON.parse(reachRow.paths) : [];

    if (paths.length === 0) {
      return null;
    }

    // Collect all node IDs on reachable paths
    const allNodeIds = new Set<string>();
    const affectedEntryPoints: string[] = [];

    for (const p of paths) {
      affectedEntryPoints.push(p.entryPoint);
      for (const nodeId of p.path) {
        allNodeIds.add(nodeId);
      }
    }

    // Identify architectural layers on reachable paths
    const affectedLayers = new Set<string>();

    if (this.config.enableArchitecture) {
      // Get file paths for all nodes on reachable paths
      const nodeIds = Array.from(allNodeIds);
      if (nodeIds.length > 0) {
        const placeholders = nodeIds.map(() => '?').join(',');
        const nodeFiles: Array<{ id: string; file_path: string }> = rawDb.all(
          `SELECT id, file_path FROM nodes WHERE id IN (${placeholders})`,
          nodeIds,
        );

        // Get layer assignments for those files from arch_file_layers
        const filePaths = [...new Set(nodeFiles.map(n => n.file_path).filter(Boolean))];
        if (filePaths.length > 0) {
          const filePlaceholders = filePaths.map(() => '?').join(',');
          const layerRows: Array<{ file_path: string; layer_id: string }> = rawDb.all(
            `SELECT file_path, layer_id FROM arch_file_layers WHERE file_path IN (${filePlaceholders})`,
            filePaths,
          );

          const fileToLayer = new Map<string, string>();
          for (const row of layerRows) {
            fileToLayer.set(row.file_path, row.layer_id);
          }

          // Assign layers to nodes; classify as "unclassified" if no layer assigned
          for (const nf of nodeFiles) {
            if (nf.file_path) {
              const layer = fileToLayer.get(nf.file_path);
              affectedLayers.add(layer ?? 'unclassified');
            }
          }
        }
      }
    }
    // When enableArchitecture is false, omit layer classification (Requirement 5.4)

    // Count distinct paths (capped at MAX_DISTINCT_PATHS)
    // Two paths are distinct if they differ by at least one intermediate symbol
    const distinctPathSet = new Set<string>();
    for (const p of paths) {
      // Use the full path as a key for distinctness
      const pathKey = p.path.join('→');
      distinctPathSet.add(pathKey);
      if (distinctPathSet.size >= MAX_DISTINCT_PATHS) break;
    }

    const summary: ImpactSummary = {
      affectedLayers: Array.from(affectedLayers),
      affectedEntryPoints,
      distinctPathCount: Math.min(distinctPathSet.size, MAX_DISTINCT_PATHS),
    };

    // Store impact summary in sec_impact table
    this.storeImpactSummary(rawDb, vulnerabilityNodeId, summary);

    return summary;
  }

  /**
   * Analyze all Vulnerability_Nodes in the graph.
   *
   * Iterates all vulnerability nodes and calls analyze() for each.
   */
  async analyzeAll(): Promise<Map<string, ReachabilityResult>> {
    const rawDb = this.db.getRawDb();
    const results = new Map<string, ReachabilityResult>();

    const vulnRows: Array<{ node_id: string }> = rawDb.all(
      `SELECT node_id FROM sec_vulnerabilities`,
    );

    for (const row of vulnRows) {
      const result = await this.analyze(row.node_id);
      results.set(row.node_id, result);
    }

    return results;
  }

  /**
   * BFS from a single entry point toward the dependency node.
   *
   * Uses outgoing edges of types: calls, imports, references.
   * Visits each node at most once (handles cycles).
   * Tracks unresolved imports encountered during traversal.
   *
   * Returns the shortest path if found, plus any unresolved symbols encountered.
   */
  /**
   * Reverse BFS: start from the dependency node and walk BACKWARDS through
   * incoming edges to find which entry points can reach it.
   *
   * This is O(V+E) total (one traversal) regardless of how many entry points exist,
   * compared to O(entryPoints × (V+E)) for forward BFS from each entry point.
   *
   * Returns the entry points that have a path to the dependency, with their paths.
   */
  private reverseBfsToEntryPoints(
    rawDb: any,
    dependencyNodeId: string,
    entryPointIds: Set<string>,
  ): Array<{ entryPointId: string; path: string[] }> {
    const results: Array<{ entryPointId: string; path: string[] }> = [];
    const visited = new Set<string>();
    const parentMap = new Map<string, string>(); // child → parent (for path reconstruction)

    const edgeKinds = TRAVERSAL_EDGE_KINDS.map(k => `'${k}'`).join(',');
    const queue: string[] = [dependencyNodeId];
    visited.add(dependencyNodeId);

    while (queue.length > 0) {
      const currentId = queue.shift()!;

      // Check if we reached an entry point
      if (currentId !== dependencyNodeId && entryPointIds.has(currentId)) {
        // Reconstruct path from entry point to dependency
        const path: string[] = [];
        let node: string | undefined = currentId;
        while (node !== undefined) {
          path.push(node);
          node = parentMap.get(node);
        }
        // path is [entryPoint, ..., dependencyNode] — already correct direction
        results.push({ entryPointId: currentId, path });
        // Don't stop — there may be other entry points reachable
        continue;
      }

      // Walk INCOMING edges (reverse direction: who calls/imports currentId?)
      const inEdges: Array<{ source: string }> = rawDb.all(
        `SELECT source FROM edges WHERE target = ? AND kind IN (${edgeKinds})`,
        [currentId],
      );

      for (const edge of inEdges) {
        if (visited.has(edge.source)) continue;
        visited.add(edge.source);
        parentMap.set(edge.source, currentId);
        queue.push(edge.source);
      }
    }

    return results;
  }

  private bfsFromEntryPoint(
    rawDb: any,
    entryPointId: string,
    dependencyNodeId: string,
  ): { path: string[] | null; unresolvedSymbols: string[] } {
    const visited = new Set<string>();
    const unresolvedSymbols: string[] = [];

    // BFS queue: each entry is [nodeId, path from entry point]
    const queue: Array<[string, string[]]> = [[entryPointId, [entryPointId]]];
    visited.add(entryPointId);

    // Prepare edge kind filter
    const edgeKinds = TRAVERSAL_EDGE_KINDS.map(k => `'${k}'`).join(',');

    while (queue.length > 0) {
      const [currentId, currentPath] = queue.shift()!;

      // Get outgoing edges from current node (calls, imports, references)
      const outEdges: Array<{ target: string; kind: string }> = rawDb.all(
        `SELECT target, kind FROM edges WHERE source = ? AND kind IN (${edgeKinds})`,
        [currentId],
      );

      // Check if current node is an unresolved import
      // An unresolved import is a node with kind='import' that has no outgoing edges
      if (outEdges.length === 0) {
        const nodeRow = rawDb.get(
          `SELECT kind FROM nodes WHERE id = ?`,
          [currentId],
        );
        if (nodeRow && nodeRow.kind === 'import') {
          unresolvedSymbols.push(currentId);
        }
      }

      for (const edge of outEdges) {
        const targetId = edge.target;

        // Check if we reached the dependency node
        if (targetId === dependencyNodeId) {
          return {
            path: [...currentPath, targetId],
            unresolvedSymbols,
          };
        }

        // Skip already visited nodes (cycle handling)
        if (visited.has(targetId)) continue;
        visited.add(targetId);

        queue.push([targetId, [...currentPath, targetId]]);
      }
    }

    // No path found from this entry point
    return { path: null, unresolvedSymbols };
  }

  /**
   * Store reachability result in sec_reachability table.
   */
  private storeReachabilityResult(
    rawDb: any,
    vulnerabilityNodeId: string,
    result: ReachabilityResult,
  ): void {
    rawDb.run(
      `INSERT OR REPLACE INTO sec_reachability
        (vulnerability_node_id, verdict, paths, unresolved_symbols, reaching_entry_point_count, analyzed_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        vulnerabilityNodeId,
        result.verdict,
        result.paths.length > 0 ? JSON.stringify(result.paths) : null,
        result.unresolvedSymbols.length > 0 ? JSON.stringify(result.unresolvedSymbols) : null,
        result.reachingEntryPointCount,
        Date.now(),
      ],
    );
  }

  /**
   * Store impact summary in sec_impact table.
   */
  private storeImpactSummary(
    rawDb: any,
    vulnerabilityNodeId: string,
    summary: ImpactSummary,
  ): void {
    rawDb.run(
      `INSERT OR REPLACE INTO sec_impact
        (vulnerability_node_id, affected_layers, affected_entry_points, distinct_path_count, analyzed_at)
       VALUES (?, ?, ?, ?, ?)`,
      [
        vulnerabilityNodeId,
        JSON.stringify(summary.affectedLayers),
        JSON.stringify(summary.affectedEntryPoints),
        summary.distinctPathCount,
        Date.now(),
      ],
    );
  }
}
