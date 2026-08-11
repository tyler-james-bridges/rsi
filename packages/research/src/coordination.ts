import { createHash } from "node:crypto";

import type { XPostFixture } from "./schemas.js";
import { socialContentFingerprint, type NormalizedUrlTrace } from "./signals.js";

export type CoordinationSignal =
  | "coordination:duplicate-content"
  | "coordination:duplicate-post-id"
  | "coordination:same-author"
  | "coordination:synchronized-destination";

export interface SocialClusterInput {
  observationId: string;
  fixture: XPostFixture;
  urls: readonly NormalizedUrlTrace[];
}

export interface CoordinationAssignment {
  coordinationClusterId: string;
  memberCount: number;
  signals: readonly CoordinationSignal[];
}

interface MutableAssignment {
  coordinationClusterId: string;
  memberCount: number;
  signals: Set<CoordinationSignal>;
}

function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 32);
}

function shareFinalDestination(
  left: readonly NormalizedUrlTrace[],
  right: readonly NormalizedUrlTrace[],
): boolean {
  const leftDestinations = new Set(left.map((trace) => trace.final.normalizedUrl));
  return right.some((trace) => leftDestinations.has(trace.final.normalizedUrl));
}

function addSignal(
  signals: Map<number, Set<CoordinationSignal>>,
  left: number,
  right: number,
  signal: CoordinationSignal,
): void {
  signals.get(left)?.add(signal);
  signals.get(right)?.add(signal);
}

/**
 * Clusters copied posts at any distance, and synchronized posts only when they
 * share a collector-observed final URL. Proximity alone is intentionally not
 * treated as proof of coordination.
 */
export function clusterSocialFixtures(
  inputs: readonly SocialClusterInput[],
  synchronizationWindowSeconds = 120,
): ReadonlyMap<string, CoordinationAssignment> {
  if (
    !Number.isInteger(synchronizationWindowSeconds) ||
    synchronizationWindowSeconds < 0 ||
    synchronizationWindowSeconds > 3_600
  ) {
    throw new Error("synchronizationWindowSeconds must be an integer between 0 and 3600");
  }

  const parents = inputs.map((_, index) => index);
  const signals = new Map(
    inputs.map((_, index) => [index, new Set<CoordinationSignal>()] as const),
  );
  const fingerprints = inputs.map(({ fixture }) => socialContentFingerprint(fixture));

  const find = (index: number): number => {
    let root = index;
    while (parents[root] !== root) {
      root = parents[root]!;
    }
    while (parents[index] !== index) {
      const next = parents[index]!;
      parents[index] = root;
      index = next;
    }
    return root;
  };

  const union = (left: number, right: number): void => {
    const leftRoot = find(left);
    const rightRoot = find(right);
    if (leftRoot !== rightRoot) {
      parents[Math.max(leftRoot, rightRoot)] = Math.min(leftRoot, rightRoot);
    }
  };

  for (let left = 0; left < inputs.length; left += 1) {
    const leftInput = inputs[left]!;
    for (let right = left + 1; right < inputs.length; right += 1) {
      const rightInput = inputs[right]!;
      let linked = false;

      if (leftInput.fixture.post.author.authorId === rightInput.fixture.post.author.authorId) {
        addSignal(signals, left, right, "coordination:same-author");
        linked = true;
      }

      if (leftInput.fixture.post.postId === rightInput.fixture.post.postId) {
        addSignal(signals, left, right, "coordination:duplicate-post-id");
        linked = true;
      }
      if (fingerprints[left] === fingerprints[right]) {
        addSignal(signals, left, right, "coordination:duplicate-content");
        linked = true;
      }

      const timeDeltaMs = Math.abs(
        Date.parse(leftInput.fixture.post.createdAt) -
          Date.parse(rightInput.fixture.post.createdAt),
      );
      if (
        timeDeltaMs <= synchronizationWindowSeconds * 1_000 &&
        shareFinalDestination(leftInput.urls, rightInput.urls)
      ) {
        addSignal(signals, left, right, "coordination:synchronized-destination");
        linked = true;
      }

      if (linked) union(left, right);
    }
  }

  const components = new Map<number, number[]>();
  for (let index = 0; index < inputs.length; index += 1) {
    const root = find(index);
    const members = components.get(root) ?? [];
    members.push(index);
    components.set(root, members);
  }

  const mutable = new Map<string, MutableAssignment>();
  for (const members of components.values()) {
    const memberIds = members.map((index) => inputs[index]!.observationId).sort();
    const clusterId = `x-cluster:${shortHash(memberIds.join("|"))}`;
    const componentSignals = new Set<CoordinationSignal>();
    for (const index of members) {
      for (const signal of signals.get(index) ?? []) componentSignals.add(signal);
    }
    for (const index of members) {
      mutable.set(inputs[index]!.observationId, {
        coordinationClusterId: clusterId,
        memberCount: members.length,
        signals: componentSignals,
      });
    }
  }

  return new Map(
    [...mutable].map(([observationId, assignment]) => [
      observationId,
      {
        coordinationClusterId: assignment.coordinationClusterId,
        memberCount: assignment.memberCount,
        signals: [...assignment.signals].sort(),
      },
    ]),
  );
}
