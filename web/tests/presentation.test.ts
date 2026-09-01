import assert from "node:assert/strict";
import test from "node:test";
import { applicableDetectionEvaluations } from "../src/presentation.ts";
import type {
  Coverage,
  RuntimeDetection,
  RuntimeDetectionEvaluation,
} from "../src/types.ts";

const entraEvaluation: RuntimeDetectionEvaluation = {
  rule_uid: "DENALI-RUNTIME-ENTRA-CONSENT-001",
  state: "unknown",
  confirmed_detections: 0,
  incomplete_candidates: 0,
  detail: null,
  evaluated_at: "2026-08-31T00:00:00Z",
};

test("Entra rules are hidden when the tenant has no Entra evidence boundary", () => {
  assert.deepEqual(applicableDetectionEvaluations([entraEvaluation], [], []), []);
});

test("Entra rules remain visible when Entra coverage or a retained detection exists", () => {
  const coverage = [{ connector_id: "denali.entra_ai" }] as Coverage[];
  assert.deepEqual(applicableDetectionEvaluations([entraEvaluation], [], coverage), [entraEvaluation]);

  const detections = [{ rule_uid: entraEvaluation.rule_uid }] as RuntimeDetection[];
  assert.deepEqual(applicableDetectionEvaluations([entraEvaluation], detections, []), [entraEvaluation]);
});
