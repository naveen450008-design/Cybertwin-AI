"""Similar Incident Search Service using Cosine Vector Similarity.

Compares normalized incident feature representations to identify historical
analogues and recommend proven containment playbooks.
"""

import math
import uuid
from typing import List, Dict, Any, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.incident import Incident


class SimilarIncidentService:
    @staticmethod
    def _incident_to_vector(inc: Incident) -> List[float]:
        """Maps incident attributes to normalized 5-dimensional numerical vector."""
        return [
            float(inc.risk_score) / 100.0,
            float(inc.threat_severity_score) / 100.0,
            float(inc.attack_stage_score) / 100.0,
            float(inc.anomaly_score) / 100.0,
            min(1.0, float(inc.event_sequence_score) / 100.0)
        ]

    @staticmethod
    def _cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
        dot = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = math.sqrt(sum(a * a for a in vec1))
        norm2 = math.sqrt(sum(b * b for b in vec2))
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot / (norm1 * norm2)

    @classmethod
    async def find_similar_incidents(
        cls,
        db: AsyncSession,
        target_incident_id: uuid.UUID,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """Finds historical incidents similar to the target incident."""
        # 1. Fetch target incident
        target_res = await db.execute(
            select(Incident).where(Incident.incident_id == target_incident_id)
        )
        target = target_res.scalar_one_or_none()
        if not target:
            return []

        target_vec = cls._incident_to_vector(target)

        # 2. Fetch candidates (different incident_id)
        candidates_res = await db.execute(
            select(Incident)
            .where(Incident.incident_id != target_incident_id)
            .limit(100)
        )
        candidates = candidates_res.scalars().all()

        scored = []
        for cand in candidates:
            cand_vec = cls._incident_to_vector(cand)
            similarity = cls._cosine_similarity(target_vec, cand_vec)
            scored.append({
                "incident_id": str(cand.incident_id),
                "title": cand.incident_title,
                "status": cand.status,
                "severity": cand.severity,
                "risk_score": cand.risk_score,
                "similarity_score": round(similarity, 3),
                "created_at": cand.created_at.isoformat(),
                "marker": "ESTIMATED PREDICTION"
            })

        # Sort descending by similarity
        scored.sort(key=lambda x: x["similarity_score"], reverse=True)
        return scored[:top_k]
