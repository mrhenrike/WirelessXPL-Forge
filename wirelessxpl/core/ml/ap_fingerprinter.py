# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Fingerprinting de APs 802.11 com TF-IDF e similaridade de cosseno acelerada."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import numpy as np

from wirelessxpl.core.gpu.backend import ComputeBackend, auto_select_backend

logger = logging.getLogger(__name__)

_SKLEARN: Any = None
try:
    from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
    from sklearn.metrics.pairwise import cosine_similarity  # type: ignore

    _SKLEARN = True
except ImportError:
    TfidfVectorizer = None  # type: ignore
    cosine_similarity = None  # type: ignore


def _sklearn_available() -> bool:
    return bool(_SKLEARN)


DEFAULT_AP_CORPUS: List[Dict[str, str]] = [
    {
        "vendor": "Ubiquiti",
        "model": "UniFi AP",
        "firmware_guess": "UniFi Controller managed",
        "profile": (
            "beacon_interval=100 ht_cap vht_cap vendor_oui_ubiquiti "
            "wps_disabled enterprise rsn_enterprise"
        ),
    },
    {
        "vendor": "TP-Link",
        "model": "Archer",
        "firmware_guess": "ArcherOS",
        "profile": (
            "beacon_interval=100 ht_cap wps_enabled vendor_oui_tplink "
            "country_code_default broadcom_ie"
        ),
    },
    {
        "vendor": "ASUSTek",
        "model": "RT-AX",
        "firmware_guess": "AsusWRT",
        "profile": (
            "beacon_interval=100 he_cap mu_mimo asus_oui wps_optional "
            "rsn_psk"
        ),
    },
    {
        "vendor": "Huawei",
        "model": "ONT/WiFi",
        "firmware_guess": "VRP-like",
        "profile": (
            "beacon_interval=100 ht_cap vendor_oui_huawei wps_enabled "
            "country_cn"
        ),
    },
    {
        "vendor": "Arcadyan",
        "model": "ISP CPE",
        "firmware_guess": "Arcadyan",
        "profile": (
            "beacon_interval=100 ht_cap vht wps_enabled isp_cpe "
            "vendor_oui_arcadyan"
        ),
    },
]


def _features_to_text(beacon_features: Mapping[str, Any]) -> str:
    """Converte dict de features de beacon/probe response em texto para TF-IDF."""
    parts: List[str] = []
    for key in (
        "beacon_interval",
        "supported_rates",
        "ht_capabilities",
        "vht_capabilities",
        "he_capabilities",
        "rsn_info",
        "vendor_oui",
        "country_code",
        "wps_flags",
        "channel_width",
        "dtim_period",
        "ie_hash",
    ):
        val = beacon_features.get(key)
        if val is None:
            continue
        if isinstance(val, (list, tuple, set)):
            parts.append("{}={}".format(key, " ".join(str(x) for x in val)))
        else:
            parts.append("{}={}".format(key, val))
    extra = beacon_features.get("raw_tags")
    if isinstance(extra, str) and extra.strip():
        parts.append(extra.strip())
    return " ".join(parts).lower()


def _token_similarity_fallback(query: str, corpus: Sequence[str]) -> np.ndarray:
    """Cosine TF manual simplificado (bag-of-chars) se sklearn ausente."""
    def vec(s: str) -> np.ndarray:
        counts: Dict[str, int] = {}
        for ch in re.findall(r"\w+", s):
            counts[ch] = counts.get(ch, 0) + 1
        return np.asarray(list(counts.values()), dtype=np.float32) if counts else np.zeros(1)

    qv = vec(query)
    rows = []
    for c in corpus:
        cv = vec(c)
        # alinha por união simples — fallback grosseiro
        m = max(len(qv), len(cv), 1)
        qv2 = np.pad(qv, (0, m - len(qv)))
        cv2 = np.pad(cv, (0, m - len(cv)))
        denom = (np.linalg.norm(qv2) * np.linalg.norm(cv2)) + 1e-9
        rows.append(float(np.dot(qv2, cv2) / denom))
    return np.asarray([rows], dtype=np.float32)


@dataclass
class APFingerprint:
    """Melhor correspondência de fabricante/modelo para um conjunto de IEs."""

    vendor: str
    model: str
    firmware_guess: str
    confidence: float
    matched_profile: str = ""
    scores: Dict[str, float] = field(default_factory=dict)


class APFingerprinter:
    """Identificação de AP por features de beacon + TF-IDF / cosseno.

    Quando há ``sklearn``, usa ``TfidfVectorizer`` e ``cosine_similarity`` ou
    ``ComputeBackend.cosine_similarity_batch`` para lotes. Sem sklearn, usa
    similaridade lexical grosseira.
    """

    def __init__(
        self,
        known_aps: Optional[Sequence[Mapping[str, str]]] = None,
        compute_backend: Optional[ComputeBackend] = None,
    ) -> None:
        self._corpus_rows: List[Dict[str, str]] = list(known_aps or DEFAULT_AP_CORPUS)
        self._vectorizer: Any = None
        self._corpus_matrix: Optional[Any] = None
        self._corpus_texts: List[str] = [r["profile"] for r in self._corpus_rows]
        self._backend: ComputeBackend = compute_backend or auto_select_backend()
        self._fit_vectorizer()

    def _fit_vectorizer(self) -> None:
        if not _sklearn_available():
            self._vectorizer = None
            self._corpus_matrix = None
            return
        self._vectorizer = TfidfVectorizer(analyzer="word", token_pattern=r"\w+")
        self._corpus_matrix = self._vectorizer.fit_transform(self._corpus_texts)

    def add_known_ap(self, vendor: str, model: str, firmware_guess: str, profile: str) -> None:
        """Adiciona um perfil conhecido e refaz o vocabulário TF-IDF."""
        self._corpus_rows.append(
            {
                "vendor": vendor,
                "model": model,
                "firmware_guess": firmware_guess,
                "profile": profile,
            }
        )
        self._corpus_texts = [r["profile"] for r in self._corpus_rows]
        self._fit_vectorizer()

    def _similarity_row(self, query_text: str) -> np.ndarray:
        if not _sklearn_available() or self._vectorizer is None or self._corpus_matrix is None:
            return _token_similarity_fallback(query_text, self._corpus_texts)

        q = self._vectorizer.transform([query_text])
        # matriz densa pequena para backend GPU
        qd = q.toarray().astype(np.float32)
        cd = self._corpus_matrix.toarray().astype(np.float32)
        try:
            sim = self._backend.cosine_similarity_batch(qd, cd)
            return np.asarray(sim, dtype=np.float32)
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("ComputeBackend cosine falhou, sklearn CPU: %s", exc)
            return cosine_similarity(q, self._corpus_matrix).astype(np.float32)

    def fingerprint(self, beacon_features: Dict[str, Any]) -> APFingerprint:
        """Retorna o fabricante/modelo mais provável dado um dict de features.

        Args:
            beacon_features: IEs agregadas (intervalo, HT/VHT/HE, RSN, OUI, etc.).

        Returns:
            ``APFingerprint`` com confiança em [0,1].
        """
        text = _features_to_text(beacon_features)
        sim_row = self._similarity_row(text).ravel()
        if sim_row.size == 0:
            return APFingerprint("unknown", "unknown", "unknown", 0.0, "", {})
        idx = int(np.argmax(sim_row))
        best = self._corpus_rows[idx]
        conf = float(max(0.0, min(1.0, sim_row[idx])))
        scores = {
            self._corpus_rows[i]["vendor"]: float(sim_row[i]) for i in range(len(sim_row))
        }
        return APFingerprint(
            vendor=str(best["vendor"]),
            model=str(best["model"]),
            firmware_guess=str(best["firmware_guess"]),
            confidence=conf,
            matched_profile=str(best["profile"]),
            scores=scores,
        )

    def fingerprint_batch(
        self,
        beacon_feature_list: Sequence[Dict[str, Any]],
    ) -> List[APFingerprint]:
        """Processa vários beacons; usa backend para matmul em lote quando útil."""
        if not beacon_feature_list:
            return []
        texts = [_features_to_text(b) for b in beacon_feature_list]
        if not _sklearn_available() or self._vectorizer is None or self._corpus_matrix is None:
            return [self.fingerprint(b) for b in beacon_feature_list]

        qm = self._vectorizer.transform(texts).toarray().astype(np.float32)
        cd = self._corpus_matrix.toarray().astype(np.float32)
        try:
            sims = self._backend.cosine_similarity_batch(qm, cd)
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("Batch cosine via backend falhou: %s", exc)
            sims = cosine_similarity(qm, cd)

        out: List[APFingerprint] = []
        for row in np.asarray(sims, dtype=np.float32):
            idx = int(np.argmax(row))
            best = self._corpus_rows[idx]
            conf = float(max(0.0, min(1.0, row[idx])))
            scores = {self._corpus_rows[i]["vendor"]: float(row[i]) for i in range(len(row))}
            out.append(
                APFingerprint(
                    vendor=str(best["vendor"]),
                    model=str(best["model"]),
                    firmware_guess=str(best["firmware_guess"]),
                    confidence=conf,
                    matched_profile=str(best["profile"]),
                    scores=scores,
                )
            )
        return out

    def train_from_captures(self, pcap_dir: str) -> Dict[str, Any]:
        """Extrai texto aproximado de beacons em PCAPs para enriquecer o corpus.

        Requer ``scapy`` instalado. Não rotula automaticamente vendor/modelo;
        apenas adiciona perfis textuais genéricos derivados dos frames.

        Args:
            pcap_dir: Diretório contendo ficheiros ``.pcap`` / ``.pcapng``.

        Returns:
            Estatísticas simples (contagens) para telemetria.
        """
        root = Path(pcap_dir)
        if not root.is_dir():
            logger.warning("train_from_captures: diretório inválido %s", pcap_dir)
            return {"pcap_files": 0, "beacons_indexed": 0, "error": "not_a_dir"}

        try:
            from scapy.compat import raw  # type: ignore
            from scapy.layers.dot11 import Dot11  # type: ignore
            from scapy.layers.dot11 import Dot11Beacon  # type: ignore
            from scapy.utils import PcapReader  # type: ignore
        except ImportError:
            logger.info("scapy indisponível; train_from_captures não executado.")
            return {"pcap_files": 0, "beacons_indexed": 0, "error": "no_scapy"}

        pcap_files = list(root.glob("*.pcap")) + list(root.glob("*.pcapng"))
        indexed = 0
        for pcap_path in pcap_files:
            try:
                reader = PcapReader(str(pcap_path))
                for pkt in reader:
                    if not pkt.haslayer(Dot11Beacon):
                        continue
                    dot11 = pkt.getlayer(Dot11)
                    if dot11 is None:
                        continue
                    blob = raw(pkt[Dot11Beacon])
                    profile = "beacon_raw={} bssid={}".format(
                        blob[:320].hex(),
                        getattr(dot11, "addr3", "") or "",
                    )
                    self.add_known_ap(
                        vendor="learned",
                        model=pcap_path.stem,
                        firmware_guess="unknown",
                        profile=profile.lower(),
                    )
                    indexed += 1
                    if indexed > 2000:
                        break
            except Exception as exc:  # pylint: disable=broad-except
                logger.debug("Falha ao ler %s: %s", pcap_path, exc)
        return {"pcap_files": len(pcap_files), "beacons_indexed": indexed}

    def save_corpus_json(self, path: Path) -> None:
        """Exporta corpus conhecido para JSON (vendor/model/profile)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(self._corpus_rows, fh, indent=2, ensure_ascii=False)

    def load_corpus_json(self, path: Path) -> None:
        """Carrega corpus e refaz TF-IDF."""
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        self._corpus_rows = [dict(x) for x in data]
        self._corpus_texts = [r["profile"] for r in self._corpus_rows]
        self._fit_vectorizer()
