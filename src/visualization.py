"""
CertRAG evaluation visualizations — embedding manifold, pipeline funnel, telemetry.
"""

from __future__ import annotations

import os
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from matplotlib.patches import FancyBboxPatch

from src.embedding_engine import EmbeddingEngine, _CLEAN_ANCHOR, _EXPLOIT_ANCHOR

_CATEGORY_COLORS = {
    "clean": "#27ae60",
    "attack_encoded": "#e74c3c",
    "attack_hidden": "#c0392b",
    "attack_direct": "#922b21",
    "attack_unicode": "#e67e22",
    "attack_markdown": "#d35400",
    "attack_rot13": "#f39c12",
    "attack_roleplay": "#9b59b6",
    "attack_chunked_b64": "#8e44ad",
    "attack_homoglyph": "#2980b9",
    "attack_multilingual": "#1abc9c",
    "attack_sql": "#16a085",
    "attack_cognitive_math": "#7d3c98",
    "attack_semantic_low_entropy": "#eb984e",
    "attack_cross_doc": "#1f618d",
    "edge_benign_url": "#3498db",
    "edge_high_entropy": "#5dade2",
    "edge_signed_toxic": "#85c1e9",
    "noise": "#95a5a6",
}


def _color(cat: str) -> str:
    return _CATEGORY_COLORS.get(cat, "#7f8c8d")


def plot_embedding_manifold(
    corpus: list[dict[str, Any]],
    embedder: EmbeddingEngine,
    out_path: str,
) -> dict[str, Any]:
    """2D PCA projection of full corpus in mock BGE-M3 space."""
    sns.set_theme(style="whitegrid")
    texts = [d["content"] for d in corpus]
    vecs = embedder.embed_batch(texts)
    coords = embedder.project_pca2(vecs)
    anchor_2d = embedder.project_pca2(
        np.vstack([_CLEAN_ANCHOR, _EXPLOIT_ANCHOR])
    )

    fig, ax = plt.subplots(figsize=(12, 9))
    for doc, (x, y) in zip(corpus, coords):
        ax.scatter(x, y, c=_color(doc["category"]), s=120, edgecolors="black", linewidth=0.6, zorder=3)
        ax.annotate(doc["title"][:22], (x, y), fontsize=6, ha="center", va="bottom", alpha=0.85)

    ax.scatter(*anchor_2d[0], marker="*", s=400, c="gold", edgecolors="black", label="Clean Anchor", zorder=5)
    ax.scatter(*anchor_2d[1], marker="X", s=300, c="black", label="Exploit Zone", zorder=5)

    ax.set_xlabel("PCA-1 (1024D -> 2D)")
    ax.set_ylabel("PCA-2 (1024D -> 2D)")
    ax.set_title("BGE-M3 Mock Embedding Manifold — Topological Zones")
    handles = [plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=c, markersize=8, label=k)
               for k, c in _CATEGORY_COLORS.items()]
    ax.legend(handles=handles, loc="upper left", fontsize=6, ncol=2)
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)

    zones = [embedder.classify_zone(d["content"]) for d in corpus]
    dists = [EmbeddingEngine.cosine_distance(_CLEAN_ANCHOR, v) for v in vecs]
    return {"zones": zones, "cosine_to_clean_anchor": dists, "pca_coords": coords.tolist()}


def plot_zone_distance_bars(corpus: list[dict[str, Any]], dists: list[float], out_path: str) -> None:
    fig, ax = plt.subplots(figsize=(14, 6))
    cats = [d["category"] for d in corpus]
    titles = [d["title"][:18] for d in corpus]
    colors = [_color(c) for c in cats]
    bars = ax.barh(range(len(dists)), dists, color=colors, edgecolor="black", linewidth=0.4)
    ax.axvline(0.25, color="red", linestyle="--", linewidth=2, label="tau=0.25")
    ax.set_yticks(range(len(titles)))
    ax.set_yticklabels(titles, fontsize=7)
    ax.set_xlabel("Cosine Distance to Clean Anchor")
    ax.set_title("Per-Document Manifold Distance (Pre-Inference)")
    ax.legend()
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_pipeline_funnel(aggregate_drops: dict[str, int], total: int, out_path: str) -> None:
    stages = ["Ingest", "1.1 RSA", "1.2 URL", "1.3 Entropy", "1.4 Unicode", "1.5 Intent", "1.6 QPC", "1.7 Inversion", "L2 Consensus", "L3 Firewall"]
    remaining = total
    counts = [total]
    for layer in ["1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7"]:
        remaining -= aggregate_drops.get(layer, 0)
        counts.append(remaining)
    remaining -= aggregate_drops.get("2.3", 0)
    counts.append(remaining)  # L2
    counts.append(remaining)  # L3

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(stages, counts, color=plt.cm.Blues(np.linspace(0.4, 0.9, len(stages))))
    for i, v in enumerate(counts):
        ax.text(i, v + 0.2, str(v), ha="center", fontweight="bold")
    ax.set_ylabel("Documents Remaining")
    ax.set_title("CertRAG Document Survival Funnel (Aggregate)")
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_per_attack_asr(results: list[dict[str, Any]], out_path: str) -> None:
    sns.set_theme(style="whitegrid")
    cats = sorted({r["category"] for r in results})
    vanilla = [np.mean([r["attack_success"] for r in results if r["category"] == c and r["pipeline"] == "vanilla"]) * 100 for c in cats]
    certrag = [np.mean([r["attack_success"] for r in results if r["category"] == c and r["pipeline"] == "certrag"]) * 100 for c in cats]

    x = np.arange(len(cats))
    w = 0.35
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(x - w / 2, vanilla, w, label="Vanilla", color="#e74c3c")
    ax.bar(x + w / 2, certrag, w, label="CertRAG", color="#27ae60")
    ax.set_xticks(x)
    ax.set_xticklabels(cats, rotation=35, ha="right", fontsize=8)
    ax.set_ylabel("Attack Success Rate (%)")
    ax.set_title("ASR by Attack Category")
    ax.legend()
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_sublayer_latency_heatmap(rows: list[dict[str, Any]], out_path: str) -> None:
    keys = ["layer_1_1_ms", "layer_1_2_ms", "layer_1_3_ms", "layer_1_4_ms", "layer_1_5_ms", "layer_1_6_ms", "layer_1_7_ms",
            "layer_2_1_ms", "layer_2_2_ms", "layer_2_3_ms", "layer_3_1_ms", "layer_3_2_ms", "layer_3_3_ms"]
    labels = ["1.1 RSA", "1.2 URL", "1.3 Ent", "1.4 Uni", "1.5 Int", "1.6 QPC", "1.7 Invs",
              "2.1 Prov", "2.2 Claim", "2.3 Vote", "3.1 Anc", "3.2 Dist", "3.3 Rout"]
    qids = [r["query_id"] for r in rows]
    mat = np.array([[r.get(k, 0) for k in keys] for r in rows])

    fig, ax = plt.subplots(figsize=(14, max(4, len(qids) * 0.35)))
    sns.heatmap(mat, annot=True, fmt=".1f", cmap="YlOrRd", xticklabels=labels, yticklabels=qids, ax=ax)
    ax.set_title("Sublayer Latency Heatmap (ms)")
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_defense_effectiveness(drop_agg: dict[str, int], out_path: str) -> None:
    layers = list(drop_agg.keys())
    vals = [drop_agg[l] for l in layers]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(layers, vals, color="#9b59b6", edgecolor="black")
    for i, v in enumerate(vals):
        ax.text(i, v + 0.3, str(v), ha="center", fontweight="bold")
    ax.set_xlabel("Blocking Layer")
    ax.set_ylabel("Documents Dropped")
    ax.set_title("Defense Layer Effectiveness (Aggregate Drops)")
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_entropy_scatter(flows: list[dict[str, Any]], out_path: str) -> None:
    fig, ax = plt.subplots(figsize=(10, 7))
    for f in flows:
        c = "#27ae60" if f.get("survived") else "#e74c3c"
        ax.scatter(f["entropy"], f["b64_ratio"], c=c, s=80, edgecolors="black", linewidth=0.4)
        ax.annotate(f["category"][:12], (f["entropy"], f["b64_ratio"]), fontsize=6, alpha=0.7)
    ax.set_xlabel("Shannon Entropy")
    ax.set_ylabel("Base64 Payload Ratio")
    ax.set_title("Layer 1.3 Feature Space (green=survived, red=dropped)")
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_pipeline_architecture(out_path: str) -> None:
    """Static diagram of all 13 sublayers."""
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.set_xlim(0, 15)
    ax.set_ylim(0, 10)
    ax.axis("off")

    layers = [
        ("LAYER 1: Ingress & Perimeter", 7.5, [
            "1.1 RSA Check", "1.2 URL Masker", "1.3 Entropy Filter",
            "1.4 Unicode Norm", "1.5 Intent Scan", "1.6 QPC Check", "1.7 Inversion",
        ]),
        ("LAYER 2: Stylometric Consensus", 5.0, [
            "2.1 Provenance Wts", "2.2 Claim Extract", "2.3 Claim Voting",
        ]),
        ("LAYER 3: Output Firewall", 2.5, [
            "3.1 Anchor Gen", "3.2 Cosine Dist", "3.3 Manifold Route",
        ]),
    ]
    for title, y, subs in layers:
        ax.add_patch(FancyBboxPatch((0.5, y - 0.8), 14.0, 1.6, boxstyle="round,pad=0.05",
                                    facecolor="#ecf0f1", edgecolor="#2c3e50", linewidth=2))
        ax.text(0.8, y, title, fontsize=11, fontweight="bold", va="center")
        sx = 4.0
        spacing = 1.4 if len(subs) > 5 else 2.4
        width = 1.25 if len(subs) > 5 else 2.2
        for s in subs:
            ax.add_patch(FancyBboxPatch((sx, y - 0.35), width, 0.7, boxstyle="round,pad=0.02",
                                        facecolor="#3498db", edgecolor="black"))
            ax.text(sx + width / 2.0, y, s, fontsize=6.5, ha="center", va="center", color="white", fontweight="bold")
            sx += spacing

    ax.annotate("", xy=(7.5, 6.7), xytext=(7.5, 7.3), arrowprops=dict(arrowstyle="->", lw=2))
    ax.annotate("", xy=(7.5, 4.2), xytext=(7.5, 4.8), arrowprops=dict(arrowstyle="->", lw=2))
    ax.set_title("CertRAG 3-Layer / 13-Sublayer Architecture", fontsize=14, fontweight="bold")
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_asr_comparison(results: list[dict[str, Any]], out_path: str) -> None:
    fig, ax = plt.subplots(figsize=(8, 5))
    asrs = []
    for pipe in ("vanilla", "certrag"):
        subset = [r for r in results if r["pipeline"] == pipe and r.get("query_type") == "attack"]
        asrs.append(np.mean([r["attack_success"] for r in subset]) * 100 if subset else 0)
    bars = ax.bar(["Vanilla RAG", "CertRAG"], asrs, color=["#e74c3c", "#27ae60"], edgecolor="black")
    for bar, val in zip(bars, asrs):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, f"{val:.1f}%", ha="center", fontweight="bold")
    ax.set_ylabel("Attack Success Rate (%)")
    ax.set_title("Overall ASR — Attack Queries")
    ax.set_ylim(0, 110)
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_latency_stacked(avg: dict[str, float], out_path: str) -> None:
    fig, ax = plt.subplots(figsize=(10, 5))
    labels = ["L1.1", "L1.2", "L1.3", "L1.4", "L1.5", "L1.6", "L1.7", "L2.1", "L2.2", "L2.3", "L3.1", "L3.2", "L3.3"]
    keys = ["layer_1_1_ms", "layer_1_2_ms", "layer_1_3_ms", "layer_1_4_ms", "layer_1_5_ms", "layer_1_6_ms", "layer_1_7_ms",
            "layer_2_1_ms", "layer_2_2_ms", "layer_2_3_ms", "layer_3_1_ms", "layer_3_2_ms", "layer_3_3_ms"]
    vals = [avg.get(k, 0) for k in keys]
    colors = plt.cm.tab20(np.linspace(0, 1, len(labels)))
    bottom = 0.0
    for lab, val, col in zip(labels, vals, colors):
        ax.bar("CertRAG", val, bottom=bottom, label=lab, color=col, edgecolor="black", linewidth=0.3)
        bottom += val
    ax.set_ylabel("Latency (ms)")
    ax.set_title(f"Sublayer Latency Stack (Total avg: {bottom:.1f}ms)")
    ax.legend(fontsize=6, ncol=3, loc="upper right")
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_availability(clean_results: list[dict[str, Any]], out_path: str) -> None:
    """False quarantine rate on benign queries."""
    fig, ax = plt.subplots(figsize=(8, 5))
    qr = np.mean([r["quarantined"] for r in clean_results]) * 100
    bars = ax.bar(["False Quarantine Rate"], [qr], color="#f39c12", edgecolor="black")
    ax.text(0, qr + 1, f"{qr:.1f}%", ha="center", fontweight="bold")
    ax.set_ylabel("%")
    ax.set_title("Availability — Benign Query Quarantine Rate (lower is better)")
    ax.set_ylim(0, 110)
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_parameter_tradeoff_sweep(sweep_results: list[dict[str, Any]], out_path: str) -> None:
    """Plot the tradeoff between security (ASR) and availability (FQR/FPR) across parameter configurations."""
    sns.set_theme(style="whitegrid")
    fig, ax = plt.subplots(figsize=(10, 7))

    # Extract data points
    taus = [r["tau"] for r in sweep_results]
    epsilons = [r["eps"] for r in sweep_results]
    asrs = [r["asr"] * 100 for r in sweep_results]
    fqrs = [r["fqr"] * 100 for r in sweep_results]

    # Scatter plot with size representing eps and color representing tau
    sc = ax.scatter(
        fqrs, asrs, 
        c=taus, cmap="viridis", 
        s=[10 + (e * 150) for e in epsilons], 
        edgecolors="black", alpha=0.85, zorder=3
    )
    
    # Annotate key trade-off points
    for r in sweep_results:
        # Label optimal, strict, and loose extremes
        if (r["tau"] == 0.25 and r["eps"] == 0.40) or (r["tau"] == 0.05 and r["eps"] == 0.10) or (r["tau"] == 0.75 and r["eps"] == 0.70):
            ax.annotate(
                f"t={r['tau']:.2f}, e={r['eps']:.2f}",
                (r["fqr"] * 100, r["asr"] * 100),
                fontsize=7, fontweight="bold", xytext=(5, 5), textcoords="offset points"
            )

    cbar = fig.colorbar(sc, ax=ax)
    cbar.set_label("Threshold tau (Manifold Routing)", fontsize=9)
    
    ax.set_xlabel("False Quarantine Rate on Clean/Edge Queries (%)", fontsize=10)
    ax.set_ylabel("Attack Success Rate (ASR) (%)", fontsize=10)
    ax.set_title("Security Trade-off Manifold (ASR vs. False Quarantine)", fontsize=12, fontweight="bold")
    ax.set_xlim(-5, 105)
    ax.set_ylim(-5, 105)
    
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_baseline_comparison(
    vanilla_asr: float, vanilla_fpr: float,
    regex_asr: float, regex_fpr: float,
    certrag_asr: float, certrag_fpr: float,
    out_path: str
) -> None:
    """Plot comparative bar charts for all 3 pipeline baselines."""
    sns.set_theme(style="whitegrid")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    labels = ["Vanilla RAG", "Regex-Filter RAG", "CertRAG (Proposed)"]
    asr_vals = [vanilla_asr * 100, regex_asr * 100, certrag_asr * 100]
    fpr_vals = [vanilla_fpr * 100, regex_fpr * 100, certrag_fpr * 100]

    # Plot ASR (Security)
    bars1 = ax1.bar(labels, asr_vals, color=["#e74c3c", "#f39c12", "#27ae60"], edgecolor="black", width=0.5)
    for bar in bars1:
        h = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2, h + 1.5, f"{h:.1f}%", ha="center", fontweight="bold", fontsize=9)
    ax1.set_ylabel("Attack Success Rate (%)", fontsize=10)
    ax1.set_title("Security Efficacy (ASR) - Lower is Better", fontsize=11, fontweight="bold")
    ax1.set_ylim(0, 115)

    # Plot FPR (Availability)
    bars2 = ax2.bar(labels, fpr_vals, color=["#2ecc71", "#e67e22", "#e74c3c"], edgecolor="black", width=0.5)
    for bar in bars2:
        h = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2, h + 1.5, f"{h:.1f}%", ha="center", fontweight="bold", fontsize=9)
    ax2.set_ylabel("False Quarantine Rate (%)", fontsize=10)
    ax2.set_title("Availability Cost (FQR) - Lower is Better", fontsize=11, fontweight="bold")
    ax2.set_ylim(0, 115)

    fig.suptitle("Comparative Evaluation Across Architecture Baselines", fontsize=14, fontweight="bold")
    plt.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)

