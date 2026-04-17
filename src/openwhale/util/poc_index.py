"""轻量 POC 知识库索引 — 扫描项目 kb/ 目录下的 Markdown 文件构建倒排索引，支持关键词 / CVE / 产品检索。

路径存储约定:
  索引中存储 **相对于项目根目录的路径** (如 "kb/awesome-poc/XXX.md")，
  读取时动态拼接 _PROJECT_ROOT，确保在任何机器上都能正确定位文件。
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from loguru import logger

_HEAD_BYTES = 4096
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CNVD_RE = re.compile(r"CNVD-\d{4}-\d+", re.IGNORECASE)
_QVD_RE = re.compile(r"QVD-\d{4}-\d+", re.IGNORECASE)

_PROJECT_ROOT = Path(__file__).resolve().parents[3]

_KB_DIR_IN_PROJECT = _PROJECT_ROOT / "kb"
_DEFAULT_KB_DIRS: list[str] = [
    str(_KB_DIR_IN_PROJECT / "awesome-poc"),
    str(_KB_DIR_IN_PROJECT / "poc-main"),
    str(_KB_DIR_IN_PROJECT / "hacktricks"),
    str(_KB_DIR_IN_PROJECT / "pentest-note"),
    str(_KB_DIR_IN_PROJECT / "java-security"),
    str(_KB_DIR_IN_PROJECT / "ctf-writeup"),
    str(_KB_DIR_IN_PROJECT / "pentest-writeup"),
    str(_KB_DIR_IN_PROJECT / "personal-notes"),
]

# 停用词（不加入索引的低价值词）
_STOPWORDS = frozenset({
    "the", "and", "for", "this", "that", "with", "from", "are", "was",
    "http", "https", "com", "www", "org", "net", "html", "php", "asp",
    "md", "png", "jpg", "gif", "img", "images", "image",
    "漏洞", "复现", "利用", "分析", "详情", "描述", "简介", "参考",
})


def _tokenize(text: str) -> set[str]:
    """将文本拆分为小写 token 集合，包含中文词和英文词。"""
    tokens: set[str] = set()
    for word in re.findall(r"[a-zA-Z0-9_\-]{2,}", text.lower()):
        if word not in _STOPWORDS and len(word) <= 60:
            tokens.add(word)
    for cword in re.findall(r"[\u4e00-\u9fff]{2,6}", text):
        if cword not in _STOPWORDS:
            tokens.add(cword)
    for cve in _CVE_RE.findall(text):
        tokens.add(cve.lower())
    for cnvd in _CNVD_RE.findall(text):
        tokens.add(cnvd.lower())
    for qvd in _QVD_RE.findall(text):
        tokens.add(qvd.lower())
    return tokens


def _extract_summary(filepath: Path) -> str:
    """读取文件头部，提取纯文本摘要（去掉 Markdown 语法噪音）。"""
    try:
        raw = filepath.read_bytes()[:_HEAD_BYTES]
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return ""
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("![", "<!--", "<img", "```")):
            continue
        clean = re.sub(r"[#*>`\[\]!]", "", stripped).strip()
        if clean:
            lines.append(clean)
        if len(lines) >= 8:
            break
    return "\n".join(lines)


class PocIndex:
    """POC 知识库倒排索引，支持构建、持久化、检索。"""

    def __init__(self, cache_path: str | Path | None = None) -> None:
        self._cache_path = Path(cache_path) if cache_path else None
        # token → set of doc_ids
        self._inverted: dict[str, set[int]] = defaultdict(set)
        # doc_id → metadata
        self._docs: dict[int, dict[str, Any]] = {}
        self._next_id = 0
        self._built = False

    # ── 索引构建 ─────────────────────────────────────────────────

    def build(self, kb_dirs: list[str] | None = None, force: bool = False) -> str:
        """扫描知识库目录构建索引。返回构建摘要。"""
        if self._built and not force:
            return f"索引已就绪: {len(self._docs)} 篇文档, {len(self._inverted)} 个索引词"

        if not force and self._cache_path and self._cache_path.exists():
            try:
                self._load_cache()
                self._built = True
                return f"从缓存加载索引: {len(self._docs)} 篇文档, {len(self._inverted)} 个索引词"
            except Exception as exc:
                logger.warning(f"缓存加载失败，将重新构建: {exc}")

        dirs = kb_dirs or _DEFAULT_KB_DIRS
        t0 = time.time()
        scanned = skipped = 0

        for kb_dir in dirs:
            dp = Path(kb_dir)
            if not dp.exists():
                logger.info(f"知识库目录不存在，跳过: {kb_dir}")
                continue
            for root, dirnames, filenames in os.walk(dp):
                dirnames[:] = [
                    d for d in dirnames
                    if d not in {"node_modules", ".git", ".svn", ".obsidian", "__pycache__", "images", "img"}
                ]
                for fname in filenames:
                    if not fname.endswith(".md"):
                        skipped += 1
                        continue
                    fpath = Path(root) / fname
                    self._index_file(fpath)
                    scanned += 1

        elapsed = time.time() - t0
        self._built = True

        if self._cache_path:
            try:
                self._save_cache()
            except Exception as exc:
                logger.warning(f"缓存保存失败: {exc}")

        summary = (
            f"索引构建完成: {scanned} 篇MD文档已索引, {skipped} 个非MD文件跳过, "
            f"{len(self._inverted)} 个索引词, 耗时 {elapsed:.1f}s"
        )
        logger.info(summary)
        return summary

    def _index_file(self, fpath: Path) -> None:
        doc_id = self._next_id
        self._next_id += 1

        fname_stem = fpath.stem
        summary = _extract_summary(fpath)
        tokens_from_name = _tokenize(fname_stem)
        tokens_from_body = _tokenize(summary)
        all_tokens = tokens_from_name | tokens_from_body

        try:
            rel_path = str(fpath.resolve().relative_to(_PROJECT_ROOT.resolve()))
        except ValueError:
            rel_path = str(fpath)
        category = self._infer_category(fpath)

        self._docs[doc_id] = {
            "path": rel_path,
            "name": fname_stem,
            "category": category,
            "summary": summary[:500],
        }

        for token in tokens_from_name:
            self._inverted[token].add(doc_id)
        for token in all_tokens:
            self._inverted[token].add(doc_id)

    @staticmethod
    def _infer_category(fpath: Path) -> str:
        """从路径推断分类标签。"""
        parts = str(fpath).lower()
        if "awesome-poc" in parts:
            return "awesome-poc"
        if "poc-main" in parts or "wpoc" in parts:
            return "poc-main"
        if "hacktricks" in parts:
            return "hacktricks"
        if "pentest_note" in parts:
            return "pentest-note"
        if "java安全" in parts or "java" in parts.split("/")[-1]:
            return "java-security"
        if "ctf" in parts:
            return "ctf-writeup"
        if "攻防渗透" in parts or "htb" in parts:
            return "pentest-writeup"
        if "笔记" in parts:
            return "personal-notes"
        return "other"

    # ── 缓存持久化 ───────────────────────────────────────────────

    def _save_cache(self) -> None:
        if not self._cache_path:
            return
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "docs": {str(k): v for k, v in self._docs.items()},
            "inverted": {k: list(v) for k, v in self._inverted.items()},
            "next_id": self._next_id,
        }
        self._cache_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def _load_cache(self) -> None:
        if not self._cache_path or not self._cache_path.exists():
            raise FileNotFoundError("No cache")
        data = json.loads(self._cache_path.read_text(encoding="utf-8"))
        self._docs = {int(k): v for k, v in data["docs"].items()}
        self._inverted = defaultdict(set)
        for k, ids in data["inverted"].items():
            self._inverted[k] = set(ids)
        self._next_id = data.get("next_id", len(self._docs))

        # 校验：如果缓存中的路径是绝对路径（旧缓存），说明是过期的，强制重建
        if self._docs:
            sample_path = next(iter(self._docs.values()))["path"]
            if sample_path.startswith("/") and not sample_path.startswith(str(_PROJECT_ROOT)):
                logger.warning("缓存中包含无效的绝对路径，强制重建索引")
                self._docs.clear()
                self._inverted.clear()
                self._next_id = 0
                raise ValueError("Stale cache with absolute paths from another machine")

    # ── 检索 ─────────────────────────────────────────────────────

    def search(self, query: str, max_results: int = 8) -> str:
        """根据关键词检索 POC 文档，返回匹配结果摘要。"""
        if not self._built:
            build_msg = self.build()
            if not self._built:
                return f"索引未就绪: {build_msg}"

        query_tokens = _tokenize(query)
        if not query_tokens:
            return f"无法解析查询 '{query}'，请使用具体关键词如 CVE编号、产品名、漏洞类型等。"

        scores: dict[int, float] = defaultdict(float)
        for token in query_tokens:
            matched_ids = self._inverted.get(token, set())
            if not matched_ids:
                for idx_token in self._inverted:
                    if token in idx_token or idx_token in token:
                        matched_ids = matched_ids | self._inverted[idx_token]
            idf = 1.0 / (1.0 + len(matched_ids)) if matched_ids else 0
            boost = 3.0 if _CVE_RE.match(token) or _CNVD_RE.match(token) else 1.0
            for doc_id in matched_ids:
                scores[doc_id] += (1.0 + idf) * boost

        if not scores:
            return f"未找到与 '{query}' 相关的 POC 文档。建议尝试: CVE编号、英文产品名、中文厂商名等。"

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:max_results]

        parts: list[str] = [f"=== POC知识库检索: '{query}' (前{len(ranked)}条) ===\n"]
        for doc_id, score in ranked:
            doc = self._docs[doc_id]
            abs_path = self._resolve_path(doc["path"])
            parts.append(f"📄 [{doc['category']}] {doc['name']}")
            parts.append(f"   路径: {abs_path}")
            if doc["summary"]:
                summary_lines = doc["summary"].split("\n")[:4]
                parts.append(f"   摘要: {' | '.join(summary_lines)}")
            parts.append("")

        parts.append("提示: 使用 read_poc_file 工具可读取具体 POC 文件的完整内容。")
        return "\n".join(parts)

    @staticmethod
    def _resolve_path(stored_path: str) -> str:
        """将存储的路径解析为绝对路径。

        支持相对路径(如 "kb/awesome-poc/XXX.md") 和绝对路径(向后兼容)。
        """
        p = Path(stored_path)
        if p.is_absolute():
            return stored_path
        resolved = _PROJECT_ROOT / stored_path
        return str(resolved)

    def read_file(self, filepath: str, max_chars: int = 6000) -> str:
        """读取指定 POC 文件的内容（截断到 max_chars）。"""
        fp = Path(self._resolve_path(filepath))
        if not fp.exists():
            return f"文件不存在: {filepath} (解析为: {fp})"
        if fp.suffix.lower() not in (".md", ".txt", ".py", ".yaml", ".yml", ".json"):
            return f"不支持的文件类型: {fp.suffix}"
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return f"读取失败: {exc}"
        if len(content) > max_chars:
            content = content[:max_chars] + f"\n\n... [截断，共 {len(content)} 字符] ..."
        return f"=== {fp.name} ===\n{content}"

    def get_stats(self) -> str:
        """返回索引统计信息。"""
        if not self._built:
            return "索引未构建。调用 search 或 build 会自动触发构建。"
        cat_counts: dict[str, int] = defaultdict(int)
        for doc in self._docs.values():
            cat_counts[doc["category"]] += 1
        lines = [f"=== POC 知识库统计 ===", f"总文档数: {len(self._docs)}", f"索引词数: {len(self._inverted)}", ""]
        lines.append("按来源分布:")
        for cat, cnt in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {cat}: {cnt} 篇")
        return "\n".join(lines)
