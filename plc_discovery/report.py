"""
PLC Discovery - レポート生成モジュール

HTML/PDFレポートを生成するための機能を提供します。
"""

import functools
import html
import json
import math
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .config import DataPoint, PLCInfo, StatusCode
from .utils import sorted_addresses


def json_safe(value):
    """Recursively replace non-finite floats (NaN, Infinity) with None"""
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    return value


@functools.lru_cache(maxsize=None)
def _template(name: str) -> str:
    """A file of plc_discovery/templates (report stylesheets)"""
    return resources.files("plc_discovery").joinpath("templates").joinpath(name).read_text(encoding="utf-8")


class ReportFormat(Enum):
    """レポート出力形式"""

    HTML = "html"
    PDF = "pdf"
    JSON = "json"


@dataclass
class ReportConfig:
    """レポート設定"""

    format: ReportFormat = ReportFormat.HTML
    output_path: Optional[str] = None
    title: str = "PLC Discovery レポート"
    company_name: str = ""
    logo_path: Optional[str] = None
    include_raw_data: bool = True
    include_charts: bool = True
    include_denied_addresses: bool = True
    language: str = "ja"
    theme: str = "default"  # default, dark, light


@dataclass
class ScanSummary:
    """スキャン結果サマリー"""

    scan_mode: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    total_plcs: int = 0
    successful_reads: int = 0
    failed_reads: int = 0
    denied_addresses: int = 0
    duration_seconds: float = 0.0

    @property
    def success_rate(self) -> float:
        """成功率を計算"""
        total = self.successful_reads + self.failed_reads
        if total == 0:
            return 0.0
        return (self.successful_reads / total) * 100


@dataclass
class ReportData:
    """レポートデータ"""

    summary: ScanSummary
    plcs: List[PLCInfo] = field(default_factory=list)
    data_points: Dict[str, List[DataPoint]] = field(default_factory=dict)
    denied_addresses: Dict[str, List[str]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ReportGenerator:
    """レポート生成クラス"""

    def __init__(self, config: Optional[ReportConfig] = None):
        """
        レポートジェネレータを初期化

        Args:
            config: レポート設定
        """
        self.config = config or ReportConfig()

    def generate(self, data: ReportData) -> Union[str, bytes]:
        """
        レポートを生成

        Args:
            data: レポートデータ

        Returns:
            生成されたレポートの内容（HTML/JSONはstr、PDFはbytes）
        """
        if self.config.format == ReportFormat.HTML:
            return self._generate_html(data)
        elif self.config.format == ReportFormat.PDF:
            return self._generate_pdf(data)
        elif self.config.format == ReportFormat.JSON:
            return self._generate_json(data)
        else:
            raise ValueError(f"Unsupported format: {self.config.format}")

    def save(self, data: ReportData, output_path: Optional[str] = None) -> str:
        """
        レポートをファイルに保存

        Args:
            data: レポートデータ
            output_path: 出力パス。指定時はそのまま使う。省略時は
                config.output_path 内に plc_report_<日時>.<拡張子> を作る

        Returns:
            保存されたファイルパス
        """
        content = self.generate(data)

        if output_path is None:
            # Auto-generated name goes into the configured output directory;
            # an explicit path is used exactly as given
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ext = self.config.format.value
            output_path = f"plc_report_{timestamp}.{ext}"
            if self.config.output_path:
                output_path = os.path.join(self.config.output_path, output_path)

        # ディレクトリ作成
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        # ファイル保存
        mode = "w" if self.config.format != ReportFormat.PDF else "wb"
        encoding = "utf-8" if self.config.format != ReportFormat.PDF else None

        with open(output_path, mode, encoding=encoding) as f:
            if self.config.format == ReportFormat.PDF:
                f.write(content.encode("utf-8") if isinstance(content, str) else content)
            else:
                f.write(content)

        return output_path

    def _generate_html(self, data: ReportData) -> str:
        """HTML形式のレポートを生成"""
        theme_css = self._get_theme_css()

        html_content = f"""<!DOCTYPE html>
<html lang="{html.escape(self.config.language)}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(self.config.title)}</title>
    <style>
{theme_css}
    </style>
</head>
<body>
    <div class="container">
        {self._generate_header(data)}
        {self._generate_summary_section(data)}
        {self._generate_plc_section(data)}
        {self._generate_data_section(data) if self.config.include_raw_data else ""}
        {self._generate_denied_section(data) if self.config.include_denied_addresses else ""}
        {self._generate_errors_section(data)}
        {self._generate_footer()}
    </div>
</body>
</html>"""
        return html_content

    def _generate_pdf(self, data: ReportData) -> bytes:
        """PDF形式のレポートを生成"""
        # まずHTMLを生成
        html_content = self._generate_html(data)

        try:
            # weasyprint を試す
            from weasyprint import HTML

            pdf_bytes = HTML(string=html_content).write_pdf()
            return bytes(pdf_bytes)
        except ImportError:
            try:
                # pdfkit を試す
                import pdfkit

                pdf_bytes = pdfkit.from_string(html_content, False)
                return bytes(pdf_bytes)
            except ImportError:
                # PDFライブラリがない場合はHTMLを返す
                raise ImportError(
                    "PDF generation requires 'weasyprint' or 'pdfkit'. "
                    "Install with: pip install weasyprint or pip install pdfkit"
                )

    def _generate_json(self, data: ReportData) -> str:
        """JSON形式のレポートを生成"""
        report_dict = {
            "title": self.config.title,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "scan_mode": data.summary.scan_mode,
                "started_at": data.summary.started_at.isoformat(),
                "completed_at": data.summary.completed_at.isoformat() if data.summary.completed_at else None,
                "total_plcs": data.summary.total_plcs,
                "successful_reads": data.summary.successful_reads,
                "failed_reads": data.summary.failed_reads,
                "denied_addresses": data.summary.denied_addresses,
                "duration_seconds": data.summary.duration_seconds,
                "success_rate": data.summary.success_rate,
            },
            "plcs": [
                {
                    "ip_address": plc.ip_address,
                    "manufacturer": plc.manufacturer,
                    "model": plc.model,
                    "protocol": plc.protocol.name if plc.protocol else None,
                    "port": plc.port,
                }
                for plc in data.plcs
            ],
            "data_points": {
                ip: [
                    {
                        "address": dp.address,
                        "value": dp.value,
                        "raw_hex": dp.raw_hex,
                        "status": dp.status.value if dp.status else None,
                        "data_type": getattr(dp, "data_type", None),
                        "converted_value": getattr(dp, "converted_value", None),
                    }
                    for dp in points
                ]
                for ip, points in data.data_points.items()
            },
            "denied_addresses": data.denied_addresses,
            "errors": data.errors,
            "metadata": data.metadata,
        }
        # NaN / Infinity (e.g. a FLOAT decoded from 0xFFFF 0xFFFF) are not valid
        # JSON; write them as null so strict parsers (JSON.parse, jq) accept the file
        return json.dumps(json_safe(report_dict), indent=2, ensure_ascii=False, allow_nan=False, default=str)

    def _get_theme_css(self) -> str:
        """テーマCSSを取得"""
        if self.config.theme == "dark":
            return self._get_dark_theme_css()
        elif self.config.theme == "light":
            return self._get_light_theme_css()
        else:
            return self._get_default_theme_css()

    def _get_default_theme_css(self) -> str:
        """デフォルトテーマCSS"""
        return _template("report_default.css")

    def _get_dark_theme_css(self) -> str:
        """ダークテーマCSS（デフォルトの上に色を上書き）"""
        return self._get_default_theme_css() + _template("report_dark.css")

    def _get_light_theme_css(self) -> str:
        """ライトテーマCSS"""
        return self._get_default_theme_css()

    def _generate_header(self, data: ReportData) -> str:
        """ヘッダーセクションを生成"""
        logo_html = ""
        if self.config.logo_path and os.path.exists(self.config.logo_path):
            logo_html = (
                f'<img src="{html.escape(self.config.logo_path, quote=True)}" alt="Logo" '
                'style="max-height: 60px; margin-bottom: 1rem;">'
            )

        company_html = ""
        if self.config.company_name:
            company_html = f'<div class="company">{html.escape(self.config.company_name)}</div>'

        return f"""
        <header>
            {logo_html}
            {company_html}
            <h1>{html.escape(self.config.title)}</h1>
            <div class="meta">
                生成日時: {datetime.now().strftime("%Y年%m月%d日 %H:%M:%S")}
            </div>
        </header>
        """

    def _generate_summary_section(self, data: ReportData) -> str:
        """サマリーセクションを生成"""
        summary = data.summary
        duration = f"{summary.duration_seconds:.1f}秒" if summary.duration_seconds else "計測中"

        return f"""
        <section class="section">
            <h2>📊 スキャン概要</h2>
            <div class="summary-grid">
                <div class="stat-card">
                    <div class="value">{html.escape(summary.scan_mode)}</div>
                    <div class="label">スキャンモード</div>
                </div>
                <div class="stat-card">
                    <div class="value">{summary.total_plcs}</div>
                    <div class="label">検出PLC数</div>
                </div>
                <div class="stat-card success">
                    <div class="value">{summary.successful_reads:,}</div>
                    <div class="label">成功読み取り</div>
                </div>
                <div class="stat-card danger">
                    <div class="value">{summary.failed_reads:,}</div>
                    <div class="label">失敗</div>
                </div>
                <div class="stat-card warning">
                    <div class="value">{summary.denied_addresses:,}</div>
                    <div class="label">アクセス拒否</div>
                </div>
                <div class="stat-card">
                    <div class="value">{summary.success_rate:.1f}%</div>
                    <div class="label">成功率</div>
                </div>
            </div>
            <div style="margin-top: 1rem; color: var(--text-secondary); font-size: 0.875rem;">
                開始: {summary.started_at.strftime("%Y-%m-%d %H:%M:%S")} |
                完了: {summary.completed_at.strftime("%Y-%m-%d %H:%M:%S") if summary.completed_at else "進行中"} |
                所要時間: {duration}
            </div>
            {self._generate_charts_html(data) if self.config.include_charts else ""}
        </section>
        """

    def _generate_charts_html(self, data: ReportData) -> str:
        """
        チャートHTMLを生成（インラインSVG）

        The report contains the plant's PLC inventory, so it loads no
        external scripts (previously Chart.js from a CDN, unpinned): the
        charts are plain SVG, work offline and in PDF output.
        """
        summary = data.summary
        status = [
            ("成功", summary.successful_reads, "#22c55e"),
            ("失敗", summary.failed_reads, "#ef4444"),
            ("アクセス拒否", summary.denied_addresses, "#f59e0b"),
        ]
        per_plc = [(label, len(points)) for label, points in data.data_points.items()]
        return f"""
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem;">
            <div class="chart-container" id="statusChart">
                <h3 style="font-size: 0.95rem;">ステータス分布</h3>
                {_svg_bar_chart(status)}
            </div>
            <div class="chart-container" id="plcChart">
                <h3 style="font-size: 0.95rem;">PLC別データポイント数</h3>
                {_svg_bar_chart([(label, count, "#2563eb") for label, count in per_plc[:20]])}
            </div>
        </div>
        """

    def _generate_plc_section(self, data: ReportData) -> str:
        """PLC一覧セクションを生成"""
        if not data.plcs:
            return ""

        rows = ""
        for i, plc in enumerate(data.plcs, 1):
            protocol = plc.protocol.name if plc.protocol else "不明"
            rows += f"""
            <tr>
                <td>{i}</td>
                <td>{html.escape(plc.ip_address)}</td>
                <td>{html.escape(plc.manufacturer or '不明')}</td>
                <td>{html.escape(plc.model or '不明')}</td>
                <td><span class="badge badge-info">{html.escape(protocol)}</span></td>
                <td>{plc.port or '-'}</td>
            </tr>
            """

        return f"""
        <section class="section">
            <h2>🔌 検出されたPLC</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IPアドレス</th>
                        <th>メーカー</th>
                        <th>機種</th>
                        <th>プロトコル</th>
                        <th>ポート</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </section>
        """

    def _generate_data_section(self, data: ReportData) -> str:
        """データセクションを生成"""
        if not data.data_points:
            return ""

        sections = ""
        for ip, points in data.data_points.items():
            rows = ""
            for point in points[:100]:  # 最大100件表示
                status_class = "success" if point.status == StatusCode.OK else "danger"
                status_text = (
                    "OK" if point.status == StatusCode.OK else str(point.status.value) if point.status else "不明"
                )

                converted = getattr(point, "converted_value", None)
                converted_html = f"<td>{html.escape(str(converted))}</td>" if converted is not None else "<td>-</td>"

                rows += f"""
                <tr>
                    <td>{html.escape(point.address)}</td>
                    <td>{point.value if point.value is not None else '-'}</td>
                    <td><code>{html.escape(point.raw_hex or '-')}</code></td>
                    {converted_html}
                    <td><span class="badge badge-{status_class}">{status_text}</span></td>
                </tr>
                """

            remaining = len(points) - 100
            if remaining > 0:
                rows += f'<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">...他 {remaining} 件</td></tr>'

            sections += f"""
            <section class="section">
                <h2>📋 データ: {html.escape(ip)}</h2>
                <table>
                    <thead>
                        <tr>
                            <th>アドレス</th>
                            <th>値</th>
                            <th>RAW (HEX)</th>
                            <th>変換値</th>
                            <th>ステータス</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </section>
            """

        return sections

    def _generate_denied_section(self, data: ReportData) -> str:
        """アクセス拒否セクションを生成"""
        if not data.denied_addresses:
            return ""

        sections = ""
        for ip, addresses in data.denied_addresses.items():
            addresses = sorted_addresses(addresses)
            addr_list = ", ".join(addresses[:50])
            remaining = len(addresses) - 50
            if remaining > 0:
                addr_list += f" ...他 {remaining} 件"

            sections += f"""
            <div style="margin-bottom: 1rem;">
                <strong>{html.escape(ip)}</strong>:
                <span style="color: var(--text-secondary);">{html.escape(addr_list)}</span>
            </div>
            """

        return f"""
        <section class="section">
            <h2>⚠️ アクセス拒否アドレス</h2>
            {sections}
        </section>
        """

    def _generate_errors_section(self, data: ReportData) -> str:
        """エラーセクションを生成"""
        if not data.errors:
            return ""

        error_items = ""
        for error in data.errors[:20]:
            error_items += f"<li>{html.escape(error)}</li>"

        remaining = len(data.errors) - 20
        if remaining > 0:
            error_items += f"<li>...他 {remaining} 件のエラー</li>"

        return f"""
        <section class="section">
            <h2>❌ エラー</h2>
            <ul class="error-list">
                {error_items}
            </ul>
        </section>
        """

    def _generate_footer(self) -> str:
        """フッターを生成"""
        return f"""
        <footer>
            <p>Generated by PLC Discovery Tool</p>
            <p>© {datetime.now().year} All rights reserved.</p>
        </footer>
        """


def _svg_bar_chart(bars: List[tuple]) -> str:
    """Horizontal bar chart as inline SVG; bars = [(label, value, color), ...]"""
    if not bars:
        return '<p style="color: var(--text-secondary);">データなし</p>'
    row_height, label_width, bar_width = 28, 180, 260
    peak = max((value for _, value, _ in bars), default=0) or 1
    rows = []
    for i, (label, value, color) in enumerate(bars):
        y = i * row_height
        width = round(bar_width * value / peak)
        rows.append(
            f'<text x="0" y="{y + 18}" font-size="12" fill="currentColor">{html.escape(str(label))}</text>'
            f'<rect x="{label_width}" y="{y + 6}" width="{width}" height="16" rx="3" fill="{color}"/>'
            f'<text x="{label_width + width + 6}" y="{y + 18}" font-size="12" fill="currentColor">{value:,}</text>'
        )
    height = row_height * len(bars)
    total_width = label_width + bar_width + 80
    return (
        f'<svg role="img" viewBox="0 0 {total_width} {height}" width="100%" '
        f'style="max-height: {height}px;" xmlns="http://www.w3.org/2000/svg">{"".join(rows)}</svg>'
    )


def create_report(
    plcs: List[PLCInfo],
    data_points: Dict[str, List[DataPoint]],
    denied_addresses: Optional[Dict[str, List[str]]] = None,
    scan_mode: str = "full",
    started_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
    config: Optional[ReportConfig] = None,
    errors: Optional[List[str]] = None,
) -> tuple[ReportGenerator, ReportData]:
    """
    レポートを作成するコンビニエンス関数

    Args:
        plcs: PLCリスト
        data_points: PLCごとのデータポイント
        denied_addresses: アクセス拒否アドレス
        scan_mode: スキャンモード
        started_at: 開始日時
        completed_at: 完了日時
        config: レポート設定
        errors: 失敗したターゲットや出力エラーの説明（エラーセクションに表示）

    Returns:
        設定済みのReportGenerator
    """
    generator = ReportGenerator(config)

    # サマリー計算
    total_success = sum(1 for points in data_points.values() for p in points if p.status == StatusCode.OK)
    total_failed = sum(1 for points in data_points.values() for p in points if p.status != StatusCode.OK)
    total_denied = sum(len(addrs) for addrs in (denied_addresses or {}).values())

    duration = 0.0
    if started_at and completed_at:
        duration = (completed_at - started_at).total_seconds()

    summary = ScanSummary(
        scan_mode=scan_mode,
        started_at=started_at or datetime.now(),
        completed_at=completed_at,
        total_plcs=len(plcs),
        successful_reads=total_success,
        failed_reads=total_failed,
        denied_addresses=total_denied,
        duration_seconds=duration,
    )

    report_data = ReportData(
        summary=summary,
        plcs=plcs,
        data_points=data_points,
        denied_addresses=denied_addresses or {},
        errors=list(errors or []),
    )

    return generator, report_data


def generate_html_report(
    plcs: List[PLCInfo],
    data_points: Dict[str, List[DataPoint]],
    output_path: str,
    denied_addresses: Optional[Dict[str, List[str]]] = None,
    scan_mode: str = "full",
    started_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
    title: str = "PLC Discovery レポート",
    company_name: str = "",
    theme: str = "default",
    include_charts: bool = True,
    include_raw_data: bool = True,
) -> str:
    """
    HTMLレポートを生成して保存

    Args:
        plcs: PLCリスト
        data_points: データポイント
        output_path: 出力パス
        denied_addresses: アクセス拒否アドレス
        scan_mode: スキャンモード
        started_at: 開始日時
        completed_at: 完了日時
        title: レポートタイトル
        company_name: 会社名
        theme: テーマ
        include_charts: チャートを含める
        include_raw_data: 生データを含める

    Returns:
        保存されたファイルパス
    """
    config = ReportConfig(
        format=ReportFormat.HTML,
        title=title,
        company_name=company_name,
        theme=theme,
        include_charts=include_charts,
        include_raw_data=include_raw_data,
    )
    generator, data = create_report(plcs, data_points, denied_addresses, scan_mode, started_at, completed_at, config)
    return generator.save(data, output_path)


def generate_pdf_report(
    plcs: List[PLCInfo],
    data_points: Dict[str, List[DataPoint]],
    output_path: str,
    denied_addresses: Optional[Dict[str, List[str]]] = None,
    scan_mode: str = "full",
    started_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
    title: str = "PLC Discovery レポート",
    company_name: str = "",
    theme: str = "default",
    include_charts: bool = True,
    include_raw_data: bool = True,
) -> str:
    """
    PDFレポートを生成して保存

    Args:
        plcs: PLCリスト
        data_points: データポイント
        output_path: 出力パス
        denied_addresses: アクセス拒否アドレス
        scan_mode: スキャンモード
        started_at: 開始日時
        completed_at: 完了日時
        title: レポートタイトル
        company_name: 会社名
        theme: テーマ
        include_charts: チャートを含める
        include_raw_data: 生データを含める

    Returns:
        保存されたファイルパス
    """
    config = ReportConfig(
        format=ReportFormat.PDF,
        title=title,
        company_name=company_name,
        theme=theme,
        include_charts=include_charts,
        include_raw_data=include_raw_data,
    )
    generator, data = create_report(plcs, data_points, denied_addresses, scan_mode, started_at, completed_at, config)
    return generator.save(data, output_path)
