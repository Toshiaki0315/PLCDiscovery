"""
レポート生成モジュールのテスト
"""

import json
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from plc_discovery.config import PLCInfo, DataPoint, Protocol, StatusCode
from plc_discovery.report import (
    ReportConfig,
    ReportFormat,
    ReportData,
    ReportGenerator,
    ScanSummary,
    create_report,
    generate_html_report,
)


class TestReportConfig:
    """ReportConfigのテスト"""
    
    def test_default_config(self):
        """デフォルト設定のテスト"""
        config = ReportConfig()
        assert config.format == ReportFormat.HTML
        assert config.title == "PLC Discovery レポート"
        assert config.include_raw_data is True
        assert config.include_charts is True
        assert config.theme == "default"
    
    def test_custom_config(self):
        """カスタム設定のテスト"""
        config = ReportConfig(
            format=ReportFormat.PDF,
            title="カスタムレポート",
            company_name="Test Company",
            include_charts=False,
            theme="dark"
        )
        assert config.format == ReportFormat.PDF
        assert config.title == "カスタムレポート"
        assert config.company_name == "Test Company"
        assert config.include_charts is False
        assert config.theme == "dark"


class TestScanSummary:
    """ScanSummaryのテスト"""
    
    def test_success_rate_calculation(self):
        """成功率計算のテスト"""
        summary = ScanSummary(
            scan_mode="full",
            started_at=datetime.now(),
            successful_reads=80,
            failed_reads=20
        )
        assert summary.success_rate == 80.0
    
    def test_success_rate_zero_reads(self):
        """読み取りゼロ時の成功率"""
        summary = ScanSummary(
            scan_mode="full",
            started_at=datetime.now(),
            successful_reads=0,
            failed_reads=0
        )
        assert summary.success_rate == 0.0
    
    def test_success_rate_all_success(self):
        """全成功時の成功率"""
        summary = ScanSummary(
            scan_mode="full",
            started_at=datetime.now(),
            successful_reads=100,
            failed_reads=0
        )
        assert summary.success_rate == 100.0


class TestReportGenerator:
    """ReportGeneratorのテスト"""
    
    @pytest.fixture
    def sample_plcs(self):
        """サンプルPLCデータ"""
        return [
            PLCInfo(
                ip_address="192.168.1.10",
                manufacturer="Mitsubishi",
                model="iQ-R",
                protocol=Protocol.SLMP,
                port=5000
            ),
            PLCInfo(
                ip_address="192.168.1.20",
                manufacturer="Siemens",
                model="S7-1500",
                protocol=Protocol.S7,
                port=102
            )
        ]
    
    @pytest.fixture
    def sample_data_points(self):
        """サンプルデータポイント"""
        return {
            "192.168.1.10": [
                DataPoint(address="D0", value=100, raw_hex="0064", status=StatusCode.OK),
                DataPoint(address="D1", value=200, raw_hex="00C8", status=StatusCode.OK),
                DataPoint(address="D2", value=None, raw_hex=None, status=StatusCode.NG_TIMEOUT),
            ],
            "192.168.1.20": [
                DataPoint(address="DB1.DBW0", value=500, raw_hex="01F4", status=StatusCode.OK),
            ]
        }
    
    @pytest.fixture
    def sample_report_data(self, sample_plcs, sample_data_points):
        """サンプルレポートデータ"""
        started = datetime.now() - timedelta(minutes=5)
        completed = datetime.now()
        
        return ReportData(
            summary=ScanSummary(
                scan_mode="full",
                started_at=started,
                completed_at=completed,
                total_plcs=2,
                successful_reads=3,
                failed_reads=1,
                denied_addresses=2,
                duration_seconds=300.0
            ),
            plcs=sample_plcs,
            data_points=sample_data_points,
            denied_addresses={
                "192.168.1.10": ["D100", "D101"]
            }
        )
    
    def test_generate_html(self, sample_report_data):
        """HTML生成のテスト"""
        generator = ReportGenerator()
        html = generator.generate(sample_report_data)
        
        assert "<!DOCTYPE html>" in html
        assert "PLC Discovery レポート" in html
        assert "192.168.1.10" in html
        assert "Mitsubishi" in html
        assert "D0" in html
        assert "100" in html
    
    def test_generate_html_with_dark_theme(self, sample_report_data):
        """ダークテーマでのHTML生成"""
        config = ReportConfig(theme="dark")
        generator = ReportGenerator(config)
        html = generator.generate(sample_report_data)
        
        assert "<!DOCTYPE html>" in html
        assert "--bg-color: #0f172a" in html
    
    def test_generate_html_without_charts(self, sample_report_data):
        """チャートなしでのHTML生成"""
        config = ReportConfig(include_charts=False)
        generator = ReportGenerator(config)
        html = generator.generate(sample_report_data)
        
        assert "chart.js" not in html.lower()
        assert "statusChart" not in html
    
    def test_generate_html_without_raw_data(self, sample_report_data):
        """生データなしでのHTML生成"""
        config = ReportConfig(include_raw_data=False)
        generator = ReportGenerator(config)
        html = generator.generate(sample_report_data)
        
        # データセクションが含まれないことを確認
        assert "📋 データ:" not in html
    
    def test_generate_json(self, sample_report_data):
        """JSON生成のテスト"""
        config = ReportConfig(format=ReportFormat.JSON)
        generator = ReportGenerator(config)
        json_str = generator.generate(sample_report_data)
        
        data = json.loads(json_str)
        assert data["title"] == "PLC Discovery レポート"
        assert data["summary"]["total_plcs"] == 2
        assert len(data["plcs"]) == 2
        assert "192.168.1.10" in data["data_points"]
    
    def test_save_html(self, sample_report_data):
        """HTMLファイル保存のテスト"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "test_report.html")
            
            generator = ReportGenerator()
            saved_path = generator.save(sample_report_data, output_path)
            
            assert os.path.exists(saved_path)
            with open(saved_path, 'r', encoding='utf-8') as f:
                content = f.read()
            assert "<!DOCTYPE html>" in content
    
    def test_save_json(self, sample_report_data):
        """JSONファイル保存のテスト"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "test_report.json")
            
            config = ReportConfig(format=ReportFormat.JSON)
            generator = ReportGenerator(config)
            saved_path = generator.save(sample_report_data, output_path)
            
            assert os.path.exists(saved_path)
            with open(saved_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            assert "summary" in data
    
    def test_save_auto_filename(self, sample_report_data):
        """自動ファイル名生成のテスト"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_path=tmpdir)
            generator = ReportGenerator(config)
            saved_path = generator.save(sample_report_data)
            
            assert os.path.exists(saved_path)
            assert saved_path.endswith(".html")
            assert "plc_report_" in saved_path
    
    def test_generate_pdf_without_library(self, sample_report_data):
        """PDFライブラリなしでのPDF生成"""
        config = ReportConfig(format=ReportFormat.PDF)
        generator = ReportGenerator(config)
        
        with patch.dict('sys.modules', {'weasyprint': None, 'pdfkit': None}):
            with pytest.raises(ImportError) as exc_info:
                generator.generate(sample_report_data)
            assert "weasyprint" in str(exc_info.value) or "pdfkit" in str(exc_info.value)


class TestConvenienceFunctions:
    """コンビニエンス関数のテスト"""
    
    def test_create_report(self):
        """create_report関数のテスト"""
        plcs = [
            PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP)
        ]
        data_points = {
            "192.168.1.10": [
                DataPoint(address="D0", value=100, raw_hex="0064", status=StatusCode.OK)
            ]
        }
        
        generator, data = create_report(
            plcs=plcs,
            data_points=data_points,
            scan_mode="range",
            started_at=datetime.now() - timedelta(minutes=1),
            completed_at=datetime.now()
        )
        
        assert isinstance(generator, ReportGenerator)
        assert isinstance(data, ReportData)
        assert data.summary.scan_mode == "range"
        assert data.summary.total_plcs == 1
        assert data.summary.successful_reads == 1
    
    def test_generate_html_report(self):
        """generate_html_report関数のテスト"""
        plcs = [
            PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP)
        ]
        data_points = {
            "192.168.1.10": [
                DataPoint(address="D0", value=100, raw_hex="0064", status=StatusCode.OK)
            ]
        }
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            saved_path = generate_html_report(
                plcs=plcs,
                data_points=data_points,
                output_path=output_path,
                title="テストレポート",
                scan_mode="full"
            )
            
            assert os.path.exists(saved_path)


class TestReportWithEdgeCases:
    """エッジケースのテスト"""
    
    def test_empty_report(self):
        """空のレポート生成"""
        data = ReportData(
            summary=ScanSummary(
                scan_mode="discovery",
                started_at=datetime.now()
            ),
            plcs=[],
            data_points={}
        )
        
        generator = ReportGenerator()
        html = generator.generate(data)
        
        assert "<!DOCTYPE html>" in html
        assert "discovery" in html
    
    def test_html_escape(self):
        """HTMLエスケープのテスト"""
        plcs = [
            PLCInfo(
                ip_address="192.168.1.10",
                manufacturer="<script>alert('xss')</script>",
                protocol=Protocol.SLMP
            )
        ]
        data = ReportData(
            summary=ScanSummary(scan_mode="full", started_at=datetime.now()),
            plcs=plcs,
            data_points={}
        )
        
        generator = ReportGenerator()
        html = generator.generate(data)
        
        # XSS攻撃文字列がエスケープされていることを確認
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html
    
    def test_large_data_truncation(self):
        """大量データの切り捨てテスト"""
        # 200件のデータポイントを生成
        data_points = {
            "192.168.1.10": [
                DataPoint(address=f"D{i}", value=i, raw_hex=f"{i:04X}", status=StatusCode.OK)
                for i in range(200)
            ]
        }
        
        data = ReportData(
            summary=ScanSummary(scan_mode="full", started_at=datetime.now()),
            plcs=[PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP)],
            data_points=data_points
        )
        
        generator = ReportGenerator()
        html = generator.generate(data)
        
        # 100件以上は切り捨てられるメッセージが表示される
        assert "他 100 件" in html
    
    def test_special_characters_in_values(self):
        """特殊文字を含む値のテスト"""
        data_points = {
            "192.168.1.10": [
                DataPoint(address="D0", value=0, raw_hex="アイウエオ", status=StatusCode.OK)
            ]
        }
        
        data = ReportData(
            summary=ScanSummary(scan_mode="full", started_at=datetime.now()),
            plcs=[PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP)],
            data_points=data_points
        )
        
        generator = ReportGenerator()
        html = generator.generate(data)
        
        # 日本語文字が正しく含まれていることを確認
        assert "アイウエオ" in html


class TestReportFormats:
    """各フォーマットの詳細テスト"""
    
    @pytest.fixture
    def minimal_data(self):
        """最小限のテストデータ"""
        return ReportData(
            summary=ScanSummary(
                scan_mode="full",
                started_at=datetime.now(),
                completed_at=datetime.now(),
                total_plcs=1,
                successful_reads=10,
                failed_reads=2
            ),
            plcs=[PLCInfo(ip_address="192.168.1.10", protocol=Protocol.SLMP)],
            data_points={}
        )
    
    def test_html_structure(self, minimal_data):
        """HTML構造の検証"""
        generator = ReportGenerator()
        html = generator.generate(minimal_data)
        
        # 必須要素の確認
        assert "<html" in html
        assert "<head>" in html
        assert "<body>" in html
        assert "<meta charset=" in html
        assert "<style>" in html
        assert "</html>" in html
    
    def test_json_structure(self, minimal_data):
        """JSON構造の検証"""
        config = ReportConfig(format=ReportFormat.JSON)
        generator = ReportGenerator(config)
        json_str = generator.generate(minimal_data)
        
        data = json.loads(json_str)
        
        # 必須フィールドの確認
        assert "title" in data
        assert "generated_at" in data
        assert "summary" in data
        assert "plcs" in data
        assert "data_points" in data
        
        # サマリーの必須フィールド
        summary = data["summary"]
        assert "scan_mode" in summary
        assert "total_plcs" in summary
        assert "success_rate" in summary

